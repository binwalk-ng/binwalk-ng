//! Minifs filesystem support.
//!
//! Format references: https://arxiv.org/html/2407.05064v1 and
//! https://github.com/RedaOps/minifs-extractor.

use crate::common::get_cstring;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use liblzma::stream::Stream;
use std::io::Read;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, U32, Unaligned};

pub const DESCRIPTION: &str = "MINIFS image";
const MAGIC: &[u8; 6] = b"MINIFS";
const MEM_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
/// Upper bound on the total decompressed data produced by one extraction.
const MAX_EXTRACTED_SIZE: usize = 1024 * 1024 * 1024;

pub fn minifs_magic() -> Vec<Vec<u8>> {
    vec![MAGIC.to_vec()]
}

#[derive(Debug)]
pub struct MinifsHeader {
    pub version: u32,
    pub num_files: u32,
    pub name_table_size: u32,
}

#[derive(Debug)]
pub struct MinifsFileEntry<'a> {
    /// Name table bytes starting at the path; NUL-terminated.
    pub path: &'a [u8],
    /// Name table bytes starting at the file name; NUL-terminated.
    pub filename: &'a [u8],
    pub chunk_number: usize,
    pub offset_in_chunk: usize,
    pub file_size: usize,
}

#[derive(Debug)]
pub struct MinifsChunkEntry {
    pub offset: usize,
    pub size: usize,
    pub decompressed_size: usize,
}

#[derive(Debug)]
pub struct MinifsImage<'a> {
    pub header: MinifsHeader,
    pub files: Vec<MinifsFileEntry<'a>>,
    pub chunks: Vec<MinifsChunkEntry>,
    pub raw_chunks_offset: usize,
    pub size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct MinifsHeaderBytes {
    magic: [u8; 6],
    _unknown1: [u8; 10],
    version: U32<BE>,
    num_files: U32<BE>,
    _unknown2: [u8; 4],
    name_table_size: U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FileEntryBytes {
    path_index: U32<BE>,
    file_index: U32<BE>,
    chunk_number: U32<BE>,
    offset_in_chunk: U32<BE>,
    file_size: U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ChunkEntryBytes {
    offset: U32<BE>,
    size: U32<BE>,
    decompressed_size: U32<BE>,
}

/// Parse and bound-check a Minifs image, including its name, file and chunk tables.
pub fn parse_minifs_file(data: &[u8]) -> Result<MinifsImage<'_>, StructureError> {
    let (mh, rest) = MinifsHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;
    let header = MinifsHeader {
        version: mh.version.get(),
        num_files: mh.num_files.get(),
        name_table_size: mh.name_table_size.get(),
    };
    if header.num_files == 0 {
        return Err(StructureError);
    }

    let (names, rest) = rest
        .split_at_checked(header.name_table_size as usize)
        .ok_or(StructureError)?;
    let (file_table, rest) =
        <[FileEntryBytes]>::ref_from_prefix_with_elems(rest, header.num_files as usize)
            .map_err(|_| StructureError)?;

    let mut files = Vec::with_capacity(file_table.len());
    let mut max_chunk = 0usize;
    for fe in file_table {
        let path = names
            .get(fe.path_index.get() as usize..)
            .ok_or(StructureError)?;
        let filename = names
            .get(fe.file_index.get() as usize..)
            .ok_or(StructureError)?;
        // An empty file name (offset at the table end or pointing at a NUL) is invalid.
        if filename.first().is_none_or(|&byte| byte == 0) {
            return Err(StructureError);
        }
        let chunk_number = fe.chunk_number.get() as usize;
        max_chunk = max_chunk.max(chunk_number);
        files.push(MinifsFileEntry {
            path,
            filename,
            chunk_number,
            offset_in_chunk: fe.offset_in_chunk.get() as usize,
            file_size: fe.file_size.get() as usize,
        });
    }

    let chunk_count = max_chunk.checked_add(1).ok_or(StructureError)?;
    let (toc_table, rest) = <[ChunkEntryBytes]>::ref_from_prefix_with_elems(rest, chunk_count)
        .map_err(|_| StructureError)?;
    let toc_end = data.len() - rest.len();

    let mut chunks = Vec::with_capacity(toc_table.len());
    let mut last_chunk_end = 0usize;
    for ce in toc_table {
        let offset = ce.offset.get() as usize;
        let size = ce.size.get() as usize;
        let end = offset.checked_add(size).ok_or(StructureError)?;
        if size == 0 || end > rest.len() {
            return Err(StructureError);
        }
        last_chunk_end = last_chunk_end.max(end);
        chunks.push(MinifsChunkEntry {
            offset,
            size,
            decompressed_size: ce.decompressed_size.get() as usize,
        });
    }
    for file in &files {
        let chunk = &chunks[file.chunk_number];
        if file
            .offset_in_chunk
            .checked_add(file.file_size)
            .is_none_or(|end| end > chunk.decompressed_size)
        {
            return Err(StructureError);
        }
    }

    Ok(MinifsImage {
        header,
        files,
        chunks,
        raw_chunks_offset: toc_end,
        size: toc_end + last_chunk_end,
    })
}

pub fn minifs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let data = file_data.get(offset..).ok_or(SignatureError)?;
    let image = parse_minifs_file(data).map_err(|_| SignatureError)?;
    Ok(SignatureResult {
        offset,
        size: image.size,
        description: format!(
            "{}, version: {}, files: {}, name table size: {} bytes",
            DESCRIPTION, image.header.version, image.header.num_files, image.header.name_table_size
        ),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    })
}

pub fn minifs_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_minifs),
        ..Default::default()
    }
}

fn decode_chunk(data: &[u8], image: &MinifsImage, chunk: &MinifsChunkEntry) -> Option<Vec<u8>> {
    let start = image.raw_chunks_offset + chunk.offset;
    let compressed = data.get(start..start + chunk.size)?;
    let stream = Stream::new_auto_decoder(MEM_LIMIT, 0).ok()?;
    let decoder = liblzma::bufread::XzDecoder::new_stream(compressed, stream);
    let limit = u64::try_from(chunk.decompressed_size).ok()? + 1;
    let mut decoded = Vec::with_capacity(chunk.decompressed_size);
    if decoder.take(limit).read_to_end(&mut decoded).is_err()
        || decoded.len() != chunk.decompressed_size
    {
        return None;
    }
    Some(decoded)
}

/// Decompress chunks and write the files through the chrooted file API.
pub fn extract_minifs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();
    let Some(data) = file_data.get(offset..) else {
        return result;
    };
    let Ok(image) = parse_minifs_file(data) else {
        return result;
    };

    // Group files by chunk (stable, so per-chunk file order is preserved).
    let mut order: Vec<&MinifsFileEntry> = image.files.iter().collect();
    order.sort_by_key(|file| file.chunk_number);

    let mut total = 0usize;
    let mut prev_chunk = None;
    for file in &order {
        if prev_chunk != Some(file.chunk_number) {
            prev_chunk = Some(file.chunk_number);
            let chunk = &image.chunks[file.chunk_number];
            match total.checked_add(chunk.decompressed_size) {
                Some(value) if value <= MAX_EXTRACTED_SIZE => total = value,
                _ => return result,
            }
        }
    }

    let chroot = output_directory.map(Chroot::new);
    for group in order.chunk_by(|a, b| a.chunk_number == b.chunk_number) {
        let Some(decoded) = decode_chunk(data, &image, &image.chunks[group[0].chunk_number]) else {
            return result;
        };
        for file in group {
            let Some(bytes) =
                decoded.get(file.offset_in_chunk..file.offset_in_chunk + file.file_size)
            else {
                return result;
            };
            if let Some(chroot) = &chroot {
                let p = chroot.safe_path_join(get_cstring(file.path), "");
                if !chroot.create_directory(&p) {
                    return result;
                }
                let path = chroot.safe_path_join(&p, get_cstring(file.filename));
                if !chroot.create_file(path, bytes) {
                    return result;
                }
            }
        }
    }

    result.success = true;
    result.size = Some(image.size);
    result
}

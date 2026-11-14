//! Minifs filesystem support.
//!
//! Format references: https://arxiv.org/html/2407.05064v1 and
//! https://github.com/RedaOps/minifs-extractor.

use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use crate::common::get_cstring;
use zerocopy::{FromBytes, Immutable, KnownLayout, BE, Unaligned};
use liblzma::stream::Stream;
use std::io::Read;
use std::path::Path;

pub const DESCRIPTION: &str = "MINIFS image";
const HEADER_SIZE: usize = 32;
const FILE_ENTRY_SIZE: usize = 20;
const CHUNK_ENTRY_SIZE: usize = 12;
const MEM_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

pub fn minifs_magic() -> Vec<Vec<u8>> {
    vec![b"MINIFS\0\0".to_vec()]
}

#[derive(Debug)]
pub struct MinifsHeader {
    pub unknown1: u64,
    pub version: u32,
    pub num_files: u32,
    pub unknown2: u32,
    pub name_table_size: u32,
}

#[derive(Debug)]
pub struct MinifsFileEntry {
    pub path: String,
    pub filename: String,
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
pub struct MinifsImage {
    pub header: MinifsHeader,
    pub files: Vec<MinifsFileEntry>,
    pub chunks: Vec<MinifsChunkEntry>,
    pub raw_chunks_offset: usize,
    pub size: usize,
}

fn table_string(table: &[u8], offset: usize) -> Result<String, StructureError> {
    let bytes = table.get(offset..).ok_or(StructureError)?;
    Ok::<std::string::String, StructureError>(get_cstring(bytes))
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct MinifsHeaderBytes {
    magic: zerocopy::U64<BE>, //MINIFS00
    unknown1: zerocopy::U64<BE>,
    version: zerocopy::U32<BE>,
    num_files: zerocopy::U32<BE>,
    unknown2: zerocopy::U32<BE>,
    name_table_size: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FileEntryBytes {
    path_index: zerocopy::U32<BE>,
    file_index: zerocopy::U32<BE>,
    chunk_number: zerocopy::U32<BE>,
    offset_in_chunk: zerocopy::U32<BE>,
    file_size: zerocopy::U32<BE>,  
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct ChunkEntryBytes {
    offset: zerocopy::U32<BE>,
    size: zerocopy::U32<BE>,
    decompressed_size: zerocopy::U32<BE>,
}

/// Parse and bound-check a Minifs image, including its name, file and chunk tables.
pub fn parse_minifs_file(data: &[u8]) -> Result<MinifsImage, StructureError> {
    let (mh, _) = MinifsHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;

    let header = MinifsHeader {
        unknown1: mh.unknown1.get(),
        version: mh.version.get(),
        num_files: mh.num_files.get(),
        unknown2: mh.unknown2.get(),
        name_table_size: mh.name_table_size.get(),
    };
    if header.num_files == 0 {
        return Err(StructureError);
    }

    let names_end = HEADER_SIZE
        .checked_add(header.name_table_size as usize)
        .ok_or(StructureError)?;
    let names = data.get(HEADER_SIZE..names_end).ok_or(StructureError)?;
    let files_end = names_end
        .checked_add(
            (header.num_files as usize)
                .checked_mul(FILE_ENTRY_SIZE)
                .ok_or(StructureError)?,
        )
        .ok_or(StructureError)?;
    let file_table = data.get(names_end..files_end).ok_or(StructureError)?;

    let mut files = Vec::new();
    let mut max_chunk = 0usize;
    for entry in file_table.chunks_exact(FILE_ENTRY_SIZE) {
        let (fe, _) = FileEntryBytes::ref_from_prefix(entry).map_err(|_| StructureError)?;

        let path = table_string(names, fe.path_index.get() as usize)?;
        let filename = table_string(names, fe.file_index.get() as usize)?;
        if filename.is_empty() {
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
    let toc_end = files_end
        .checked_add(
            chunk_count
                .checked_mul(CHUNK_ENTRY_SIZE)
                .ok_or(StructureError)?,
        )
        .ok_or(StructureError)?;
    let chunk_table = data.get(files_end..toc_end).ok_or(StructureError)?;
    let mut chunks = Vec::new();
    let mut image_end = toc_end;
    for entry in chunk_table.chunks_exact(CHUNK_ENTRY_SIZE) {
        let (ce, _) = ChunkEntryBytes::ref_from_prefix(entry).map_err(|_| StructureError)?;

        let offset = ce.offset.get() as usize;
        let size = ce.size.get() as usize;
        let decompressed_size = ce.decompressed_size.get() as usize;
        let end = toc_end
            .checked_add(offset)
            .and_then(|value| value.checked_add(size))
            .ok_or(StructureError)?;
        if size == 0 || end > data.len() {
            return Err(StructureError);
        }
        image_end = image_end.max(end);
        chunks.push(MinifsChunkEntry {
            offset,
            size,
            decompressed_size,
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
        size: image_end,
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

    let chroot = output_directory.map(Chroot::new);
    let mut decompressed_chunks = Vec::with_capacity(image.chunks.len());
    for chunk in &image.chunks {
        let Some(compressed) = data.get(
            image.raw_chunks_offset + chunk.offset
                ..image.raw_chunks_offset + chunk.offset + chunk.size,
        ) else {
            return result;
        };
        let Ok(stream) = Stream::new_auto_decoder(MEM_LIMIT, 0) else {
            return result;
        };
        let decoder = liblzma::bufread::XzDecoder::new_stream(compressed, stream);
        let Some(limit) = u64::try_from(chunk.decompressed_size)
            .ok()
            .and_then(|size| size.checked_add(1))
        else {
            return result;
        };
        let mut decoded = Vec::new();
        if decoder.take(limit).read_to_end(&mut decoded).is_err()
            || decoded.len() != chunk.decompressed_size
        {
            return result;
        }
        decompressed_chunks.push(decoded);
    }

    for file in &image.files {
         let Some(bytes) = decompressed_chunks[file.chunk_number]
            .get(file.offset_in_chunk..file.offset_in_chunk + file.file_size)
        else {
            return result;
        };
        if let Some(chroot) = &chroot {
            let p = chroot.safe_path_join(&file.path, "");
            if !chroot.create_directory(&p) {
                return result;
            }
            let path = chroot.safe_path_join(&p, &file.filename);
            if !chroot.create_file(path, bytes) {
                return result;
            }
        }
    }

    result.success = true;
    result.size = Some(image.size);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::stream::LzmaOptions;
    use std::io::Write;

    fn make_image() -> Vec<u8> {
        let payload = b"hello Minifs";
        let options = LzmaOptions::new_preset(6).unwrap();
        let stream = Stream::new_lzma_encoder(&options).unwrap();
        let mut encoder = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let names = b"web\0index.html\0";
        let mut data = Vec::new();
        data.extend_from_slice(b"MINIFS\0\0");
        data.extend_from_slice(&0u64.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&(names.len() as u32).to_be_bytes());
        data.extend_from_slice(names);
        for value in [0, 4, 0, 0, payload.len() as u32] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        for value in [0, compressed.len() as u32, payload.len() as u32] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        data.extend_from_slice(&compressed);
        data
    }

    #[test]
    fn rejects_truncated_and_invalid_images() {
        let image = make_image();
        for length in 0..image.len() {
            assert!(
                parse_minifs_file(&image[..length]).is_err(),
                "length {length}"
            );
        }
        let mut bad_reference = image.clone();
        let chunk_number_offset = HEADER_SIZE + b"web\0index.html\0".len() + 8;
        bad_reference[chunk_number_offset..chunk_number_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_minifs_file(&bad_reference).is_err());
        let mut bad_name = image;
        let name_offset = HEADER_SIZE + b"web\0index.html\0".len();
        bad_name[name_offset..name_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_minifs_file(&bad_name).is_err());
    }
}

use crate::common::crc32;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Outer dual-kernel container magic
pub const DUAL_KERNEL_MAGIC: u32 = 0xFEED9112;

/// Primary TI record magic
pub const TI_AR7_MAGIC: u32 = 0xFEED1281;

/// Secondary TI record magic
pub const TI_AR7_2ND_MAGIC: u32 = 0xFEEDB007;

/// EVA LZMA payload type marker
pub const EVA_LZMA_TYPE_MAGIC: u32 = 0x075A0201;

/// Trailing file signature magic
pub const FILE_SIGNATURE_MAGIC: u32 = 0xC453DE23;

/// Size of a TI record header (magic + payload_length + load_addr)
pub const TI_HEADER_SIZE: usize = 12;

/// Size of a TI record trailer (checksum + zero + entry_addr)
pub const TI_TRAILER_SIZE: usize = 12;

/// Size of the EVA LZMA header (type + compressed_len + uncompressed_len + data_checksum)
pub const EVA_LZMA_HEADER_SIZE: usize = 16;

/// Size of the EVA LZMA stream header (properties + dict_size + 3 padding bytes)
pub const EVA_LZMA_STREAM_HEADER: usize = 8;

/// Size of a standard LZMA-alone header that the extractor reconstructs:
/// properties(1) + dict_size(4) + uncompressed_size(8) = 13 bytes.
pub const LZMA_ALONE_HEADER_SIZE: usize = 13;

/// Size of the trailing file signature (magic + crc)
pub const FILE_SIGNATURE_SIZE: usize = 8;

/// Max bytes to scan for a trailing file signature after the last TI trailer
const FILE_SIGNATURE_SCAN_WINDOW: usize = 4096;

/// Parsed EVA LZMA payload (16-byte header + 8-byte stream header, followed by compressed data)
#[derive(Debug, Default, Clone)]
pub struct EvaLzmaPayload {
    pub compressed_len: usize,
    pub uncompressed_len: usize,
    pub data_checksum_valid: bool,
    pub properties: u8,
    pub dict_size: u32,
}

/// Parsed TI record (header + EVA LZMA payload + trailer)
#[derive(Debug, Default, Clone)]
pub struct EvaTiRecord {
    pub load_addr: u32,
    pub checksum_valid: bool,
    pub entry_addr: u32,
    pub lzma: EvaLzmaPayload,
    pub header_offset: usize,
    pub total_size: usize,
}

/// Located trailing EVA file signature
#[derive(Debug, Default, Clone, Copy)]
pub struct EvaFileSignature {
    pub crc: u32,
    pub valid: bool,
    /// Absolute end offset of the signature within the EVA image
    pub end_offset: usize,
}

/// Shape of a parsed EVA kernel image
#[derive(Debug, Clone)]
pub enum EvaImageKind {
    /// Standalone primary kernel image (TI_AR7 magic at offset 0)
    SingleKernel(EvaTiRecord),
    /// Isolated secondary-kernel fragment (TI_AR7_2ND magic at offset 0)
    SecondaryFragment(EvaTiRecord),
    /// Dual-kernel container: primary + secondary + outer dual trailer
    DualKernel {
        primary: EvaTiRecord,
        secondary: EvaTiRecord,
        trailer_checksum_valid: bool,
    },
}

/// Parsed EVA kernel image
#[derive(Debug, Clone)]
pub struct EvaImage {
    pub kind: EvaImageKind,
    pub file_signature: Option<EvaFileSignature>,
    pub total_size: usize,
}

impl EvaImage {
    /// Returns true if every checksum layer present in this image validated
    pub fn all_checksums_valid(&self) -> bool {
        match &self.kind {
            EvaImageKind::SingleKernel(rec) | EvaImageKind::SecondaryFragment(rec) => {
                if !rec.checksum_valid || !rec.lzma.data_checksum_valid {
                    return false;
                }
            }
            EvaImageKind::DualKernel {
                primary,
                secondary,
                trailer_checksum_valid,
            } => {
                if !primary.checksum_valid || !primary.lzma.data_checksum_valid {
                    return false;
                }
                if !secondary.checksum_valid || !secondary.lzma.data_checksum_valid {
                    return false;
                }
                if !trailer_checksum_valid {
                    return false;
                }
            }
        }
        if self.file_signature.is_some_and(|sig| !sig.valid) {
            return false;
        }
        true
    }
}

// 12-byte TI-style record header, also used for the dual-kernel container header
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TiHeaderBytes {
    magic: zerocopy::U32<LE>,
    payload_length: zerocopy::U32<LE>,
    load_addr: zerocopy::U32<LE>,
}

// 12-byte TI-style record trailer, also used for the dual-kernel trailer
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct TiTrailerBytes {
    checksum: zerocopy::U32<LE>,
    zero: zerocopy::U32<LE>,
    entry_addr: zerocopy::U32<LE>,
}

// 16-byte EVA LZMA payload header
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EvaLzmaHeaderBytes {
    type_: zerocopy::U32<LE>,
    compressed_len: zerocopy::U32<LE>,
    uncompressed_len: zerocopy::U32<LE>,
    data_checksum: zerocopy::U32<LE>,
}

// 8-byte LZMA alone stream header: properties(1) + dict_size(4) + unknown(3)
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EvaLzmaStreamHeaderBytes {
    properties: u8,
    dict_size: zerocopy::U32<LE>,
    padding: [u8; 3],
}

// 8-byte trailing file signature: magic(4) + crc(4)
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FileSignatureBytes {
    magic: zerocopy::U32<LE>,
    crc: zerocopy::U32<LE>,
}

/// CRC-32 variant used by the Fritz!Box EVA kernel image file signature.
///
/// Differs from the standard [`crc32`] in three ways: bits are processed
/// MSB-first (polynomial 0x04C11DB7, not the reflected form), the CRC starts
/// at 0 instead of 0xFFFFFFFF, and the payload length is folded into the CRC
/// byte-by-byte before the final one's-complement.
fn eva_file_signature_crc32(data: &[u8]) -> u32 {
    const POLY: u32 = 0x04C11DB7;
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 1;
        while i < 256 {
            let mut crc = table[i / 2];
            let c = (crc >> 31) ^ ((i as u32) & 1);
            crc <<= 1;
            if c & 1 != 0 {
                crc ^= POLY;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc: u32 = 0;
    for &byte in data {
        crc = (crc << 8) ^ TABLE[((crc >> 24) as u8 ^ byte) as usize];
    }

    // Fold the payload length into the CRC
    let mut length = data.len();
    while length > 0 {
        crc = (crc << 8) ^ TABLE[((crc >> 24) as u8 ^ (length & 0xFF) as u8) as usize];
        length >>= 8;
    }

    !crc
}

/// Parse a Fritz!Box EVA kernel image
pub fn parse_eva_image(file_data: &[u8], image_offset: usize) -> Result<EvaImage, StructureError> {
    let data = file_data.get(image_offset..).ok_or(StructureError)?;
    let (header, _) = TiHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;
    match header.magic.get() {
        DUAL_KERNEL_MAGIC => parse_dual_kernel_image(file_data, image_offset),
        TI_AR7_MAGIC => parse_single_kernel_image(file_data, image_offset, TI_AR7_MAGIC),
        TI_AR7_2ND_MAGIC => parse_single_kernel_image(file_data, image_offset, TI_AR7_2ND_MAGIC),
        _ => Err(StructureError),
    }
}

/// Parse a dual-kernel EVA image
fn parse_dual_kernel_image(
    file_data: &[u8],
    image_offset: usize,
) -> Result<EvaImage, StructureError> {
    let data = file_data.get(image_offset..).ok_or(StructureError)?;
    let (dual_header, _) = TiHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;
    let dual_payload_length_u32 = dual_header.payload_length.get();
    let dual_payload_length = dual_payload_length_u32 as usize;
    let dual_load_addr = dual_header.load_addr.get();

    let primary = parse_ti_record(data, TI_HEADER_SIZE, TI_AR7_MAGIC)?;
    let after_primary = primary.header_offset + primary.total_size;

    // Secondary TI record starts at the next 4-byte aligned offset
    let aligned_secondary_offset = align_up(after_primary, 4).ok_or(StructureError)?;
    let secondary = parse_ti_record(data, aligned_secondary_offset, TI_AR7_2ND_MAGIC)?;
    let after_secondary = secondary.header_offset + secondary.total_size;

    let dual_trailer_offset = TI_HEADER_SIZE
        .checked_add(dual_payload_length)
        .ok_or(StructureError)?;
    if dual_trailer_offset < after_secondary {
        return Err(StructureError);
    }
    let dual_trailer_end = dual_trailer_offset
        .checked_add(TI_TRAILER_SIZE)
        .ok_or(StructureError)?;
    if data.len() < dual_trailer_end {
        return Err(StructureError);
    }

    let dual_trailer_data = data
        .get(dual_trailer_offset..dual_trailer_end)
        .ok_or(StructureError)?;
    let (dual_trailer, _) =
        TiTrailerBytes::ref_from_prefix(dual_trailer_data).map_err(|_| StructureError)?;
    if dual_trailer.zero.get() != 0 {
        return Err(StructureError);
    }

    // Dual checksum covers every byte between the dual header and the dual trailer
    let dual_payload = data
        .get(TI_HEADER_SIZE..dual_trailer_offset)
        .ok_or(StructureError)?;
    let expected_dual_checksum =
        calculate_ti_checksum(dual_payload_length_u32, dual_load_addr, dual_payload);
    let trailer_checksum_valid = dual_trailer.checksum.get() == expected_dual_checksum;

    let file_signature = detect_file_signature(file_data, image_offset, dual_trailer_end);
    let total_size = file_signature
        .map(|sig| sig.end_offset)
        .unwrap_or(dual_trailer_end);

    Ok(EvaImage {
        kind: EvaImageKind::DualKernel {
            primary,
            secondary,
            trailer_checksum_valid,
        },
        file_signature,
        total_size,
    })
}

/// Parse a single-kernel EVA image, or an isolated secondary TI record fragment
fn parse_single_kernel_image(
    file_data: &[u8],
    image_offset: usize,
    expected_magic: u32,
) -> Result<EvaImage, StructureError> {
    let data = file_data.get(image_offset..).ok_or(StructureError)?;
    let record = parse_ti_record(data, 0, expected_magic)?;
    let content_end = record.total_size;

    // Secondary-only fragments never carry a trailing file signature
    let (kind, file_signature) = match expected_magic {
        TI_AR7_MAGIC => (
            EvaImageKind::SingleKernel(record),
            detect_file_signature(file_data, image_offset, content_end),
        ),
        TI_AR7_2ND_MAGIC => (EvaImageKind::SecondaryFragment(record), None),
        _ => return Err(StructureError),
    };

    let total_size = file_signature
        .map(|sig| sig.end_offset)
        .unwrap_or(content_end);

    Ok(EvaImage {
        kind,
        file_signature,
        total_size,
    })
}

/// Parse a TI record at the given offset
fn parse_ti_record(
    data: &[u8],
    offset: usize,
    expected_magic: u32,
) -> Result<EvaTiRecord, StructureError> {
    let header_end = offset.checked_add(TI_HEADER_SIZE).ok_or(StructureError)?;
    let header_data = data.get(offset..header_end).ok_or(StructureError)?;

    let (header, _) = TiHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;
    if header.magic.get() != expected_magic {
        return Err(StructureError);
    }
    let payload_length_u32 = header.payload_length.get();
    let payload_length = payload_length_u32 as usize;
    let load_addr = header.load_addr.get();

    let payload_start = header_end;
    let payload_end = payload_start
        .checked_add(payload_length)
        .ok_or(StructureError)?;
    let trailer_end = payload_end
        .checked_add(TI_TRAILER_SIZE)
        .ok_or(StructureError)?;
    if data.len() < trailer_end {
        return Err(StructureError);
    }

    let payload = data.get(payload_start..payload_end).ok_or(StructureError)?;
    let lzma = parse_eva_lzma_payload(payload)?;

    let trailer_data = data.get(payload_end..trailer_end).ok_or(StructureError)?;
    let (trailer, _) = TiTrailerBytes::ref_from_prefix(trailer_data).map_err(|_| StructureError)?;
    if trailer.zero.get() != 0 {
        return Err(StructureError);
    }
    let entry_addr = trailer.entry_addr.get();

    let expected_checksum = calculate_ti_checksum(payload_length_u32, load_addr, payload);
    let checksum_valid = trailer.checksum.get() == expected_checksum;

    Ok(EvaTiRecord {
        load_addr,
        checksum_valid,
        entry_addr,
        lzma,
        header_offset: offset,
        total_size: trailer_end - offset,
    })
}

/// Parse an EVA LZMA payload (16-byte header + 8-byte stream header + compressed data)
fn parse_eva_lzma_payload(payload: &[u8]) -> Result<EvaLzmaPayload, StructureError> {
    let (lzma_header, after_header) =
        EvaLzmaHeaderBytes::ref_from_prefix(payload).map_err(|_| StructureError)?;
    if lzma_header.type_.get() != EVA_LZMA_TYPE_MAGIC {
        return Err(StructureError);
    }
    let compressed_len = lzma_header.compressed_len.get() as usize;
    let uncompressed_len = lzma_header.uncompressed_len.get() as usize;
    let stored_data_checksum = lzma_header.data_checksum.get();

    // Stream header: properties(1) + dict_size(4) + unknown(3)
    let (stream_header, _) =
        EvaLzmaStreamHeaderBytes::ref_from_prefix(after_header).map_err(|_| StructureError)?;
    let properties = stream_header.properties;
    let dict_size = stream_header.dict_size.get();

    // Compressed data lives immediately after the stream header
    let data_start = EVA_LZMA_HEADER_SIZE + EVA_LZMA_STREAM_HEADER;
    let data_end = data_start
        .checked_add(compressed_len)
        .ok_or(StructureError)?;
    if payload.len() < data_end {
        return Err(StructureError);
    }
    let compressed_data = payload.get(data_start..data_end).ok_or(StructureError)?;

    let data_checksum_valid = crc32(compressed_data) == stored_data_checksum;

    Ok(EvaLzmaPayload {
        compressed_len,
        uncompressed_len,
        data_checksum_valid,
        properties,
        dict_size,
    })
}

/// Two's complement additive checksum: `(payload_length + load_addr + sum_of_payload_bytes + checksum) ≡ 0 (mod 2^32)`
fn calculate_ti_checksum(payload_length: u32, load_addr: u32, payload: &[u8]) -> u32 {
    let byte_sum: u32 = payload
        .iter()
        .map(|&b| u32::from(b))
        .fold(0, u32::wrapping_add);
    payload_length
        .wrapping_add(load_addr)
        .wrapping_add(byte_sum)
        .wrapping_neg()
}

/// Round `n` up to the next multiple of `alignment`. `alignment` must be a
/// power of two. Returns `None` if the rounded value would overflow `usize`.
fn align_up(n: usize, alignment: usize) -> Option<usize> {
    debug_assert!(alignment.is_power_of_two());
    n.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}

/// Scan forward from `content_end` at 4-byte stride for a trailing file
/// signature. `content_end` is in image-local coordinates; the signature
/// may sit flush against it or follow zero padding.
fn detect_file_signature(
    file_data: &[u8],
    image_offset: usize,
    content_end: usize,
) -> Option<EvaFileSignature> {
    let data = file_data.get(image_offset..)?;
    let scan_end = data
        .len()
        .min(content_end.saturating_add(FILE_SIGNATURE_SCAN_WINDOW));

    let mut candidate = content_end;
    while candidate.saturating_add(FILE_SIGNATURE_SIZE) <= scan_end {
        if let Some(sig) = try_file_signature_at(file_data, image_offset, candidate) {
            return Some(sig);
        }
        candidate += 4;
    }
    None
}

fn try_file_signature_at(
    file_data: &[u8],
    image_offset: usize,
    candidate: usize,
) -> Option<EvaFileSignature> {
    let data = file_data.get(image_offset..)?;
    let sig_end = candidate.checked_add(FILE_SIGNATURE_SIZE)?;
    let slice = data.get(candidate..sig_end)?;
    let (sig, _) = FileSignatureBytes::ref_from_prefix(slice).ok()?;
    if sig.magic.get() != FILE_SIGNATURE_MAGIC {
        return None;
    }
    let crc = sig.crc.get();
    // CRC input is every byte of the original file before the 8-byte signature
    let absolute_candidate = image_offset.checked_add(candidate)?;
    let crc_input = file_data.get(0..absolute_candidate)?;
    let expected_crc = eva_file_signature_crc32(crc_input);
    Some(EvaFileSignature {
        crc,
        valid: crc == expected_crc,
        end_offset: sig_end,
    })
}

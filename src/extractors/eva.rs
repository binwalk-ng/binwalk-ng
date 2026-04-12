use std::path::Path;

use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::eva::{
    EVA_LZMA_HEADER_SIZE, EVA_LZMA_STREAM_HEADER, EvaImageKind, EvaTiRecord,
    LZMA_ALONE_HEADER_SIZE, TI_HEADER_SIZE, parse_eva_image,
};

const PRIMARY_OUTPUT_FILE_NAME: &str = "kernel.lzma";
const SECONDARY_OUTPUT_FILE_NAME: &str = "kernel_2nd.lzma";

/// Defines the internal extractor for Fritz!Box EVA kernel images
pub fn eva_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_eva),
        ..Default::default()
    }
}

/// Internal EVA kernel image extractor
pub fn extract_eva(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    let Some(data) = file_data.get(offset..) else {
        return result;
    };
    let Ok(image) = parse_eva_image(file_data, offset) else {
        return result;
    };

    if !image.all_checksums_valid() {
        return result;
    }

    // Reconstruct every TI record as a standard LZMA-alone stream paired with its on-disk name
    let outputs: Vec<(&str, Vec<u8>)> = match &image.kind {
        EvaImageKind::SingleKernel(record) => {
            let Some(bytes) = reconstruct_lzma_alone(data, record) else {
                return result;
            };
            vec![(PRIMARY_OUTPUT_FILE_NAME, bytes)]
        }
        EvaImageKind::SecondaryFragment(record) => {
            let Some(bytes) = reconstruct_lzma_alone(data, record) else {
                return result;
            };
            vec![(SECONDARY_OUTPUT_FILE_NAME, bytes)]
        }
        EvaImageKind::DualKernel {
            primary, secondary, ..
        } => {
            let Some(primary_bytes) = reconstruct_lzma_alone(data, primary) else {
                return result;
            };
            let Some(secondary_bytes) = reconstruct_lzma_alone(data, secondary) else {
                return result;
            };
            vec![
                (PRIMARY_OUTPUT_FILE_NAME, primary_bytes),
                (SECONDARY_OUTPUT_FILE_NAME, secondary_bytes),
            ]
        }
    };

    if let Some(output_directory) = output_directory {
        let chroot = Chroot::new(output_directory);
        for (name, bytes) in &outputs {
            if !chroot.create_file(name, bytes) {
                return result;
            }
        }
    }

    result.success = true;
    result.size = Some(image.total_size);
    result
}

/// Reconstruct a standard LZMA alone stream from an EVA TI record
///
/// Standard LZMA alone format:
/// ```text
///   [properties:        1 byte]
///   [dict_size:         4 bytes, little-endian]
///   [uncompressed_size: 8 bytes, little-endian]  (upper 4 bytes zero-padded)
///   [compressed_data:   compressed_len bytes]
/// ```
///
/// The 3 "unknown" padding bytes from the EVA stream header are dropped
fn reconstruct_lzma_alone(image_data: &[u8], record: &EvaTiRecord) -> Option<Vec<u8>> {
    let compressed_data_offset =
        record.header_offset + TI_HEADER_SIZE + EVA_LZMA_HEADER_SIZE + EVA_LZMA_STREAM_HEADER;
    let compressed_data_end = compressed_data_offset.checked_add(record.lzma.compressed_len)?;
    let compressed_data = image_data.get(compressed_data_offset..compressed_data_end)?;

    let mut out = Vec::with_capacity(LZMA_ALONE_HEADER_SIZE + compressed_data.len());
    out.push(record.lzma.properties);
    out.extend_from_slice(&record.lzma.dict_size.to_le_bytes());
    out.extend_from_slice(&(record.lzma.uncompressed_len as u64).to_le_bytes());
    out.extend_from_slice(compressed_data);
    debug_assert_eq!(out.len(), LZMA_ALONE_HEADER_SIZE + compressed_data.len());
    Some(out)
}

use std::path::Path;

use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};

/// Defines the internal extractor function for u16 swapped firmware images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::common::ExtractorType;
/// use binwalk_ng::extractors::swapped::swapped_extractor_u16;
///
/// match swapped_extractor_u16().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn swapped_extractor_u16() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_swapped_u16),
        ..Default::default()
    }
}

/// Extract firmware where every two bytes have been swapped
pub fn extract_swapped_u16(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const SWAP_BYTE_COUNT: usize = 2;
    extract_swapped::<SWAP_BYTE_COUNT>(file_data, offset, output_directory)
}

/// Extract a block of data where every n bytes have been swapped
fn extract_swapped<const N: usize>(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "swapped.bin";

    let mut result = ExtractionResult::default();

    if let Some(data) = file_data.get(offset..) {
        let swapped_data = byte_swap::<N>(data);

        result.success = !swapped_data.is_empty();

        if result.success {
            result.size = Some(swapped_data.len());

            // Write to file, if requested
            if let Some(output_directory) = output_directory {
                let chroot = Chroot::new(output_directory);
                result.success = chroot.create_file(OUTPUT_FILE_NAME, &swapped_data);
            }
        }
    }

    result
}

/// Swap every N bytes of the provided data
///
/// ## Example:
///
/// ```
/// use binwalk_ng::extractors::swapped::byte_swap;
///
/// assert_eq!(byte_swap::<2>(b"ABCD"), b"CDAB");
/// ```
///
/// Remaining bytes are copied as-is:
///
/// ```
/// use binwalk_ng::extractors::swapped::byte_swap;
///
/// assert_eq!(byte_swap::<2>(b"ABCD12"), b"CDAB12");
/// ```
pub fn byte_swap<const N: usize>(data: &[u8]) -> Vec<u8> {
    let mut swapped_data: Vec<u8> = vec![0; data.len()];

    let mut dst_chunks = swapped_data.chunks_exact_mut(N * 2);
    let mut src_chunks = data.chunks_exact(N * 2);
    for (dst_chunk, src_chunk) in std::iter::zip(&mut dst_chunks, &mut src_chunks) {
        let (dst_l, dst_r) = dst_chunk.split_at_mut(N);
        let (src_l, src_r) = src_chunk.split_at(N);
        dst_l.copy_from_slice(src_r);
        dst_r.copy_from_slice(src_l);
    }
    dst_chunks
        .into_remainder()
        .copy_from_slice(src_chunks.remainder());

    swapped_data
}

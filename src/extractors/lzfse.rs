use crate::extractors::common::Chroot;
use crate::extractors::common::{ExtractionResult, Extractor, ExtractorType};
use crate::structures::lzfse::parse_lzfse_block_header;
use std::path::Path;

/// Describes how to run the lzfse utility to decompress LZFSE files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::common::ExtractorType;
/// use binwalk_ng::extractors::lzfse::lzfse_extractor;
///
/// match lzfse_extractor().utility {
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
pub fn lzfse_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(lzfse_decompress),
        ..Default::default()
    }
}

fn lzfse_decompress(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";

    let mut exresult = ExtractionResult::default();

    let data = &file_data[offset..];
    let mut dst_size = 0;
    let src_size = {
        let mut remaining_data = data;
        while let Ok(lzfse_block) = parse_lzfse_block_header(remaining_data) {
            let block_size = lzfse_block.header_size + lzfse_block.data_size;
            dst_size += lzfse_block.uncompressed_size;
            remaining_data = &remaining_data[block_size..];
            if lzfse_block.eof {
                break;
            }
            // We'll never return a header with zero size, but if we did, this would be an infinite loop
            assert!(block_size > 0);
        }
        data.len() - remaining_data.len()
    };

    // The LZFSE API can't differentiate between decompressing exactly the right amount of data and
    // truncation (see https://github.com/lzfse/lzfse/issues/5#issuecomment-237134992), so
    // give it an extra byte so we can differentiate.
    let mut dst = vec![0; dst_size + 1];
    if let Ok(actual_len) = lzfse::decode_buffer(&data[..src_size], &mut dst)
        && actual_len == dst_size
    {
        exresult.success = true;
        exresult.size = Some(dst_size);
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            exresult.success = chroot.create_file(OUTPUT_FILE_NAME, &dst[..dst_size]);
        }
    }

    exresult
}

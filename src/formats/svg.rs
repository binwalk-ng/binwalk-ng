use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use aho_corasick::AhoCorasick;
use std::path::Path;

/// Human readable description
pub const DESCRIPTION: &str = "SVG image";

/// SVG magic bytes
pub fn svg_magic() -> Vec<Vec<u8>> {
    vec![b"<svg ".to_vec()]
}

/// Parse an SVG image
pub fn svg_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Perform an extraction dry-run
    let dry_run = extract_svg_image(file_data, offset, None);

    // If the dry-run was a success, this is probably a valid JPEG file
    if dry_run.success {
        // Get the total size of the SVG
        if let Some(svg_size) = dry_run.size {
            // If this file starts with SVG data, there's no need to extract it
            if offset == 0 {
                result.extraction_declined = true;
            }

            // Report signature result
            result.size = svg_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

const SVG_OPEN_TAG: &[u8] = b"<svg ";
const SVG_CLOSE_TAG: &[u8] = b"</svg>";
const SVG_HEAD_MAGIC: &str = "xmlns=\"http://www.w3.org/2000/svg\"";

/// Stores info about an SVG image
#[derive(Debug, Default, Clone)]
pub struct SVGImage {
    pub total_size: usize,
}

/// Parse an SVG image to determine its total size
pub fn parse_svg_image(svg_data: &[u8]) -> Result<SVGImage, StructureError> {
    let mut head_tag_count: usize = 0;
    let mut unclosed_svg_tags: usize = 0;

    let svg_tags = vec![SVG_OPEN_TAG, SVG_CLOSE_TAG];

    let grep = AhoCorasick::new(svg_tags).unwrap();

    // Need to search through the data to find all <svg ...> and </svg> tags.
    // There may be multiple of these tags in any given SVG image.
    for tag_match in grep.find_overlapping_iter(svg_data) {
        let tag_start = tag_match.start();

        match parse_svg_tag(&svg_data[tag_start..]) {
            Err(_) => {
                break;
            }
            Ok(svg_tag) => {
                if svg_tag.is_head {
                    head_tag_count += 1;
                }

                if svg_tag.is_open {
                    unclosed_svg_tags += 1;
                }

                if svg_tag.is_close {
                    unclosed_svg_tags -= 1;
                }

                // There should be only one head tag
                if head_tag_count > 1 {
                    break;
                }

                // If one head tag was found and all svg tags are closed, that's EOF
                if head_tag_count == 1 && unclosed_svg_tags == 0 {
                    return Ok(SVGImage {
                        total_size: tag_start + SVG_CLOSE_TAG.len(),
                    });
                }
            }
        }
    }

    Err(StructureError)
}

/// Stores info about a parsed SVG tag
#[derive(Debug, Default, Clone)]
struct SVGTag {
    pub is_head: bool,
    pub is_open: bool,
    pub is_close: bool,
}

/// Parse an individual SVG tag
fn parse_svg_tag(tag_data: &[u8]) -> Result<SVGTag, StructureError> {
    const END_TAG: u8 = 0x3E;

    let svg_open_tag = String::from_utf8(SVG_OPEN_TAG.to_vec()).unwrap();
    let svg_close_tag = String::from_utf8(SVG_CLOSE_TAG.to_vec()).unwrap();
    let svg_head_string = SVG_HEAD_MAGIC.to_string();

    // Tags are expected to start with '<svg' or </svg>', and end with '>'
    for i in 0..tag_data.len() {
        if tag_data[i] == END_TAG
            && let Some(tag_bytes) = tag_data.get(0..i + 1)
            && let Ok(tag_string) = String::from_utf8(tag_bytes.to_vec())
        {
            return Ok(SVGTag {
                is_head: tag_string.contains(&svg_head_string),
                is_open: tag_string.starts_with(&svg_open_tag),
                is_close: tag_string.starts_with(&svg_close_tag),
            });
        }
    }

    Err(StructureError)
}

/// Defines the internal extractor function for carving out SVG images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::svg::svg_extractor;
///
/// match svg_extractor().utility {
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
pub fn svg_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(extract_svg_image),
        ..Default::default()
    }
}

/// Internal extractor for carving SVG images to disk
pub fn extract_svg_image(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "image.svg";

    let mut result = ExtractionResult::default();

    // Parse the SVG image to determine its total size
    if let Ok(svg_image) = parse_svg_image(&file_data[offset..]) {
        result.size = Some(svg_image.total_size);
        result.success = true;

        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success =
                chroot.carve_file(OUTFILE_NAME, file_data, offset, result.size.unwrap());
        }
    }

    result
}

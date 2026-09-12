use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use aho_corasick::AhoCorasick;
use std::path::Path;
use std::sync::LazyLock;

/// Human readable description
pub const DESCRIPTION: &str = "SVG image";

/// SVG magic bytes
pub fn svg_magic() -> Vec<Vec<u8>> {
    vec![SVG_OPEN_TAG.as_bytes().to_vec()]
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

    // If the dry-run was a success, this is probably a valid SVG file
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

const SVG_OPEN_TAG: &str = "<svg ";
const SVG_CLOSE_TAG: &str = "</svg>";

/// Stores info about an SVG image
#[derive(Debug, Default, Clone)]
pub struct SVGImage {
    pub total_size: usize,
}

const SVG_TAGS: [&str; 2] = [SVG_OPEN_TAG, SVG_CLOSE_TAG];
const OPEN_PATTERN: usize = 0;
const CLOSE_PATTERN: usize = 1;
static SVG_OPEN_CLOSE_TAG_PATTERNS: LazyLock<AhoCorasick> =
    LazyLock::new(|| AhoCorasick::new(SVG_TAGS).unwrap());

/// Parse an SVG image to determine its total size
pub fn parse_svg_image(svg_data: &[u8]) -> Result<SVGImage, StructureError> {
    let mut offset = 0;
    let mut depth = 0usize;

    let grep: &AhoCorasick = &SVG_OPEN_CLOSE_TAG_PATTERNS;

    // Need to search through the data to find all <svg ...> and </svg> tags.
    // There may be multiple of these tags in any given SVG image.
    while let Some(tag_match) = grep.find(aho_corasick::Input::new(svg_data).range(offset..)) {
        if str::from_utf8(&svg_data[offset..tag_match.start()]).is_err() {
            // Only allow UTF-8 contents, don't accidentally consume binary data
            break;
        };
        offset = match tag_match.pattern().as_usize() {
            OPEN_PATTERN => {
                // Make sure the tag closes
                let Some(tag_len) = memchr::memchr(b'>', &svg_data[tag_match.end()..]) else {
                    break;
                };
                if str::from_utf8(&svg_data[tag_match.end()..][..tag_len]).is_err() {
                    // Only allow UTF-8 contents, don't accidentally consume binary data
                    break;
                }
                depth += 1;
                tag_match.end() + tag_len + 1
            }
            CLOSE_PATTERN => {
                depth = depth.checked_sub(1).ok_or(StructureError)?;
                tag_match.end()
            }
            _ => unreachable!(),
        };
        if depth == 0 {
            return Ok(SVGImage { total_size: offset });
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

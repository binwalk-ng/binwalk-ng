use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use aho_corasick::AhoCorasick;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use std::path::Path;

/// Human readable descriptions
pub const PEM_PUBLIC_KEY_DESCRIPTION: &str = "PEM public key";
pub const PEM_PRIVATE_KEY_DESCRIPTION: &str = "PEM private key";
pub const PEM_CERTIFICATE_DESCRIPTION: &str = "PEM certificate";

/// Magic bytes that identify PEM public keys
const PUBLIC_KEY_MAGICS: [&[u8]; 4] = [
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"-----BEGIN DSA PUBLIC KEY-----",
    b"-----BEGIN ECDSA PUBLIC KEY-----",
];

/// Magic bytes that identify PEM private keys
const PRIVATE_KEY_MAGICS: [&[u8]; 8] = [
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ANY PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN TSS2 PRIVATE KEY-----",
];

/// Magic bytes that identify PEM certificates
const CERTIFICATE_MAGICS: [&[u8]; 1] = [b"-----BEGIN CERTIFICATE-----"];

/// Public key magic
pub fn pem_public_key_magic() -> Vec<Vec<u8>> {
    PUBLIC_KEY_MAGICS
        .iter()
        .map(|magic| magic.to_vec())
        .collect()
}

/// Private key magics
pub fn pem_private_key_magic() -> Vec<Vec<u8>> {
    PRIVATE_KEY_MAGICS
        .iter()
        .map(|magic| magic.to_vec())
        .collect()
}

/// Certificate magic
pub fn pem_certificate_magic() -> Vec<Vec<u8>> {
    CERTIFICATE_MAGICS
        .iter()
        .map(|magic| magic.to_vec())
        .collect()
}

/// Validates both PEM certificate and key signatures
pub fn pem_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Enough bytes to uniquely differentiate certs from keys
    const MIN_PEM_LEN: usize = 26;

    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Sanity check available data
    if let Some(pem_magic) = file_data.get(offset..offset + MIN_PEM_LEN) {
        // All magic bytes are at least MIN_PEM_LEN long and unique within their first
        // MIN_PEM_LEN bytes, so comparing their prefix against the data is enough to tell
        // a public key from a private key from a certificate.
        if PUBLIC_KEY_MAGICS
            .iter()
            .any(|magic| magic.starts_with(pem_magic))
        {
            result.description = PEM_PUBLIC_KEY_DESCRIPTION.to_string();
        } else if PRIVATE_KEY_MAGICS
            .iter()
            .any(|magic| magic.starts_with(pem_magic))
        {
            result.description = PEM_PRIVATE_KEY_DESCRIPTION.to_string();
        } else if CERTIFICATE_MAGICS
            .iter()
            .any(|magic| magic.starts_with(pem_magic))
        {
            result.description = PEM_CERTIFICATE_DESCRIPTION.to_string();
        } else {
            // This function will only be called if one of the magics was found, so this should never happen
            return Err(SignatureError);
        }

        // Do an extraction dry-run to validate that this PEM file looks sane
        let dry_run = pem_carver(file_data, offset, None, None);
        if dry_run.success
            && let Some(pem_size) = dry_run.size
        {
            // Make sure the PEM data can be base64 decoded
            if decode_pem_data(&file_data[offset..offset + pem_size]).is_ok() {
                // If the file starts and end with this PEM data, no sense in carving it out to another file on disk
                if offset == 0 && pem_size == file_data.len() {
                    result.extraction_declined = true;
                }

                result.size = pem_size;
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Base64 decode PEM file contents
fn decode_pem_data(pem_file_data: &[u8]) -> Result<usize, SignatureError> {
    const DELIM: &str = "--";

    // Make sure the PEM data can be converted to a string
    if let Ok(pem_file_string) = std::str::from_utf8(pem_file_data) {
        let mut delim_count: usize = 0;
        let mut base64_string: String = "".to_string();

        // Loop through PEM file lines
        for line in pem_file_string.lines() {
            // PEM begin and end delimiter strings both start with hyphens
            if line.starts_with(DELIM) {
                delim_count += 1;

                // Expect two delimiters: the start, and the end. If we've found both, break.
                if delim_count == 2 {
                    break;
                } else {
                    continue;
                }
            }

            // This is not a delimiter string, append the line to the base64 string to be decoded
            base64_string.push_str(line);
        }

        // If we found some text between the delimiters, attempt to base64 decode it
        if !base64_string.is_empty() {
            // PEM contents are base64 encoded, they should decode OK; if not, it's a false positive
            if let Ok(decoded_data) = BASE64_STANDARD.decode(&base64_string) {
                return Ok(decoded_data.len());
            }
        }
    }

    Err(SignatureError)
}

/// Defines the internal extractor function for carving out PEM keys
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::pem::pem_key_extractor;
///
/// match pem_key_extractor().utility {
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
pub fn pem_key_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(pem_key_carver),
        ..Default::default()
    }
}

/// Internal extractor function for carving out PEM certs
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::pem::pem_certificate_extractor;
///
/// match pem_certificate_extractor().utility {
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
pub fn pem_certificate_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(pem_certificate_carver),
        ..Default::default()
    }
}

pub fn pem_certificate_carver(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const CERTIFICATE_FILE_NAME: &str = "pem.crt";
    pem_carver(
        file_data,
        offset,
        output_directory,
        Some(CERTIFICATE_FILE_NAME),
    )
}

pub fn pem_key_carver(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const KEY_FILE_NAME: &str = "pem.key";
    pem_carver(file_data, offset, output_directory, Some(KEY_FILE_NAME))
}

pub fn pem_carver(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
    fname: Option<&str>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    if let Some(pem_size) = get_pem_size(file_data, offset) {
        result.size = Some(pem_size);
        result.success = true;

        if let Some(outfile) = fname
            && let Some(output_directory) = output_directory
        {
            let chroot = Chroot::new(output_directory);
            result.success = chroot.carve_file(outfile, file_data, offset, result.size.unwrap());
        }
    }

    result
}

fn get_pem_size(file_data: &[u8], start_of_pem_offset: usize) -> Option<usize> {
    const EOF_MARKERS: [&[u8]; 7] = [
        b"-----END PUBLIC KEY-----",
        b"-----END CERTIFICATE-----",
        b"-----END PRIVATE KEY-----",
        b"-----END EC PRIVATE KEY-----",
        b"-----END RSA PRIVATE KEY-----",
        b"-----END DSA PRIVATE KEY-----",
        b"-----END OPENSSH PRIVATE KEY-----",
    ];

    let newline_chars = [0x0D, 0x0A];

    let grep = AhoCorasick::new(EOF_MARKERS).unwrap();

    // Find the first end marker
    if let Some(eof_match) = grep
        .find_overlapping_iter(&file_data[start_of_pem_offset..])
        .next()
    {
        let eof_marker_index = eof_match.pattern().as_usize();
        let mut pem_size = eof_match.start() + EOF_MARKERS[eof_marker_index].len();

        // Include any trailing newline characters in the total size of the PEM file
        while (start_of_pem_offset + pem_size) < file_data.len() {
            if newline_chars.contains(&file_data[start_of_pem_offset + pem_size]) {
                pem_size += 1;
            } else {
                break;
            }
        }

        return Some(pem_size);
    }

    None
}

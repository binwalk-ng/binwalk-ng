//! # File / Data Signatures
//!
//! Creating a signature to identify a particular file or data type is composed of two parts:
//!
//! 1. Defining the signature's attributes
//! 2. Writing a parser to parse and validate potential signature matches
//!
//! ## Defining a Signature
//!
//! Signatures are defined using the `signatures::Signature` struct. This structure stores critical information
//! about a signature, such as the signature name, the magic bytes that are associated with the signature, and which extractor
//! to use (if any) to extract the data associated with the signature.
//!
//! ### Example
//!
//! ```ignore
//! use binwalk_ng::extractors::foobar::foobar_extractor;
//! use binwalk_ng::signatures::Signature;
//! use binwalk_ng::signatures::foobar::foobar_parser;
//!
//! // FooBar file signature
//! let foobar_signature = Signature {
//!     // A unique name for the signature, no spaces; signatures can be included/excluded from analysis based on this attribute
//!     name: "foobar".to_string(),
//!     // Set to true for signatures with very short magic bytes; they will only be matched at file offset 0
//!     short: false,
//!     // Offset from the start of the file to the "magic" bytes; only really relevant for short signatures
//!     magic_offset: 0,
//!     // Most signatures will want to set this to false and let the code in main.rs determine if/when to display
//!     always_display: false,
//!     // The magic bytes associated with this signature; there may be more than one set of magic bytes per signature
//!     magic: vec![b"\xF0\x00\xBA\xA2".to_vec()],
//!     // This is the parser function to call to validate magic byte matches
//!     parser: foobar_parser,
//!     // A short human-readable description of the signature
//!     description: "FooBar file".to_string(),
//!     // The extractor to use to extract this file/data type
//!     extractor: Some(foobar_extractor()),
//! };
//! ```
//!
//! Internally, Binwalk keeps a list of `Signature` definitions in `magic.rs`.
//!
//! ## Signature Parsers
//!
//! Signature parsers are at the heart of each defined signature. They parse and validate magic matches to ensure accuracy and
//! determine the total size of the file data (if possible).
//!
//! Signature parsers must conform to the `signatures::SignatureParser` type definition.
//! They are provided two arguments: the raw file data, and an offset into the file data where the signature's magic bytes were found.
//!
//! Signature parsers must parse and validate the expected signature data, and return either a `signatures::SignatureResult`
//! structure on success, or a `signatures::SignatureError` on failure.
//!
//! ### Example
//!
//! ```ignore
//! use binwalk_ng::extractors::foobar::extract_foobar_file;
//! use binwalk_ng::signatures::{SignatureResult, SignatureError, CONFIDENCE_HIGH};
//!
//! /// This function is responsible for parsing and validating the FooBar file system data whenever the "magic bytes"
//! /// are found inside a file. It is provided access to the entire file data, and an offset into the file data where
//! /// the magic bytes were found. On success, it will return a signatures::SignatureResult structure.
//! ///
//! pub fn foobar_parser(file_data: &Vec<u8>, offset: usize) -> Result<SignatureResult, SignatureError> {
//!    /*
//!     * This will be returned if the format of the suspected FooBar file system looks correct.
//!     * We will update it later with more information, but for now just define what is known
//!     * (the offset where the FooBar file  starts, the human-readable description, and
//!     * a confidence level), and leave the remaining fields at their defaults.
//!     *
//!     * Note that confidence level is chosen somewhat arbitrarily, and should be one of:
//!     *
//!     *   - CONFIDENCE_LOW (the default)
//!     *   - CONFIDENCE_MEDIUM
//!     *   - CONFIDENCE_HIGH
//!     *
//!     * In this case the extractor and header parser (defined elsewhere) validate CRC's, so if those pass,
//!     * the confidence that this is in fact a FooBar file type is high.
//!     */
//!    let mut result = SignatureResult {
//!         offset: offset,
//!         description: "FooBar file".to_string(),
//!         confidence: CONFIDENCE_HIGH,
//!         ..Default::default()
//!    };
//!
//!    /*
//!     * The internal FooBar file extractor already parses the header and validates the data CRC. By passing it an output
//!     * directory of None, it will still parse and validate the data, but without performing an extraction.
//!     */
//!    let dry_run = extact_foobar_file(file_data, offset, None);
//!
//!    // The extractor should have reported success, as well as the total size of the file data
//!    if dry_run.success == true {
//!        if let Some(file_size) = dry_run.size {
//!            // Update the reported size and human-readable description and return the result
//!            result.size = file_size;
//!            result.description = format!("{}, total size: {} bytes", result.description, result.size);
//!            return Ok(result);
//!        }
//!    }
//!
//!    // Something didn't look right about this file data, it is likely a false positive, so return an error
//!    return Err(SignatureError);
//! }
//! ```

use crate::extractors;
use serde::{Deserialize, Serialize};

/// Some pre-defined confidence levels for SignatureResult structures
pub const CONFIDENCE_LOW: u8 = 0;
pub const CONFIDENCE_MEDIUM: u8 = 128;
pub const CONFIDENCE_HIGH: u8 = 250;

/// Return value of SignatureParser upon error
#[derive(Debug, Clone)]
pub struct SignatureError;

/// Type definition for signature parser functions
///
/// ## Arguments
///
/// All signature parsers are passed two arguments: a vector of u8 bytes, and an offset into that vector where the signature's magic bytes were found.
///
/// ## Return values
///
/// Each signature parser is responsible for parsing and validating signature candidates.
///
/// They must return either a SignatureResult struct if validation succeeds, or a SignatureError if validation fails.
pub type SignatureParser = fn(&[u8], usize) -> Result<SignatureResult, SignatureError>;

/// Describes a valid identified file signature
///
/// ## Construction
///
/// The SignatureResult struct is returned by all SignatureParser functions upon success.
///
/// The `id`, `name`, and `always_display` fields are automatically populated after being returned by a SignatureParser function, and need not be set by the SignatureParser function.
///
/// At the very least, SignatureParser functions should define the `offset` and `description` fields.
///
/// ## Additional Notes
///
/// If a SignatureResult contains a `size` of `0` (the default value), it is assumed to extend to the beginning of the next signature, or EOF, whichever comes first.
///
/// SignatureResult structs are sortable by `offset`.
///
/// SignatureResult structs can be JSON serialized/deserialized with [serde](https://crates.io/crates/serde).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignatureResult {
    /// File/data offset where this signature starts
    pub offset: usize,
    /// A UUID uniquely identifying this signature result; auto-populated
    pub id: String,
    /// Size of the signature data, 0 if unknown
    pub size: usize,
    /// A unique name for this signature type, auto-populated from the signature definition in Signature.name
    pub name: String,
    /// One of CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH; default is CONFIDENCE_LOW
    pub confidence: u8,
    /// Human readable description of this signature
    pub description: String,
    /// If true, always display this signature result; auto-populated from the signature definition in Signature.always_display
    pub always_display: bool,
    /// Set to true to disable extraction for this particular signature result (default: false)
    pub extraction_declined: bool,
    /// Signatures may specify a preferred extractor, which overrides the default extractor specified in the Signature.extractor definition
    #[serde(skip_deserializing, skip_serializing)]
    pub preferred_extractor: Option<extractors::Extractor>,
}

/// Defines a file signature to search for, and how to extract that file type
#[derive(Debug, Clone)]
pub struct Signature {
    /// Unique name for the signature (no whitespace)
    pub name: String,
    /// Set to true if this is a short signature; it will only be matched at the beginning of a file
    pub short: bool,
    /// List of magic byte patterns associated with this signature
    pub magic: Vec<Vec<u8>>,
    /// Offset of magic bytes from the beginning of the file; only relevant for short signatures
    pub magic_offset: usize,
    /// Human readable description of this signature
    pub description: String,
    /// If true, will always display files that contain this signature, even during recursive extraction
    pub always_display: bool,
    /// Specifies the signature parser to invoke for magic match validation
    pub parser: SignatureParser,
    /// Specifies the extractor to use when extracting this file type
    pub extractor: Option<extractors::Extractor>,
}

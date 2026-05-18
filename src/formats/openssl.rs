use crate::common::is_printable_ascii;
use crate::signatures::{CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "OpenSSL encryption";

/// OpenSSL crypto magic
pub fn openssl_crypt_magic() -> Vec<Vec<u8>> {
    vec![b"Salted__".to_vec()]
}

/// Validate an openssl signature
pub fn openssl_crypt_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    // Parse the header
    if let Ok(openssl_header) = parse_openssl_crypt_header(&file_data[offset..]) {
        // Sanity check the salt value
        if !is_salt_invalid(openssl_header.salt) {
            // If the magic starts at the beginning of a file, our confidence is a bit higher
            if offset == 0 {
                result.confidence = CONFIDENCE_MEDIUM;
            }

            result.description =
                format!("{}, salt: {:#X}", result.description, openssl_header.salt);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

// Returns true if the salt is entirely comprised of NULL and/or ASCII bytes
fn is_salt_invalid(salt: u64) -> bool {
    const SALT_LEN: usize = std::mem::size_of::<u64>();

    (0..SALT_LEN).all(|i| {
        let byte = ((salt >> (8 * i)) & 0xFF) as u8;
        byte == 0 || is_printable_ascii(byte)
    })
}

/// Struct to store info on an OpenSSL crypto header
pub struct OpenSSLCryptHeader {
    pub salt: u64,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SSLHeaderBytes {
    magic: zerocopy::U64<BE>,
    salt: zerocopy::U64<BE>,
}

/// Parse an OpenSSl crypto header
pub fn parse_openssl_crypt_header(ssl_data: &[u8]) -> Result<OpenSSLCryptHeader, StructureError> {
    let (ssl_header, _) = SSLHeaderBytes::ref_from_prefix(ssl_data).map_err(|_| StructureError)?;

    match ssl_header.salt.get() {
        0 => Err(StructureError),
        salt => Ok(OpenSSLCryptHeader { salt }),
    }
}

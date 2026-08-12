use crate::signatures::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "PKCS DER hash";

/// The hash types and their associated signature bytes
const DER_HASH_LOOKUPS: &[(&str, &[u8])] = &[
    (
        "MD5",
        b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    ),
    (
        "SHA1",
        b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    ),
    (
        "SHA256",
        b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    ),
    (
        "SHA384",
        b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    ),
    (
        "SHA512",
        b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04",
    ),
];

/// DER hash signatures
pub fn der_hash_magic() -> Vec<Vec<u8>> {
    DER_HASH_LOOKUPS
        .iter()
        .map(|(_, magic)| magic.to_vec())
        .collect()
}

/// Validates the DER hash matches
pub fn der_hash_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    for (name, magic) in DER_HASH_LOOKUPS {
        let hash_start = offset;
        let hash_end = hash_start + magic.len();

        if let Some(hash_bytes) = file_data.get(hash_start..hash_end)
            && hash_bytes == *magic
        {
            result.size = magic.len();
            result.description = format!("{}, {}", result.description, name);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

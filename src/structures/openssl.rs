use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

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

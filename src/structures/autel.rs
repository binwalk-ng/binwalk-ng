use crate::common::get_cstring;
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store Autel ECC header info
#[derive(Debug, Default, Clone)]
pub struct AutelECCHeader {
    pub data_size: usize,
    pub header_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct AutelEccHeaderBytes {
    magic: zerocopy::U64<LE>,
    data_size: zerocopy::U32<LE>,
    header_size: zerocopy::U32<LE>,
    copyright: [u8; 16],
}

/// Parses an Autel header
pub fn parse_autel_header(autel_data: &[u8]) -> Result<AutelECCHeader, StructureError> {
    const EXPECTED_HEADER_SIZE: u32 = 0x20;
    const EXPECTED_COPYRIGHT_STRING: &str = "Copyright Autel";

    // Parse the header
    let (autel_header, _) =
        AutelEccHeaderBytes::ref_from_prefix(autel_data).map_err(|_| StructureError)?;

    // Sanity check the reported header size
    if autel_header.header_size.get() == EXPECTED_HEADER_SIZE {
        // Get the copyright string contained in the header

        let copyright_string = get_cstring(&autel_header.copyright);

        // Sanity check the copyright string value
        if copyright_string == EXPECTED_COPYRIGHT_STRING {
            return Ok(AutelECCHeader {
                data_size: autel_header.data_size.get() as usize,
                header_size: autel_header.header_size.get() as usize,
            });
        }
    }

    Err(StructureError)
}

use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// LZO checksums are 4-bytes long
const LZO_CHECKSUM_SIZE: usize = 4;

/// Struct to store LZOP file header info
#[derive(Debug, Default, Clone)]
pub struct LZOPFileHeader {
    pub header_size: usize,
    pub block_checksum_present: bool,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOHeaderP1 {
    magic_p1: u8,
    magic_p2: zerocopy::U64<BE>,
    version: zerocopy::U16<BE>,
    lib_version: zerocopy::U16<BE>,
    version_needed: zerocopy::U16<BE>,
    method: u8,
    level: u8,
    flags: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOHeaderP2 {
    mode: zerocopy::U32<BE>,
    mtime: zerocopy::U32<BE>,
    gmt_diff: zerocopy::U32<BE>,
    file_name_length: u8,
}

/// Parse an LZOP file header
pub fn parse_lzop_file_header(lzop_data: &[u8]) -> Result<LZOPFileHeader, StructureError> {
    // Max supported LZO version
    const LZO_MAX_VERSION: u16 = 0x1040;

    const LZO_HEADER_SIZE_P1: usize = 21;
    const LZO_HEADER_SIZE_P2: usize = 13;

    const FILTER_SIZE: usize = 4;

    const FLAG_FILTER: u32 = 0x000_00800;
    //const FLAG_CRC32_D: usize = 0x0000_0100;
    const FLAG_CRC32_C: u32 = 0x0000_0200;
    //const FLAG_ADLER32_D: usize = 0x0000_0001;
    const FLAG_ADLER32_C: u32 = 0x0000_0002;

    let allowed_methods = [1, 2, 3];

    let mut lzop_info = LZOPFileHeader::default();

    // Parse the first part of the header
    let (lzo_header_p1, _) = LZOHeaderP1::ref_from_prefix(lzop_data).map_err(|_| StructureError)?;
    // Sanity check the methods field
    if allowed_methods.contains(&lzo_header_p1.method) {
        // Sanity check the header version numbers
        if lzo_header_p1.version <= LZO_MAX_VERSION
            && lzo_header_p1.version >= lzo_header_p1.version_needed
        {
            // Unless the optional filter field is included, start of the second part of the header is at the end of the first
            let mut header_p2_start: usize = LZO_HEADER_SIZE_P1;

            // Next part of the header may or may not have an optional filter field
            if (lzo_header_p1.flags & FLAG_FILTER) != 0 {
                header_p2_start += FILTER_SIZE;
            }

            // Calculate the end of the second part of the header
            let header_p2_end: usize = header_p2_start + LZO_HEADER_SIZE_P2;

            if let Some(header_p2_data) = lzop_data.get(header_p2_start..header_p2_end) {
                // Parse the second part of the header
                let (lzo_header_p2, _) =
                    LZOHeaderP2::ref_from_prefix(header_p2_data).map_err(|_| StructureError)?;

                // Calculate the total header size; compressed data blocks will immediately follow
                lzop_info.header_size =
                    header_p2_end + lzo_header_p2.file_name_length as usize + LZO_CHECKSUM_SIZE;

                // Check if block headers include an optional compressed data checksum field
                lzop_info.block_checksum_present =
                    (lzo_header_p1.flags & (FLAG_ADLER32_C | FLAG_CRC32_C)) != 0;

                // Sanity check on the calculated header size
                if lzop_info.header_size <= lzop_data.len() {
                    return Ok(lzop_info);
                }
            }
        }
    }

    Err(StructureError)
}

/// Struct to store info on LZOP block headers
#[derive(Debug, Default, Clone)]
pub struct LZOPBlockHeader {
    pub header_size: usize,
    pub compressed_size: usize,
    pub checksum_size: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZOPBlockHeaderBytes {
    uncompressed_size: zerocopy::U32<BE>,
    compressed_size: zerocopy::U32<BE>,
    uncompressed_checksum: zerocopy::U32<BE>,
}

/// Parse an LZO block header
pub fn parse_lzop_block_header(
    lzo_data: &[u8],
    compressed_checksum_present: bool,
) -> Result<LZOPBlockHeader, StructureError> {
    const BLOCK_HEADER_SIZE: usize = 12;
    const MAX_UNCOMPRESSED_BLOCK_SIZE: u32 = 64 * 1024 * 1024;

    let (block_header, _) =
        LZOPBlockHeaderBytes::ref_from_prefix(lzo_data).map_err(|_| StructureError)?;
    // Basic sanity check on the block header values
    if block_header.compressed_size != 0
        && block_header.uncompressed_size != 0
        && block_header.uncompressed_checksum != 0
        && block_header.uncompressed_size <= MAX_UNCOMPRESSED_BLOCK_SIZE
    {
        let mut block_hdr_info = LZOPBlockHeader {
            header_size: BLOCK_HEADER_SIZE,
            compressed_size: block_header.compressed_size.get() as usize,
            ..Default::default()
        };

        // Checksum field is optional
        if compressed_checksum_present {
            block_hdr_info.checksum_size = LZO_CHECKSUM_SIZE;
        }

        return Ok(block_hdr_info);
    }

    Err(StructureError)
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EOFMarker {
    marker: zerocopy::U32<BE>,
}

/// Parse an LZOP EOF marker, returns the size of the EOF marker (always 4 bytes)
pub fn parse_lzop_eof_marker(eof_data: &[u8]) -> Result<usize, StructureError> {
    const EOF_MARKER: u32 = 0;
    /*
     * It is unclear, but observed, that LZOP files end with 0x00000000; this is assumed to be an EOF marker,
     * as other similar compression file formats use that. This assumption could be incorrect.
     */
    let (eof_marker, _) = EOFMarker::ref_from_prefix(eof_data).map_err(|_| StructureError)?;

    match eof_marker.marker.get() {
        EOF_MARKER => Ok(std::mem::size_of::<EOFMarker>()),
        _ => Err(StructureError),
    }
}

use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Struct to store useful LZMA header data
#[derive(Debug, Default, Clone)]
pub struct LZMAHeader {
    pub properties: u8,
    pub dictionary_size: u32,
    pub decompressed_size: u64,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct LZMAHeaderBytes {
    properties: u8,
    dictionary_size: zerocopy::U32<LE>,
    decompressed_size: zerocopy::U64<LE>,
    null_byte: u8,
}

/// Parse an LZMA header
pub fn parse_lzma_header(lzma_data: &[u8]) -> Result<LZMAHeader, StructureError> {
    // Streamed data has a reported size of -1
    const LZMA_STREAM_SIZE: u64 = 0xFFFFFFFFFFFFFFFF;

    // Some sane min and max values on the reported decompressed data size
    const MIN_SUPPORTED_DECOMPRESSED_SIZE: u64 = 256;
    const MAX_SUPPORTED_DECOMPRESSED_SIZE: u64 = 0xFFFFFFFF;

    let mut lzma_hdr_info = LZMAHeader {
        ..Default::default()
    };

    // Parse the lzma header
    let (lzma_header, _) =
        LZMAHeaderBytes::ref_from_prefix(lzma_data).map_err(|_| StructureError)?;

    // Make sure the expected NULL byte is NULL
    if lzma_header.null_byte == 0 {
        // Sanity check the reported decompressed size
        let decompressed_size = lzma_header.decompressed_size.get();
        if decompressed_size >= MIN_SUPPORTED_DECOMPRESSED_SIZE
            && (decompressed_size == LZMA_STREAM_SIZE
                || decompressed_size <= MAX_SUPPORTED_DECOMPRESSED_SIZE)
        {
            lzma_hdr_info.properties = lzma_header.properties;
            lzma_hdr_info.dictionary_size = lzma_header.dictionary_size.get();
            lzma_hdr_info.decompressed_size = decompressed_size;

            return Ok(lzma_hdr_info);
        }
    }

    Err(StructureError)
}

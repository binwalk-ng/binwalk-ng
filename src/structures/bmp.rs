use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

#[derive(Debug, Default, Clone)]
pub struct BMPFileHeader {
    pub size: usize,
    pub bitmap_bits_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RawHeader {
    // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapfileheader
    bf_type: zerocopy::U16<LE>,
    bf_size: zerocopy::U32<LE>,
    bf_reserved1: zerocopy::U16<LE>,
    bf_reserved2: zerocopy::U16<LE>,
    bf_off_bits: zerocopy::U32<LE>,
}

pub fn parse_bmp_file_header(bmp_data: &[u8]) -> Result<BMPFileHeader, StructureError> {
    let (raw_header, _rest) = RawHeader::ref_from_prefix(bmp_data).map_err(|_| StructureError)?;
    let bmp_data_size = bmp_data.len();

    let bf_size = raw_header.bf_size.get() as usize;
    let bf_off_bits = raw_header.bf_off_bits.get() as usize;

    // The BMP file size cannot be bigger than bmp_data
    if bmp_data_size < bf_size {
        return Err(StructureError);
    }

    // The file size cannot be 0
    if bf_size == 0 {
        return Err(StructureError);
    }

    // The offset cannot be 0
    if bf_off_bits == 0 {
        return Err(StructureError);
    }

    // The offset cannot be bigger than the file
    if bf_off_bits > bmp_data_size {
        return Err(StructureError);
    }

    // If everything is Ok so far, return a BMPFileHeader
    Ok(BMPFileHeader {
        size: bf_size,
        bitmap_bits_offset: bf_off_bits,
    })
}

// https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ns-wingdi-bitmapv5header
// "The number of bytes required by the structure. Applications should use this member to determine which bitmap information header structure is being used."
pub fn get_dib_header_size(bmp_data: &[u8]) -> Result<usize, StructureError> {
    let valid_header_sizes = [
        12,  // BITMAPCOREHEADER
        40,  // BITMAPINFOHEADER
        108, // BITMAPV4HEADER
        124,
    ];

    let header_size = u32::from_le_bytes(bmp_data[..4].try_into().unwrap());

    if !valid_header_sizes.contains(&header_size) {
        return Err(StructureError);
    }

    Ok(header_size as usize)
}

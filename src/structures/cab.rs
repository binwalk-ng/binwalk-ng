use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Stores CAB header info
#[derive(Debug, Default, Clone)]
pub struct CabinetHeader {
    pub total_size: usize,
    pub header_size: usize,
    pub file_count: usize,
    pub folder_count: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct CabHeaderBytes {
    magic: zerocopy::U32<LE>,
    reserved1: zerocopy::U32<LE>,
    size: zerocopy::U32<LE>,
    reserved2: zerocopy::U32<LE>,
    first_file_offset: zerocopy::U32<LE>,
    reserved3: zerocopy::U32<LE>,
    minor_version: u8,
    major_version: u8,
    folder_count: zerocopy::U16<LE>,
    file_count: zerocopy::U16<LE>,
    flags: zerocopy::U16<LE>,
    id: zerocopy::U16<LE>,
    set_number: zerocopy::U16<LE>,
    extra_header_size: zerocopy::U16<LE>,
    cb_cf_folder: u8,
    cb_cf_data: u8,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct CabExtraBytes {
    unknown1: zerocopy::U32<LE>,
    data_offset: zerocopy::U32<LE>,
    data_size: zerocopy::U32<LE>,
    unknown2: zerocopy::U32<LE>,
    unknown3: zerocopy::U32<LE>,
}

/// Parse a CAB file header
pub fn parse_cab_header(header_data: &[u8]) -> Result<CabinetHeader, StructureError> {
    // CAB files must be version 1.3
    const MAJOR_VERSION: u8 = 1;
    const MINOR_VERSION: u8 = 3;

    const CAB_STRUCT_SIZE: usize = 40;
    const CAB_EXTRA_STRUCT_SIZE: u16 = 20;
    const FLAG_EXTRA_DATA_PRESENT: u16 = 4;

    let mut header_info = CabinetHeader {
        header_size: CAB_STRUCT_SIZE,
        ..Default::default()
    };

    // Parse the CAB header

    let (cab_header, _) =
        CabHeaderBytes::ref_from_prefix(header_data).map_err(|_| StructureError)?;

    // All reserved fields must be 0
    if cab_header.reserved1 == 0 && cab_header.reserved2 == 0 && cab_header.reserved3 == 0 {
        // Version must be 1.3
        if cab_header.major_version == MAJOR_VERSION && cab_header.minor_version == MINOR_VERSION {
            // Update the CabinetHeader fields
            header_info.total_size = cab_header.size.get() as usize;
            header_info.file_count = cab_header.file_count.get() as usize;
            header_info.folder_count = cab_header.folder_count.get() as usize;

            // If the extra data flag was set, we need to parse the extra data header to get the size of the extra data
            if (cab_header.flags.get() & FLAG_EXTRA_DATA_PRESENT) != 0
                && cab_header.extra_header_size.get() == CAB_EXTRA_STRUCT_SIZE
            {
                // Calclate the start and end of the extra header
                let extra_header_start: usize = CAB_STRUCT_SIZE;
                let extra_header_end: usize = extra_header_start + CAB_EXTRA_STRUCT_SIZE as usize;

                // Get the extra header raw data
                if let Some(extra_header_data) =
                    header_data.get(extra_header_start..extra_header_end)
                {
                    // Parse the extra header

                    let (extra_header, _) = CabExtraBytes::ref_from_prefix(extra_header_data)
                        .map_err(|_| StructureError)?;

                    // The extra data is expected to come immediately after the data specified in the main CAB header
                    if extra_header.data_offset == cab_header.size {
                        // Update the CAB file size to include the extra data
                        header_info.total_size += extra_header.data_size.get() as usize;
                        return Ok(header_info);
                    }
                }
            } else {
                return Ok(header_info);
            }
        }
    }

    Err(StructureError)
}

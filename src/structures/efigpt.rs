use crate::common::{crc32, is_offset_safe};
use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

const BLOCK_SIZE: usize = 512;

/// Struct to store EFI GPT header info
#[derive(Debug, Default, Clone)]
pub struct EFIGPTHeader {
    pub total_size: usize,
}

// https://uefi.org/sites/default/files/resources/UEFI_Spec_2_10_Aug29.pdf, p.116
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct EFIGPTHeaderBytes {
    magic: zerocopy::U64<LE>,
    revision: zerocopy::U32<LE>,
    header_size: zerocopy::U32<LE>,
    header_crc: zerocopy::U32<LE>,
    reserved: zerocopy::U32<LE>,
    my_lba: zerocopy::U64<LE>,
    alternate_lba: zerocopy::U64<LE>,
    first_usable_lba: zerocopy::U64<LE>,
    last_usable_lba: zerocopy::U64<LE>,
    disk_guid_p1: zerocopy::U64<LE>,
    disk_guid_p2: zerocopy::U64<LE>,
    partition_entry_lba: zerocopy::U64<LE>,
    partition_entry_count: zerocopy::U32<LE>,
    partition_entry_size: zerocopy::U32<LE>,
    partition_entries_crc: zerocopy::U32<LE>,
}

/// Parses an EFI GPT header
pub fn parse_efigpt_header(efi_data: &[u8]) -> Result<EFIGPTHeader, StructureError> {
    const EXPTECTED_REVISION: u32 = 0x00010000;

    let mut result = EFIGPTHeader {
        ..Default::default()
    };

    // EFI GPT structure starts at the second block (first block is MBR)
    if let Some(gpt_data) = efi_data.get(BLOCK_SIZE..) {
        // Parse the EFI GPT structure
        let (gpt_header, _) =
            EFIGPTHeaderBytes::ref_from_prefix(gpt_data).map_err(|_| StructureError)?;

        // Make sure the reserved field is NULL
        if gpt_header.reserved == 0 {
            // Make sure the revision field is the expected valid
            if gpt_header.revision == EXPTECTED_REVISION {
                // Calculate the start and end offsets of the partition entries
                let partition_entries_start: usize =
                    lba_to_offset(gpt_header.partition_entry_lba.get() as usize);
                let partition_entries_end: usize = partition_entries_start
                    + (gpt_header.partition_entry_count.get()
                        * gpt_header.partition_entry_size.get()) as usize;

                // Get the partition entires
                if let Some(partition_entries_data) =
                    efi_data.get(partition_entries_start..partition_entries_end)
                {
                    // Validate the partition entries' CRC
                    if gpt_header.partition_entries_crc == crc32(partition_entries_data) {
                        let mut next_partition_offset = 0;
                        let mut previous_partition_offset = None;
                        let available_data = partition_entries_data.len();

                        // Loop through all partition entries
                        while is_offset_safe(
                            available_data,
                            next_partition_offset,
                            previous_partition_offset,
                        ) {
                            if let Some(partition) = parse_gpt_partition_entry(
                                &partition_entries_data[next_partition_offset..],
                            ) {
                                // EOF is the end of the farthest away partition
                                if partition.start_offset < partition.end_offset
                                    && partition.end_offset > result.total_size
                                {
                                    result.total_size = partition.end_offset;
                                }
                            }

                            previous_partition_offset = Some(next_partition_offset);
                            next_partition_offset += gpt_header.partition_entry_size.get() as usize;
                        }

                        if result.total_size > 0 {
                            return Ok(result);
                        }
                    }
                }
            }
        }
    }

    Err(StructureError)
}

#[derive(Debug, Default, Clone)]
struct GPTPartitionEntry {
    pub end_offset: usize,
    pub start_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct GPTEntry {
    type_guid_p1: zerocopy::U64<LE>,
    type_guid_p2: zerocopy::U64<LE>,
    partition_guid_p1: zerocopy::U64<LE>,
    partition_guid_p2: zerocopy::U64<LE>,
    starting_lba: zerocopy::U64<LE>,
    ending_lba: zerocopy::U64<LE>,
    attributes: zerocopy::U64<LE>,
}

/// Parse a GPT partition entry
fn parse_gpt_partition_entry(entry_data: &[u8]) -> Option<GPTPartitionEntry> {
    let mut result = GPTPartitionEntry {
        ..Default::default()
    };

    if let Ok((entry_header, _)) = GPTEntry::ref_from_prefix(entry_data).map_err(|_| StructureError)
    {
        // GUID types of NULL can be ignored
        if entry_header.type_guid_p1 != 0 && entry_header.type_guid_p2 != 0 {
            result.start_offset = lba_to_offset(entry_header.starting_lba.get() as usize);
            result.end_offset = lba_to_offset(entry_header.ending_lba.get() as usize);
            return Some(result);
        }
    }

    None
}

// Convert LBA to offset
fn lba_to_offset(lba: usize) -> usize {
    lba * BLOCK_SIZE
}

use crate::common::{crc32, is_offset_safe};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "EFI Global Partition Table";

/// EFI GPT always contains these bytes
pub fn efigpt_magic() -> Vec<Vec<u8>> {
    vec![b"\x55\xAAEFI PART".to_vec()]
}

/// Validates the EFI GPT header
pub fn efigpt_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Offset of magic bytes from the start of the MBR
    const MAGIC_OFFSET: usize = 0x01FE;

    // Successful return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    if offset >= MAGIC_OFFSET {
        // MBR actually starts this may bytes before the magic bytes
        result.offset = offset - MAGIC_OFFSET;

        // Get the EFI data, including the MBR block
        if let Some(efi_data) = file_data.get(result.offset..) {
            // Parse the EFI data; this also validates CRC so if this succeeds, confidence is high
            if let Ok(efi_header) = parse_efigpt_header(efi_data) {
                // total_size is relative to the rewound image start, so
                // compare against the bytes available from there.
                let available_from_start = efi_data.len();
                // Some EFI images have been observed to define partitions that extend beyond EOF.
                // If that is the case, assume the EFI image extends to EOF.
                if efi_header.total_size > available_from_start {
                    result.size = available_from_start;
                } else {
                    result.size = efi_header.total_size;
                }
                result.description = format!("{}, total size: {}", result.description, result.size);
                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

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
    const EXPECTED_REVISION: u32 = 0x00010000;

    let mut result = EFIGPTHeader::default();

    // EFI GPT structure starts at the second block (first block is MBR)
    if let Some(gpt_data) = efi_data.get(BLOCK_SIZE..) {
        // Parse the EFI GPT structure
        let (gpt_header, _) =
            EFIGPTHeaderBytes::ref_from_prefix(gpt_data).map_err(|_| StructureError)?;

        // Make sure the reserved field is NULL
        if gpt_header.reserved == 0 {
            // Make sure the revision field is the expected valid
            if gpt_header.revision == EXPECTED_REVISION {
                // Validate the GPT header CRC (computed over header_size
                // bytes with the CRC field zeroed). Validate the declared
                // length before allocating; it must cover the fixed header
                // but cannot exceed one LBA.
                let header_len = gpt_header.header_size.get() as usize;
                if header_len < std::mem::size_of::<EFIGPTHeaderBytes>() || header_len > BLOCK_SIZE
                {
                    return Err(StructureError);
                }
                let mut header_for_crc =
                    gpt_data.get(0..header_len).ok_or(StructureError)?.to_vec();
                const CRC_OFFSET: usize = 16;
                const CRC_LEN: usize = 4;
                let crc_end = CRC_OFFSET.checked_add(CRC_LEN).ok_or(StructureError)?;
                if header_for_crc.len() < crc_end {
                    return Err(StructureError);
                }
                header_for_crc[CRC_OFFSET..crc_end].fill(0);
                if crc32(&header_for_crc) != gpt_header.header_crc.get() {
                    return Err(StructureError);
                }
                // Calculate the start and end offsets of the partition entries.
                // LBAs and table sizes that overflow usize cannot address data in
                // the scanned file.
                let Some(partition_entries_start) =
                    lba_to_offset(gpt_header.partition_entry_lba.get() as usize)
                else {
                    return Err(StructureError);
                };
                let partition_entries_len = (gpt_header.partition_entry_count.get() as usize)
                    .checked_mul(gpt_header.partition_entry_size.get() as usize)
                    .ok_or(StructureError)?;
                let Some(partition_entries_end) =
                    partition_entries_start.checked_add(partition_entries_len)
                else {
                    return Err(StructureError);
                };

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
                                let total_size = result.total_size;
                                if (total_size < partition.end_offset)
                                    && (partition.start_offset < partition.end_offset)
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

fn parse_gpt_partition_entry(entry_data: &[u8]) -> Option<GPTPartitionEntry> {
    let (entry_header, _) = GPTEntry::ref_from_prefix(entry_data).ok()?;

    // GUID types of NULL can be ignored
    if entry_header.type_guid_p1 == 0 || entry_header.type_guid_p2 == 0 {
        return None;
    }

    Some(GPTPartitionEntry {
        start_offset: lba_to_offset(entry_header.starting_lba.get() as usize)?,
        end_offset: lba_to_offset(entry_header.ending_lba.get() as usize)?,
    })
}

// Convert LBA to offset; None if the product overflows.
const fn lba_to_offset(lba: usize) -> Option<usize> {
    lba.checked_mul(BLOCK_SIZE)
}

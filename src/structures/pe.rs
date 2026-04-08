use crate::structures::common::StructureError;
use std::collections::HashMap;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Stores info about the PE file
pub struct PEHeader {
    pub machine: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DOSHeaderBytes {
    e_magic: zerocopy::U16<LE>,    // MZ
    e_cblp: zerocopy::U16<LE>,     // Bytes on last page of file
    e_cp: zerocopy::U16<LE>,       // Pages in file
    e_crlc: zerocopy::U16<LE>,     // Relocations
    e_cparhdr: zerocopy::U16<LE>,  // Header size, in paragraphs
    e_minalloc: zerocopy::U16<LE>, // Min extra paragraphs needed
    e_maxalloc: zerocopy::U16<LE>, // Max extra paragraphs needed
    e_ss: zerocopy::U16<LE>,       // Initial relative SS value
    e_sp: zerocopy::U16<LE>,       // Initial SP value
    e_csum: zerocopy::U16<LE>,     // Checksum
    e_ip: zerocopy::U16<LE>,       // Initial IP value
    e_cs: zerocopy::U16<LE>,       // Initial relative CS value
    e_lfarlc: zerocopy::U16<LE>,   // File address of relocation table
    e_ovno: zerocopy::U16<LE>,     // Overlay number
    e_res_1: [u8; 8],
    e_oemid: zerocopy::U16<LE>,   // OEM identifier
    e_oeminfo: zerocopy::U16<LE>, // OEM specific information
    e_res_2: [u8; 20],
    e_lfanew: zerocopy::U32<LE>, // Offset to the PE header
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct PEHeaderBytes {
    magic: zerocopy::U32<LE>,
    machine: zerocopy::U16<LE>,
    number_of_sections: zerocopy::U16<LE>,
    timestamp: zerocopy::U32<LE>,
    symbol_table_ptr: zerocopy::U32<LE>,
    number_of_symbols: zerocopy::U32<LE>,
    optional_header_size: zerocopy::U16<LE>,
    characteristics: zerocopy::U16<LE>,
}

/// Partially parse a PE header
pub fn parse_pe_header(pe_data: &[u8]) -> Result<PEHeader, StructureError> {
    const PE_MAGIC: u32 = 0x00004550;

    let known_machine_types = HashMap::from([
        (0, "Unknown"),
        (0x184, "Alpha32"),
        (0x284, "Alpha64"),
        (0x1D3, "Matsushita AM33"),
        (0x8664, "Intel x86-64"),
        (0x1C0, "ARM"),
        (0xAA64, "ARM-64"),
        (0x1C4, "ARM Thumb2"),
        (0xEBC, "EFI"),
        (0x14C, "Intel x86"),
        (0x200, "Intel Itanium"),
        (0x6232, "LoongArch 32-bit"),
        (0x6264, "LoongArch 64-bit"),
        (0x9041, "Mitsubishi M32R"),
        (0x266, "MIPS16"),
        (0x366, "MIPS with FPU"),
        (0x466, "MIPS16 with FPU"),
        (0x1F0, "PowerPC"),
        (0x1F1, "PowerPC with FPU"),
        (0x5032, "RISC-V 32-bit"),
        (0x5064, "RISC-V 64-bit"),
        (0x5128, "RISC-V 128-bit"),
        (0x1A2, "Hitachi SH3"),
        (0x1A3, "Hitachi SH3 DSP"),
        (0x1A6, "Hitachi SH4"),
        (0x1A8, "Hitachi SH5"),
        (0x1C2, "Thumb"),
        (0x169, "MIPS WCEv2"),
    ]);

    // Size of PE header structure
    let pe_header_size = std::mem::size_of::<PEHeaderBytes>();

    // Parse the DOS header
    let (dos_header, _) = DOSHeaderBytes::ref_from_prefix(pe_data).map_err(|_| StructureError)?;
    // Sanity check the reserved header fields; they should all be 0
    if dos_header
        .e_res_1
        .iter()
        .chain(&dos_header.e_res_2)
        .all(|&b| b == 0)
    {
        // Start and end offsets of the PE header
        let pe_header_start: usize = dos_header.e_lfanew.get() as usize;
        let pe_header_end: usize = pe_header_start + pe_header_size;

        // Sanity check the PE header offsets
        if let Some(pe_header_data) = pe_data.get(pe_header_start..pe_header_end) {
            // Parse the PE header
            let (pe_header, _) =
                PEHeaderBytes::ref_from_prefix(pe_header_data).map_err(|_| StructureError)?;

            // Check the PE magic bytes
            if pe_header.magic == PE_MAGIC {
                // Check the reported machine type
                if let Some(machine) = known_machine_types.get(&pe_header.machine.get()) {
                    return Ok(PEHeader {
                        machine: machine.to_string(),
                    });
                }
            }
        }
    }

    Err(StructureError)
}

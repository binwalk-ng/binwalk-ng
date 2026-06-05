use crate::common::{get_cstring, is_offset_safe};
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_LOW, SignatureError, SignatureResult};
use crate::structures::{Endianness, StructureError, dyn_endian};
use log::error;
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable descriptions
pub const SYMTAB_DESCRIPTION: &str = "VxWorks symbol table";
pub const WIND_KERNEL_DESCRIPTION: &str = "VxWorks WIND kernel version";

/// WIND kernel version magic
pub fn wind_kernel_magic() -> Vec<Vec<u8>> {
    // Magic version string for WIND kernels
    vec![b"WIND version ".to_vec()]
}

/// VxWorks symbol table magic bytes
pub fn symbol_table_magic() -> Vec<Vec<u8>> {
    // These magic bytes match the type and group fields in the VxWorks symbol table, for both big and little endian targets
    vec![
        b"\x00\x00\x05\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x00\x07\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x00\x09\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x05\x00\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x07\x00\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x09\x00\x00\x00\x00\x00\x00".to_vec(),
    ]
}

/// Validates WIND kernel version signatures
pub fn wind_kernel_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Length of the magic signatures bytes
    const MAGIC_SIZE: usize = 13;

    let mut result = SignatureResult {
        offset,
        description: WIND_KERNEL_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    // Want the string that proceeds the magic bytes
    let version_offset: usize = offset + MAGIC_SIZE;

    if let Some(version_bytes) = file_data.get(version_offset..) {
        // The wind kernel magic bytes should be followed by a string containing the wind kernel version
        let version_string = get_cstring(version_bytes);

        // Make sure we got a string
        if !version_string.is_empty() {
            result.size = MAGIC_SIZE + version_string.len();
            result.description = format!("{} {}", result.description, version_string);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validates VxWorks symbol table signatures
pub fn symbol_table_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // The magic bytes start at this offset from the beginning of the symbol table
    const MAGIC_OFFSET: usize = 8;

    let mut result = SignatureResult {
        description: SYMTAB_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // The magic bytes are not at the beginning of the VxWorks symbol table; sanity check the specified offset
    if offset >= MAGIC_OFFSET {
        // Actual start of the symbol table
        let symtab_start: usize = offset - MAGIC_OFFSET;

        // Do a dry-run extraction of the symbol table
        let dry_run = extract_symbol_table(file_data, symtab_start, None);

        // If dry run was a success, this is very likely a valid symbol table
        if dry_run.success {
            // Get the size of the symbol table from the dry-run
            if let Some(symtab_size) = dry_run.size {
                result.size = symtab_size;
                result.offset = symtab_start;
                result.description =
                    format!("{}, total size: {} bytes", result.description, result.size);

                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Stores info about a single VxWorks symbol table entry
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VxWorksSymbolTableEntry {
    pub size: usize,
    pub name: u32,
    pub value: u32,
    pub symtype: String,
}

// This *seems* to be the correct structure for a symbol table entry, it may be different for different VxWorks versions...
#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct SymbolEntryBytes {
    name_ptr: dyn_endian::U32,
    value_ptr: dyn_endian::U32,
    symbol_type: dyn_endian::U32,
    group: dyn_endian::U32,
}

/// Parse a single VxWorks symbol table entry
pub fn parse_symtab_entry(
    symbol_data: &[u8],
    endianness: Endianness,
) -> Result<VxWorksSymbolTableEntry, StructureError> {
    let symtab_structure_size = std::mem::size_of::<SymbolEntryBytes>();

    // Parse the symbol table entry
    let (symbol_entry, _) =
        SymbolEntryBytes::ref_from_prefix(symbol_data).map_err(|_| StructureError)?;

    // Sanity check expected values in the symbol table entry
    let name_ptr = symbol_entry.name_ptr.get(endianness);
    let value_ptr = symbol_entry.value_ptr.get(endianness);
    if name_ptr != 0 && value_ptr != 0 {
        // There may be more types; these are the only ones I've found in the wild
        let symbol_type = match symbol_entry.symbol_type.get(endianness) {
            0x500 => "function",
            0x700 => "initialized data",
            0x900 => "uninitialized data",
            _ => return Err(StructureError),
        };

        return Ok(VxWorksSymbolTableEntry {
            size: symtab_structure_size,
            name: name_ptr,
            value: value_ptr,
            symtype: symbol_type.to_string(),
        });
    }

    Err(StructureError)
}

/// Detect a symbol table entry's endianness
pub fn get_symtab_endianness(symbol_data: &[u8]) -> Result<Endianness, StructureError> {
    const TYPE_FIELD_OFFSET: usize = 9;

    // The type field starts at offset 8 and is 0x00_00_05_00, so for big endian targets the 9th byte will be NULL
    if let Some(offset_field) = symbol_data.get(TYPE_FIELD_OFFSET) {
        if *offset_field == 0 {
            return Ok(Endianness::Big);
        }

        return Ok(Endianness::Little);
    }

    Err(StructureError)
}

/// Describes the VxWorks symbol table extractor
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::vxworks::vxworks_symtab_extractor;
///
/// match vxworks_symtab_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn vxworks_symtab_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(extract_symbol_table),
        ..Default::default()
    }
}

/// Internal extractor for writing VxWorks symbol tables to JSON
pub fn extract_symbol_table(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const MIN_VALID_ENTRIES: usize = 250;
    const OUTFILE_NAME: &str = "symtab.json";

    let mut result = ExtractionResult::default();

    let available_data = file_data.len();
    let mut previous_entry_offset = None;
    let mut symtab_entry_offset: usize = offset;
    let mut symtab_entries: Vec<VxWorksSymbolTableEntry> = vec![];

    // Determine the symbol table endianness first
    if let Ok(endianness) = get_symtab_endianness(&file_data[symtab_entry_offset..]) {
        // Loop through all the symbol table entries, until we run out of data or hit an invalid entry
        while is_offset_safe(available_data, symtab_entry_offset, previous_entry_offset) {
            // Parse the symbol table entry
            match parse_symtab_entry(&file_data[symtab_entry_offset..], endianness) {
                // Break on an invalid entry
                Err(_) => {
                    break;
                }

                // Increment symtab_entry_offset to the offset of the next entry and keep a list of all processed entries
                Ok(entry) => {
                    previous_entry_offset = Some(symtab_entry_offset);
                    symtab_entry_offset += entry.size;
                    symtab_entries.push(entry);
                }
            }
        }
    }

    // Sanity check the number of symbols in the symbol table; there are usualy MANY
    if symtab_entries.len() >= MIN_VALID_ENTRIES {
        result.success = true;
        result.size = Some(symtab_entry_offset - offset);

        // This is not a drill!
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);

            // Convert symbol table entires to JSON
            match serde_json::to_string_pretty(&symtab_entries) {
                // This should never happen...
                Err(e) => {
                    error!("Failed to convert VxWorks symbol table to JSON: {e}");
                }

                // Write JSON to file
                Ok(symtab_json) => {
                    result.success = chroot.create_file(OUTFILE_NAME, &symtab_json.into_bytes());
                }
            }
        }
    }

    result
}

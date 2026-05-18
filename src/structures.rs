//! # Data Structure Parsing
//!
//! Both signatures and internal extractors may need to parse data structures used by various file formats.
//! Structure parsing code is placed in the `structures` module.
//!
//! ## Helper Functions
//!
//! There are some definitions and helper functions in `structures::common` that are generally helpful for processing data structures.
//!
//! The `structures::parse` function provides a way to parse basic data structures by defining the data structure format,
//! the endianness to use, and the data to cast the structure over. It is heavily used by most structure parsers.
//! It supports the following data types:
//!
//! - u8
//! - u16
//! - u24
//! - u32
//! - u64
//!
//! Regardless of the data type specified, all values are returned as `usize` types.
//! If an error occurs (typically due to not enough data available to process the specified data structure), `Err(structures::StructureError)` is returned.
//!
//! The `structures::size` function is a convenience function that returns the number of bytes required to parse a defined data structure.
//!
//! The `structures::StructureError` struct is typically used by structure parsers to return an error.
//!
//! ## Writing a Structure Parser
//!
//! Structure parsers may be defined however they need to be; there are no strict rules here.
//! Generally, however, they should:
//!
//! - Accept some data to parse
//! - Parse the data structure
//! - Validate the structure fields for correctness
//! - Return an error or success status
//!
//! ### Example
//!
//! To write a structure parser for a simple, fictional, `FooBar` file header:
//!
//! ```no_run
//! use binwalk_ng::common::{crc32, get_cstring};
//! use binwalk_ng::structures::{self, StructureError};
//!
//! #[derive(Debug, Default, Clone)]
//! pub struct FooBarHeader {
//!     pub data_crc: usize,
//!     pub data_size: usize,
//!     pub header_size: usize,
//!     pub original_file_name: String,
//! }
//!
//! /// This function parses and validates the FooBar file header.
//! /// It returns a FooBarHeader struct on success, StructureError on failure.
//! fn parse_foobar_header(foobar_data: &[u8]) -> Result<FooBarHeader, StructureError> {
//!     // The header CRC is calculated over the first 13 bytes of the header (everything except the header_crc field)
//!     const HEADER_CRC_LEN: usize = 13;
//!
//!     // Define a data structure; structure members must be in the order in which they appear in the data
//!     let foobar_struct = vec![
//!         ("magic", "u32"),
//!         ("flags", "u8"),
//!         ("data_size", "u32"),
//!         ("data_crc", "u32"),
//!         ("header_crc", "u32"),
//!         // NULL-terminated original file name immediately follows the header structure
//!     ];
//!
//!     let struct_size: usize = structures::size(&foobar_struct);
//!
//!     // Parse the provided data in accordance with the layout defined in foobar_struct, interpret fields as little endian
//!     if let Ok(foobar_header) = structures::parse(foobar_data, &foobar_struct, "little") {
//!         
//!         if let Some(crc_data) = foobar_data.get(0..HEADER_CRC_LEN) {
//!             // Validate the header CRC
//!             if foobar_header["header_crc"] == (crc32(crc_data) as usize) {
//!                 // Get the NULL-terminated file name that immediately follows the header structure
//!                 if let Some(file_name_bytes) = foobar_data.get(struct_size..) {
//!                     let file_name = get_cstring(file_name_bytes);
//!
//!                     // The file name should be non-zero in length
//!                     if file_name.len() > 0 {
//!                         return Ok(FooBarHeader{
//!                             data_crc: foobar_header["data_crc"],
//!                             data_size: foobar_header["data_size"],
//!                             header_size: struct_size + file_name.len() + 1,  // Total header size is structure size + name length + NULL byte
//!                             original_file_name: file_name.clone(),
//!                         });
//!                     }
//!                 }
//!             }
//!         }
//!     }
//!
//!     return Err(StructureError);
//! }
//! ```

use log::error;
use std::collections::HashMap;

/*
 * Note that all values returned by the parse() function are of type usize; this is a concious decision.
 * Returning usize types makes the calling code much cleaner, but that means that u64 fields won't fit into the return value on 32-bit systems.
 * Thus, only 64-bit systems are supported. This requirement is enforced here.
 */
#[cfg(not(target_pointer_width = "64"))]
compile_error!("compilation is only allowed for 64-bit targets");

/// Error return value of structure parsers
#[derive(Debug, Clone)]
pub struct StructureError;

/// Function to parse basic C-style data structures.
///
/// ## Supported Data Types
///
/// The following data types are supported:
/// - u8
/// - u16
/// - u24
/// - u32
/// - u64
///
/// ## Arguments
///
/// - `data`: The raw data to apply the structure over
/// - `structure`: A vector of tuples describing the data structure
/// - `endianness`: One of: "big", "little"
///
/// ## Example:
///
/// ```
/// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_structures_common_rs_34_0() -> Result<bool, binwalk_ng::structures::StructureError> {
/// use binwalk_ng::structures;
///
/// let my_structure = vec![
///     ("magic", "u32"),
///     ("size", "u64"),
///     ("flags", "u8"),
///     ("packed_bytes", "u24"),
///     ("checksum", "u16"),
/// ];
///
/// let some_data = b"AAAA\x01\x00\x00\x00\x00\x00\x00\x00\x08\x0A\x0B\x0C\x01\x02";
/// let header = structures::parse(some_data, &my_structure, "little")?;
///
/// assert_eq!(header["magic"], 0x41414141);
/// assert_eq!(header["checksum"], 0x0201);
/// # Ok(true)
/// # } _doctest_main_src_structures_common_rs_34_0(); }
/// ```
pub fn parse(
    data: &[u8],
    structure: &[(&str, &str)],
    endianness: &str,
) -> Result<HashMap<String, usize>, StructureError> {
    const U8_SIZE: usize = std::mem::size_of::<u8>();
    const U16_SIZE: usize = std::mem::size_of::<u16>();
    const U32_SIZE: usize = std::mem::size_of::<u32>();
    const U64_SIZE: usize = std::mem::size_of::<u64>();
    const U24_SIZE: usize = 3;

    let mut parsed_structure = HashMap::with_capacity(structure.len());

    let mut remaining_data = data;
    for &(name, ctype) in structure {
        let csize = type_to_size(ctype).ok_or(StructureError)?;
        let raw_bytes = remaining_data.split_off(..csize).ok_or(StructureError)?;
        let value = match csize {
            // u8, endianness doesn't matter
            U8_SIZE => usize::from(raw_bytes[0]),
            U16_SIZE => {
                let f = if endianness == "big" {
                    u16::from_be_bytes
                } else {
                    u16::from_le_bytes
                };
                usize::from(f(raw_bytes.try_into().unwrap()))
            }
            U32_SIZE => {
                let f = if endianness == "big" {
                    u32::from_be_bytes
                } else {
                    u32::from_le_bytes
                };
                f(raw_bytes.try_into().unwrap()) as usize
            }
            U64_SIZE => {
                let f = if endianness == "big" {
                    u64::from_be_bytes
                } else {
                    u64::from_le_bytes
                };
                f(raw_bytes.try_into().unwrap()) as usize
            }
            // Yes Virginia, u24's are real
            U24_SIZE => {
                if endianness == "big" {
                    usize::from(raw_bytes[0]) << 16
                        | usize::from(raw_bytes[1]) << 8
                        | usize::from(raw_bytes[2])
                } else {
                    usize::from(raw_bytes[2]) << 16
                        | usize::from(raw_bytes[1]) << 8
                        | usize::from(raw_bytes[0])
                }
            }
            _ => {
                error!("Cannot parse structure element with unknown data type '{ctype}'");
                return Err(StructureError);
            }
        };

        parsed_structure.insert(name.to_string(), value);
    }

    Ok(parsed_structure)
}

/// Returns the size of a given structure definition.
///
/// ## Example:
///
/// ```
/// use binwalk_ng::structures;
///
/// let my_structure = vec![
///     ("magic", "u32"),
///     ("size", "u64"),
///     ("flags", "u8"),
///     ("checksum", "u32"),
/// ];
///
/// let struct_size = structures::size(&my_structure);
///
/// assert_eq!(struct_size, 17);
/// ```
pub fn size(structure: &[(&str, &str)]) -> usize {
    structure
        .iter()
        .filter_map(|(_, ctype)| type_to_size(ctype))
        .sum()
}

fn type_to_size(ctype: &str) -> Option<usize> {
    match ctype {
        "u8" => Some(1),
        "u16" => Some(2),
        "u24" => Some(3),
        "u32" => Some(4),
        "u64" => Some(8),
        _ => {
            error!("Unknown size for structure type '{ctype}'!");
            None
        }
    }
}

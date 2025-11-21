use core::fmt;
use log::error;
use std::collections::HashMap;
use std::marker::PhantomData;
use zerocopy::byteorder::{BE, LE};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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

/// Generic 24-bit unsigned integer (3 bytes) with configurable endianness
///
/// Use `U24<LE>` for little-endian or `U24<BE>` for big-endian.
#[derive(FromBytes, KnownLayout, Unaligned, Immutable, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct U24<O>([u8; 3], PhantomData<O>);

impl U24<LE> {
    /// Create a new U24 from a u32 value, returning None if the value is too large for a u24
    pub const fn new(val: u32) -> Option<Self> {
        // little endian, the last byte is the most significant and should be zero for a u24
        let [b1, b2, b3, 0] = val.to_le_bytes() else {
            return None;
        };
        Some(Self([b1, b2, b3], PhantomData))
    }

    /// Get the value as a u32 (little-endian)
    pub const fn get(self) -> u32 {
        // little endian, the last byte is the most significant and should be zero for a u24
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], 0])
    }
}

impl U24<BE> {
    /// Create a new U24 from a u32 value, returning None if the value is too large for a u24
    pub const fn new(val: u32) -> Option<Self> {
        // big endian, the first byte is the most significant and should be zero for a u24
        let [0, b1, b2, b3] = val.to_le_bytes() else {
            return None;
        };
        Some(Self([b1, b2, b3], PhantomData))
    }

    /// Get the value as a u32 (big-endian)
    pub const fn get(self) -> u32 {
        // big endian, the first byte is the most significant and should be zero for a u24
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }
}

impl fmt::Debug for U24<LE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.get(), f)
    }
}

impl fmt::Debug for U24<BE> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.get(), f)
    }
}

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
/// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_structures_common_rs_34_0() -> Result<bool, binwalk_ng::structures::common::StructureError> {
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
/// let header = structures::common::parse(some_data, &my_structure, "little")?;
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
/// let struct_size = structures::common::size(&my_structure);
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

pub mod dyn_endian;

use std::fmt;

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl fmt::Display for Endianness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(f, "Little Endian"),
            Self::Big => write!(f, "Big Endian"),
        }
    }
}

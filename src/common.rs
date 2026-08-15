//! Common Functions

use crate::binwalk_ng::MmapUsage;
use log::{debug, error};
use memmap2::Mmap;
use std::io::Read;
use std::path::Path;

/// Read a file data into memory and return its contents.
///
/// ## Example
///
/// ```
/// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_common_rs_48_0() -> Result<(), Box<dyn std::error::Error>> {
/// use binwalk_ng::common::read_file;
///
/// let file_data = read_file("/etc/passwd")?;
/// assert!(file_data.len() > 0);
/// # Ok(())
/// # } _doctest_main_src_common_rs_48_0(); }
/// ```
pub fn read_file(file: impl AsRef<Path>) -> Result<Vec<u8>, std::io::Error> {
    let file_path = file.as_ref();

    let file_data = std::fs::read(file_path).inspect_err(|e| {
        error!(
            "Failed to read file {} into memory: {e}",
            file_path.display()
        )
    })?;

    let file_size = file_data.len();
    debug!("Loaded {file_size} bytes from {}", file_path.display());
    Ok(file_data)
}

pub fn read_or_map_file(file: &Path, mmap_usage: MmapUsage) -> std::io::Result<impl AsRef<[u8]>> {
    let mut f = std::fs::File::open(file)?;
    if mmap_usage != MmapUsage::Never
        && let Ok(map) = unsafe { Mmap::map(&f) }
    {
        Ok(VecOrMmap::Mmap(map))
    } else {
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        Ok(VecOrMmap::Vec(v))
    }
}

enum VecOrMmap {
    Vec(Vec<u8>),
    Mmap(Mmap),
}

impl AsRef<[u8]> for VecOrMmap {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Vec(v) => v,
            Self::Mmap(map) => map,
        }
    }
}

/// Calculates the CRC32 checksum of the given data.
///
/// ## Notes
///
/// Uses initial CRC value of 0.
///
/// ## Example
///
/// ```
/// use binwalk_ng::common::crc32;
///
/// let my_data: &[u8] = b"ABCD";
///
/// let my_data_crc = crc32(my_data);
///
/// assert_eq!(my_data_crc, 0xDB1720A5);
/// ```
pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Converts an epoch time to a formatted time string.
///
/// ## Example
///
/// ```
/// use binwalk_ng::common::epoch_to_string;
///
/// let timestamp = epoch_to_string(0);
///
/// assert_eq!(timestamp, "1970-01-01 00:00:00");
/// ```
pub fn epoch_to_string(epoch_timestamp: impl Into<i64>) -> String {
    jiff::Timestamp::new(epoch_timestamp.into(), 0).map_or_else(
        |_| "".to_string(),
        |timestamp| timestamp.strftime("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

/// Get a C-style NULL-terminated string from the provided array of u8 bytes.
///
/// ## Example
///
/// ```
/// use binwalk_ng::common::get_cstring;
///
/// let raw_data: &[u8] = b"this_is_a_c_string\x00";
///
/// let string = get_cstring(raw_data);
///
/// assert_eq!(string, "this_is_a_c_string");
/// ```
pub fn get_cstring(raw_data: &[u8]) -> String {
    let first_zero = raw_data
        .iter()
        .position(|&r| r == 0)
        .unwrap_or(raw_data.len());
    let raw_bytes = &raw_data[..first_zero];
    String::from_utf8_lossy(raw_bytes).into_owned()
}

/// Returns true if the provided byte is a printable ASCII character
///
/// ## Example
///
/// ```
/// use binwalk_ng::common::is_printable_ascii;
///
/// assert!(is_printable_ascii(0x41));
/// assert!(!is_printable_ascii(0xFE));
/// ```
pub fn is_printable_ascii(b: u8) -> bool {
    const ASCII_MIN: u8 = 0x0A;
    const ASCII_MAX: u8 = 0x7E;

    (ASCII_MIN..=ASCII_MAX).contains(&b)
}

/// Validates data offsets to prevent out-of-bounds access and infinite loops while parsing file formats.
///
/// ## Notes
///
/// - `next_offset` must be within the bounds of `available_data`
/// - `previous_offset` must be less than `next_offset`, or `None`
///
/// ## Example
///
/// ```
/// use binwalk_ng::common::is_offset_safe;
///
/// let my_data: &[u8] = b"ABCD";
/// let available_data = my_data.len();
///
/// assert!(is_offset_safe(available_data, 0, None));
/// assert!(!is_offset_safe(available_data, 4, None));
/// assert!(is_offset_safe(available_data, 2, Some(1)));
/// assert!(!is_offset_safe(available_data, 2, Some(2)));
/// assert!(!is_offset_safe(available_data, 1, Some(2)));
/// ```
pub fn is_offset_safe(
    available_data: usize,
    next_offset: usize,
    last_offset: Option<usize>,
) -> bool {
    // If a previous file offset was specified, ensure that it is less than the next file offset
    if last_offset.is_some_and(|b| b >= next_offset) {
        return false;
    }

    // Ensure that the next file offset is within the bounds of available file data
    if next_offset >= available_data {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn epoch_to_string_zero_epoch() {
        assert_eq!(epoch_to_string(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn epoch_to_string_positive_epoch() {
        assert_eq!(epoch_to_string(86400), "1970-01-02 00:00:00");
    }

    #[test]
    fn epoch_to_string_negative_epoch() {
        assert_eq!(epoch_to_string(-1), "1969-12-31 23:59:59");
    }

    #[test]
    fn epoch_to_string_out_of_range_returns_empty_string() {
        assert_eq!(epoch_to_string(i64::MAX), "");
        assert_eq!(epoch_to_string(i64::MIN), "");
    }

    #[test]
    fn epoch_to_string_accepts_signed_and_unsigned_types() {
        assert_eq!(epoch_to_string(0u32), "1970-01-01 00:00:00");
    }

    #[test]
    fn is_offset_safe_zero_length_data() {
        assert!(!is_offset_safe(0, 0, None));
        assert!(!is_offset_safe(0, 1, None));
    }

    #[test]
    fn is_offset_safe_next_offset_at_eof_is_unsafe() {
        assert!(!is_offset_safe(4, 4, None));
        assert!(!is_offset_safe(4, 5, None));
    }

    #[test]
    fn is_offset_safe_valid_next_offset_without_previous() {
        assert!(is_offset_safe(4, 0, None));
        assert!(is_offset_safe(4, 3, None));
    }

    #[test]
    fn is_offset_safe_previous_offset_must_be_less_than_next() {
        assert!(is_offset_safe(4, 2, Some(1)));
        assert!(!is_offset_safe(4, 2, Some(2)));
        assert!(!is_offset_safe(4, 1, Some(2)));
        assert!(!is_offset_safe(4, 2, Some(3)));
    }

    #[test]
    fn read_or_map_file_returns_file_contents() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"test data").unwrap();

        let mapped = read_or_map_file(tmp.path(), true).unwrap();
        let read = read_or_map_file(tmp.path(), false).unwrap();

        assert_eq!(mapped.as_ref(), b"test data");
        assert_eq!(read.as_ref(), b"test data");
    }

    #[test]
    fn read_or_map_file_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();

        let mapped = read_or_map_file(tmp.path(), true).unwrap();
        let read = read_or_map_file(tmp.path(), false).unwrap();

        assert_eq!(mapped.as_ref(), b"");
        assert_eq!(read.as_ref(), b"");
    }

    #[test]
    fn read_or_map_file_missing_file_returns_error() {
        assert!(read_or_map_file(Path::new("/nonexistent/file"), true).is_err());
        assert!(read_or_map_file(Path::new("/nonexistent/file"), false).is_err());
    }
}

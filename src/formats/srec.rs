use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use std::io;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

/// Human readable descriptions
pub const SREC_DESCRIPTION: &str = "Motorola S-record";
pub const SREC_SHORT_DESCRIPTION: &str = "Motorola S-record (generic)";

/// Generic, short signature for s-records, should only be matched at the beginning of a file
pub fn srec_short_magic() -> Vec<Vec<u8>> {
    vec![b"S0".to_vec()]
}

/// This assumes a srec header with the hex encoded string of "HDR"
pub fn srec_magic() -> Vec<Vec<u8>> {
    vec![b"S00600004844521B".to_vec()]
}

/// Validates a SREC signature
pub fn srec_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let file_data = &file_data[offset..];
    let mut remaining = file_data;

    let mut os_type = None;
    let mut saw_data = false;
    while let Ok((record, rest)) = take_srec_record(remaining) {
        if !record.checksum_valid() {
            break;
        }
        remaining = rest;

        if !saw_data && record.ty.is_data() {
            saw_data = true;
        }

        // Require a terminal record at the end
        if record.ty.is_terminal() {
            os_type = Some(match record.line_end {
                LineEnd::Lf => "Unix",
                LineEnd::CrLf => "Windows",
            });
            break;
        }
    }

    let os_type: &str = os_type.ok_or(SignatureError)?;
    if !saw_data {
        return Err(SignatureError);
    }

    let size = file_data.len() - remaining.len();
    let result = SignatureResult {
        offset,
        description: format!("{SREC_DESCRIPTION}, origin OS: {os_type}, total size: {size} bytes"),
        confidence: CONFIDENCE_HIGH,
        size,
        ..Default::default()
    };

    Ok(result)
}

/// Describes the internal extractor used to convert Motorola S-records to binary
///
/// ```
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::srec::srec_extractor;
///
/// match srec_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => panic!("Unexpected external extractor '{}'", cmd),
/// }
/// ```
pub fn srec_extractor() -> extractors::Extractor {
    extractors::Extractor {
        utility: extractors::ExtractorType::Internal(extract_srec),
        ..Default::default()
    }
}

/// Internal extractor for Motorola S-records. Decodes the data records into a binary blob.
pub fn extract_srec(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "s-record.bin";

    let mut result = ExtractionResult::default();

    let Some(srec_data) = file_data.get(offset..) else {
        return result;
    };
    let mut file = None;
    if let Some(output_directory) = output_directory {
        let chroot = Chroot::new(output_directory);
        file = chroot.create_file_writer(OUTPUT_FILE_NAME);
        if file.is_none() {
            return result;
        }
    }
    let mut remaining = srec_data;
    while let Ok((record, rest)) = take_srec_record(remaining) {
        if !record.hex_data.is_empty()
            && record.ty.is_data()
            && let Some(f) = &mut file
        {
            let res = record.write(f);
            if res.is_err() {
                return result;
            }
        }
        remaining = rest;

        if record.ty.is_terminal() {
            break;
        }
    }
    let consumed = srec_data.len() - remaining.len();
    result.size = Some(consumed);
    result.success = consumed > 0;

    result
}

fn take_srec_record(record_bytes: &[u8]) -> Result<(Record<'_>, &[u8]), SignatureError> {
    let (header, rest) =
        RecordHeaderBytes::try_ref_from_prefix(record_bytes).map_err(|_| SignatureError)?;
    let addr_size = header.ty.addr_size();
    let len = header.byte_count.get().ok_or(SignatureError)?;
    // Requires at least the address and a checksum byte in the len,
    // and we need at least that many hex bytes and a newline remaining
    if usize::from(len) < addr_size + 1 || rest.len() < usize::from(len) * 2 + 1 {
        return Err(SignatureError);
    }

    let mut computed_sum = len;

    let (addr, rest) =
        <[HexByte]>::try_ref_from_prefix_with_elems(rest, addr_size).map_err(|_| SignatureError)?;
    let addr = read_addr(addr, &mut computed_sum).ok_or(SignatureError)?;

    let data_len = usize::from(len)
        .checked_sub(addr_size + 1)
        .ok_or(SignatureError)?;
    let (hex_data, rest) =
        <[HexByte]>::try_ref_from_prefix_with_elems(rest, data_len).map_err(|_| SignatureError)?;

    let (checksum, rest) = HexByte::try_read_from_prefix(rest).map_err(|_| SignatureError)?;
    computed_sum = computed_sum.wrapping_add(checksum.get().ok_or(SignatureError)?);

    let (line_end, mut rest) = take_newline(rest).ok_or(SignatureError)?;
    while let Some((_, r)) = take_newline(rest) {
        rest = r;
    }

    Ok((
        Record {
            ty: header.ty,
            sum_without_data: computed_sum,
            addr,
            hex_data,
            line_end,
        },
        rest,
    ))
}

struct Record<'a> {
    ty: RecordType,
    /// sum of checksummed bytes, except for the data in hex_bytes
    sum_without_data: u8,
    addr: u32,
    hex_data: &'a [HexByte],
    line_end: LineEnd,
}

impl Record<'_> {
    fn checksum_valid(&self) -> bool {
        let mut checksum = self.sum_without_data;
        for hex_byte in self.hex_data {
            let Some(byte) = hex_byte.get() else {
                return false;
            };
            checksum = checksum.wrapping_add(byte);
        }
        checksum == 0xFF
    }

    fn write<F>(&self, f: &mut F) -> io::Result<()>
    where
        F: Write + Seek,
    {
        f.seek(SeekFrom::Start(u64::from(self.addr)))?;
        let decoded = hex::decode(self.hex_data.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        f.write_all(&decoded)
    }
}

#[derive(Debug, Copy, Clone)]
enum LineEnd {
    Lf,
    CrLf,
}

#[derive(Debug, Copy, Clone, TryFromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct RecordHeaderBytes {
    _s: S,
    ty: RecordType,
    byte_count: HexByte,
}

#[derive(Debug, Copy, Clone, FromBytes, KnownLayout, Immutable, IntoBytes)]
#[repr(transparent)]
struct HexByte([u8; 2]);

impl HexByte {
    #[inline]
    fn get(self) -> Option<u8> {
        let [hi, lo] = self.0;
        Some((decode_hex_digit(hi)? << 4) | decode_hex_digit(lo)?)
    }
}

#[derive(Debug, Copy, Clone, TryFromBytes, Immutable)]
#[repr(u8)]
enum S {
    _S = b'S',
}

#[allow(dead_code)] // Constructed only through zerocopy
#[derive(Debug, Copy, Clone, TryFromBytes, Immutable)]
#[repr(u8)]
enum RecordType {
    Header = b'0',
    DataAt16 = b'1',
    DataAt24 = b'2',
    DataAt32 = b'3',
    // note, '4' intentionally omitted
    RecordCount16 = b'5',
    RecordCount24 = b'6',
    TerminateAt32 = b'7',
    TerminateAt24 = b'8',
    TerminateAt16 = b'9',
}

impl RecordType {
    const fn addr_size(self) -> usize {
        match self {
            Self::Header | Self::DataAt16 | Self::RecordCount16 | Self::TerminateAt16 => 2,
            Self::DataAt24 | Self::RecordCount24 | Self::TerminateAt24 => 3,
            Self::DataAt32 | Self::TerminateAt32 => 4,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::TerminateAt16 | Self::TerminateAt24 | Self::TerminateAt32
        )
    }

    const fn is_data(self) -> bool {
        matches!(self, Self::DataAt16 | Self::DataAt24 | Self::DataAt32)
    }
}

#[inline]
const fn decode_hex_digit(digit: u8) -> Option<u8> {
    Some(match digit {
        b'0'..=b'9' => digit - b'0',
        b'A'..=b'F' => digit - b'A' + 10,
        b'a'..=b'f' => digit - b'a' + 10,
        _ => return None,
    })
}

#[inline]
fn read_addr(addr_digits: &[HexByte], checksum: &mut u8) -> Option<u32> {
    assert!(addr_digits.len() <= 4);
    let mut res = 0;

    for digit in addr_digits {
        res <<= 8;
        let byte = digit.get()?;
        *checksum = checksum.wrapping_add(byte);
        res |= u32::from(byte);
    }

    Some(res)
}

#[inline]
fn take_newline(rest: &[u8]) -> Option<(LineEnd, &[u8])> {
    match rest {
        [b'\n', rest @ ..] => Some((LineEnd::Lf, rest)),
        [b'\r', b'\n', rest @ ..] => Some((LineEnd::CrLf, rest)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::assert_snapshot;

    fn decode_srec(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let dir = tempfile::tempdir().unwrap();
        let res = extract_srec(data, 0, Some(dir.path()));
        if !res.success {
            return Err("failed to extract");
        }
        assert_eq!(res.size, Some(data.len()));
        Ok(std::fs::read(dir.path().join("s-record.bin")).unwrap())
    }

    #[test]
    fn decode_srec_with_address_gap() {
        // Records at 0x0000 and 0x0008 with a 4-byte gap.
        // Records are placed at their target addresses with 0x00 padding in gaps.
        let srec = b"S107000000010203F2\n\
                      S107000804050607DA\n\
                      S9030000FC\n";
        let decoded = decode_srec(srec).unwrap();
        assert_snapshot!(hex::encode(&decoded), @"000102030000000004050607");
    }

    #[test]
    fn decode_srec_nonzero_base_with_gap() {
        // Non-zero base address and a gap between records.
        let srec = b"S107001000010203E2\n\
                      S107001C04050607C6\n\
                      S9030000FC\n";
        let decoded = decode_srec(srec).unwrap();
        assert_snapshot!(
            hex::encode(&decoded),
            @"0000000000000000000000000000000000010203000000000000000004050607"
        );
    }

    #[test]
    fn decode_srec_invalid_checksum() {
        // Correct checksum is 0xF2; 0xF3 is wrong.
        let srec = b"S107000000010203F3\n\
                      S9030000FC\n";
        assert!(srec_parser(srec, 0).is_err());
    }

    #[test]
    fn decode_srec_truncated_record() {
        // Too short to parse (fewer than 6 hex chars for type+count+address+checksum).
        let srec = b"S1\n\
                      S9030000FC\n";
        assert!(srec_parser(srec, 0).is_err());
    }

    #[test]
    fn decode_srec_unsupported_type() {
        // S4 is undefined in the standard and should be rejected.
        let srec = b"S407000000010203F2\n\
                      S9030000FC\n";
        assert!(srec_parser(srec, 0).is_err());
    }

    #[test]
    fn decode_srec_no_terminator() {
        // Missing S7/S8/S9 termination record.
        let srec = b"S107000000010203F2\n\
                      S107000804050607DA\n";
        assert!(srec_parser(srec, 0).is_err());
    }
}

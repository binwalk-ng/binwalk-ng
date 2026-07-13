use crate::common::is_offset_safe;
use crate::extractors::{self, Chroot, ExtractionResult};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use aho_corasick::AhoCorasick;
use std::path::Path;

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
    // \r and \n
    const UNIX_TERMINATING_CHARACTER: u8 = 0x0A;
    const WINDOWS_TERMINATING_CHARACTER: u8 = 0x0D;

    let mut result = SignatureResult {
        offset,
        description: SREC_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.len();

    // Srec lines, and hence the last line of an s-record, should end with a new line or line feed
    let terminating_characters = [WINDOWS_TERMINATING_CHARACTER, UNIX_TERMINATING_CHARACTER];

    // Possible srec footers
    let srec_footers = vec![b"\nS9", b"\nS8", b"\nS7"];

    // Need to grep for the srec footer to determine total size
    let grep = AhoCorasick::new(srec_footers.clone()).unwrap();

    // Search for srec footer lines
    for srec_footer_match in grep.find_overlapping_iter(&file_data[offset..]) {
        // Assume origin OS is Unix unless proven otherwise
        let mut os_type = "Unix";

        // Start searching for terminating EOF characters after this footer match (all footer signatures are the same size)
        let mut srec_eof: usize = offset + srec_footer_match.start() + srec_footers[0].len();
        let mut last_srec_eof = None;

        // Found the start of a possible srec footer line, loop over remianing bytes looking for the line termination
        while is_offset_safe(available_data, srec_eof, last_srec_eof) {
            // All srec lines should end in \n or \r\n
            if terminating_characters.contains(&file_data[srec_eof]) {
                // Windows systems use \r\n
                if file_data[srec_eof] == WINDOWS_TERMINATING_CHARACTER {
                    // There should be one more character, a \n, which is common to both windows and linux implementations
                    srec_eof += 1;
                    os_type = "Windows";
                }

                // Sanity check, don't want to index out of bounds
                if let Some(srec_last_byte) = file_data.get(srec_eof) {
                    // Last byte should be a line feed (\n)
                    if *srec_last_byte == UNIX_TERMINATING_CHARACTER {
                        // Include the final line feed byte in the size of the s-record
                        srec_eof += 1;

                        // Report results
                        result.size = srec_eof - offset;
                        result.description = format!(
                            "{}, origin OS: {}, total size: {} bytes",
                            result.description, os_type, result.size
                        );
                        return Ok(result);
                    }
                }

                // Invalid srec termination, stop searching
                return Err(SignatureError);
            }

            // Not a terminating character, go to the next byte in the file
            last_srec_eof = Some(srec_eof);
            srec_eof += 1;
        }
    }

    // No valid srec footers found
    Err(SignatureError)
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

    if let Some(srec_data) = file_data.get(offset..)
        && let Ok((consumed, decoded)) = decode_srec(srec_data)
    {
        result.success = true;
        result.size = Some(consumed);

        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success = chroot.create_file(OUTPUT_FILE_NAME, &decoded);
        }
    }

    result
}

/// A chunk of decoded binary data and the memory address it should be placed at.
struct DataRecord {
    address: u64,
    data: Vec<u8>,
}

/// Decodes the data payload of a Motorola S-record stream.
/// Returns the number of input bytes consumed and the decoded binary data.
///
/// Record format (per Motorola M68000 Family Programmer's Reference Manual):
///   S + Type(1) + ByteCount(2 hex) + Address(4/6/8 hex) + Data(0+) + Checksum(2 hex)
///
/// ByteCount = number of address + data + checksum bytes (excludes type and count fields).
/// Checksum  = LSB of ones' complement of (ByteCount + Address + Data).
fn decode_srec(srec_data: &[u8]) -> Result<(usize, Vec<u8>), SignatureError> {
    const MIN_RECORD_LEN: usize = 6;

    let mut consumed = 0usize;
    let mut terminated = false;
    let mut data_records: Vec<DataRecord> = Vec::new();

    for line in srec_data.split_inclusive(|&b| b == b'\n') {
        let record = strip_line_terminators(line);

        if record.is_empty() {
            consumed += line.len();
            continue;
        }

        if record.len() < MIN_RECORD_LEN || record[0] != b'S' || !record[1].is_ascii_digit() {
            break;
        }

        let record_type = record[1] - b'0';

        // Decode the hex payload (byte_count + address + data + checksum)
        let record_bytes = match hex::decode(&record[2..]) {
            Ok(bytes) => bytes,
            Err(_) => break,
        };

        // First decoded byte is the count of the bytes that follow (address + data + checksum)
        let byte_count = record_bytes[0] as usize;
        if record_bytes.len() != byte_count + 1 {
            break;
        }

        // Validate checksum: sum of all bytes (count, address, data, checksum) must be 0xFF
        let sum: u8 = record_bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0xFF {
            break;
        }

        // Each record type defines its address field size; byte_count must
        // cover the address field plus at least the checksum byte.
        let address_size = match record_type {
            0 => 2,     // S0 header: 2-byte address (always 0x0000), optional data
            1 => 2,     // S1 data: 2-byte address
            2 => 3,     // S2 data: 3-byte address
            3 => 4,     // S3 data: 4-byte address
            5 => 2,     // S5 count: 2-byte field (holds S1/S2/S3 record count)
            6 => 3,     // S6 count: 3-byte field (non-standard extension of S5)
            7 => 4,     // S7 termination: 4-byte execution address
            8 => 3,     // S8 termination: 3-byte execution address
            9 => 2,     // S9 termination: 2-byte execution address
            _ => break, // S4 is undefined in the official standard
        };

        if byte_count < address_size + 1 {
            break;
        }

        // Non-data records: no payload to extract
        match record_type {
            0 | 5 | 6 => {
                consumed += line.len();
                continue;
            }
            7..=9 => {
                consumed += line.len();
                terminated = true;
                break;
            }
            _ => {} // S1/S2/S3: fall through to data extraction
        }

        // Address lies after the byte-count field
        let mut addr_buf = [0u8; 8];
        addr_buf[8 - address_size..].copy_from_slice(&record_bytes[1..1 + address_size]);
        let address = u64::from_be_bytes(addr_buf);

        // Data lies between the address field and the trailing checksum byte
        let data_start = 1 + address_size;
        let data_end = record_bytes.len() - 1;
        if data_start > data_end {
            break;
        }

        data_records.push(DataRecord {
            address,
            data: record_bytes[data_start..data_end].to_vec(),
        });
        consumed += line.len();
    }

    if !terminated || data_records.is_empty() {
        return Err(SignatureError);
    }

    // Compute the full address span so the output buffer covers every data chunk
    let min_addr = data_records.iter().map(|r| r.address).min().unwrap();
    let max_end = data_records
        .iter()
        .map(|r| r.address + r.data.len() as u64)
        .max()
        .unwrap();

    let mut decoded = vec![0xFFu8; (max_end - min_addr) as usize];

    for record in &data_records {
        let offset = (record.address - min_addr) as usize;
        decoded[offset..offset + record.data.len()].copy_from_slice(&record.data);
    }

    Ok((consumed, decoded))
}

/// Strip trailing `\n` and `\r` bytes from a record line
fn strip_line_terminators(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_srec_with_address_gap() {
        // Records at 0x0000 and 0x0008 with a 4-byte gap.
        // Records are placed at their target addresses with 0xFF padding in gaps.
        let srec = b"S107000000010203F2\n\
                      S107000804050607DA\n\
                      S9030000FC\n";
        let (_consumed, decoded) = decode_srec(srec).unwrap();
        assert_eq!(decoded.len(), 12);
        assert_eq!(&decoded[0..4], &[0x00, 0x01, 0x02, 0x03]);
        for &b in &decoded[4..8] {
            assert_eq!(b, 0xFF);
        }
        assert_eq!(&decoded[8..12], &[0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn decode_srec_nonzero_base_with_gap() {
        // Non-zero base address and a gap between records.
        let srec = b"S107010000010203F1\n\
                      S107010C04050607D5\n\
                      S9030000FC\n";
        let (_consumed, decoded) = decode_srec(srec).unwrap();
        assert_eq!(decoded.len(), 16);
        assert_eq!(&decoded[0..4], &[0x00, 0x01, 0x02, 0x03]);
        for &b in &decoded[4..12] {
            assert_eq!(b, 0xFF);
        }
        assert_eq!(&decoded[12..16], &[0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn decode_srec_invalid_checksum() {
        // Correct checksum is 0xF2; 0xF3 is wrong.
        let srec = b"S107000000010203F3\n\
                      S9030000FC\n";
        assert!(decode_srec(srec).is_err());
    }

    #[test]
    fn decode_srec_truncated_record() {
        // Too short to parse (fewer than 6 hex chars for type+count+address+checksum).
        let srec = b"S1\n\
                      S9030000FC\n";
        assert!(decode_srec(srec).is_err());
    }

    #[test]
    fn decode_srec_unsupported_type() {
        // S4 is undefined in the standard and should be rejected.
        let srec = b"S407000000010203F2\n\
                      S9030000FC\n";
        assert!(decode_srec(srec).is_err());
    }

    #[test]
    fn decode_srec_no_terminator() {
        // Missing S7/S8/S9 termination record.
        let srec = b"S107000000010203F2\n\
                      S107000804050607DA\n";
        assert!(decode_srec(srec).is_err());
    }
}

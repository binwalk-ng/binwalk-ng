use crate::signatures::{SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "PDF document";

/// PDF magic bytes
pub fn pdf_magic() -> Vec<Vec<u8>> {
    vec![b"%PDF-1.".to_vec(), b"%PDF-2.".to_vec()]
}

/// Validate a PDF signature
pub fn pdf_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // More than enough data for our needs
    const MIN_PDF_SIZE: usize = 16;

    const NEWLINE_OFFSET: usize = 8;
    const MAJOR_NUMBER_OFFSET: usize = 5;
    const MINOR_NUMBER_OFFSET: usize = 7;

    const ASCII_ZERO: u8 = 0x30;
    const ASCII_ONE: u8 = 0x31;
    const ASCII_TWO: u8 = 0x32;
    const ASCII_NINE: u8 = 0x39;
    const ASCII_NEWLINE: u8 = 0x0A;
    const ASCII_PERCENT: u8 = 0x25;
    const ASCII_CARRIGE_RETURN: u8 = 0x0D;

    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        size: 0,
        ..Default::default()
    };

    let newline_characters: Vec<u8> = vec![ASCII_NEWLINE, ASCII_CARRIGE_RETURN];

    let pdf_header_start = offset;
    let pdf_header_end = pdf_header_start + MIN_PDF_SIZE;

    // PDF header is expected to start with something like: %PDF-1.7\n%
    if let Some(pdf_header) = file_data.get(pdf_header_start..pdf_header_end) {
        // Get the major and minor version numbers at the expected offsets
        let version_major: u8 = pdf_header[MAJOR_NUMBER_OFFSET];
        let version_minor: u8 = pdf_header[MINOR_NUMBER_OFFSET];

        // Sanity check the version numbers (1.0-1.9, 2.0)
        if (version_major == ASCII_ONE && (ASCII_ZERO..=ASCII_NINE).contains(&version_minor))
            || (version_major == ASCII_TWO && version_minor == ASCII_ZERO)
        {
            // Update the result description to include the version number
            result.description = format!(
                "{}, version {}.{}",
                result.description,
                version_major - ASCII_ZERO,
                version_minor - ASCII_ZERO
            );

            // Search the remaining bytes for new line characters followed by a percent character
            for byte in pdf_header[NEWLINE_OFFSET..].iter().copied() {
                // Any new line or carrige return byte is OK, just keep going
                if newline_characters.contains(&byte) {
                    continue;
                // There should be a percent character
                } else if byte == ASCII_PERCENT {
                    return Ok(result);
                // Anything else is invalid
                } else {
                    break;
                }
            }
        }
    }

    Err(SignatureError)
}

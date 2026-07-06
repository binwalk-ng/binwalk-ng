use crate::common::get_cstring;
use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_LOW, SignatureError, SignatureResult};
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

pub const DESCRIPTION: &str = "D-Link firmware";

const KNOWN_MODELS: &[&[u8]] = &[b"DAP-1325", b"DAP-1610"];
const HEADER_SIZE: usize = std::mem::size_of::<DlinkFwHeader>();

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DlinkFwHeader {
    model: [u8; 32],
    hw_rev: [u8; 8],
    version: [u8; 8],
    build: [u8; 8],
    encrypt_marker: [u8; 8],
}

pub fn dlink_fw_magic() -> Vec<Vec<u8>> {
    KNOWN_MODELS.iter().map(|m| m.to_vec()).collect()
}

pub fn dlink_fw_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let data = file_data.get(offset..).ok_or(SignatureError)?;
    let (header, _) = DlinkFwHeader::ref_from_prefix(data).map_err(|_| SignatureError)?;

    let model_valid = KNOWN_MODELS.iter().any(|m| header.model.starts_with(m));
    if !model_valid || &header.encrypt_marker != b"encrypt\x00" {
        return Err(SignatureError);
    }

    let model = get_cstring(&header.model)
        .trim_end_matches('\r')
        .to_string();
    let hw_rev = get_cstring(&header.hw_rev)
        .trim_end_matches('\r')
        .to_string();
    let ver = get_cstring(&header.version)
        .trim_end_matches('\r')
        .to_string();
    let build = get_cstring(&header.build)
        .trim_end_matches('\r')
        .to_string();

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: if offset == 0 {
            CONFIDENCE_HIGH
        } else {
            CONFIDENCE_LOW
        },
        ..Default::default()
    };

    result.description = format!(
        "{}, model: {}, HW rev: {}, firmware version: {}, build: {}",
        result.description, model, hw_rev, ver, build,
    );

    Ok(result)
}

pub fn dlink_fw_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(dlink_fw_decrypt),
        ..Default::default()
    }
}

pub fn dlink_fw_decrypt(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTPUT_FILE_NAME: &str = "decrypted.bin";

    let mut result = ExtractionResult::default();
    if let Ok(decrypted_data) = delink::decrypt(&file_data[offset..]) {
        // dap1325::decrypt prepends the 64-byte plaintext header to the decrypted body.
        // Strip it so the output starts directly with the uImage and doesn't
        // trigger a dlink_fw re-match during recursive extraction.
        let payload = if decrypted_data.len() > HEADER_SIZE {
            &decrypted_data[HEADER_SIZE..]
        } else {
            &decrypted_data[..]
        };

        result.success = true;

        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success = chroot.create_file(OUTPUT_FILE_NAME, payload);
        }
    }

    result
}

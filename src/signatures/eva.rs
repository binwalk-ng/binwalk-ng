use crate::signatures::common::{
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};
use crate::structures::eva::{
    DUAL_KERNEL_MAGIC, EvaImageKind, EvaTiRecord, TI_AR7_2ND_MAGIC, TI_AR7_MAGIC, parse_eva_image,
};

/// Human readable description
pub const DESCRIPTION: &str = "Fritz!Box EVA kernel image";

/// EVA magic bytes: dual-kernel container, primary TI record, secondary TI record
pub fn eva_magic() -> Vec<Vec<u8>> {
    vec![
        DUAL_KERNEL_MAGIC.to_le_bytes().to_vec(),
        TI_AR7_MAGIC.to_le_bytes().to_vec(),
        TI_AR7_2ND_MAGIC.to_le_bytes().to_vec(),
    ]
}

/// Validates EVA kernel image signatures
pub fn eva_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let image = parse_eva_image(file_data, offset).map_err(|_| SignatureError)?;

    let all_checksums_valid = image.all_checksums_valid();

    let confidence = if all_checksums_valid {
        CONFIDENCE_HIGH
    } else if offset == 0 {
        CONFIDENCE_MEDIUM
    } else {
        CONFIDENCE_LOW
    };

    let kernel_phrase = match &image.kind {
        EvaImageKind::SingleKernel(_) => "single-kernel",
        EvaImageKind::SecondaryFragment(_) => "secondary-kernel fragment",
        EvaImageKind::DualKernel { .. } => "dual-kernel",
    };

    let records_desc = match &image.kind {
        EvaImageKind::SingleKernel(record) => record_desc("primary", record),
        EvaImageKind::SecondaryFragment(record) => record_desc("secondary", record),
        EvaImageKind::DualKernel {
            primary, secondary, ..
        } => format!(
            "{}, {}",
            record_desc("primary", primary),
            record_desc("secondary", secondary),
        ),
    };

    let signature_desc = image
        .file_signature
        .map(|sig| format!(", file signature CRC: {:#010X}", sig.crc))
        .unwrap_or_default();

    let validation_desc = if all_checksums_valid {
        String::new()
    } else {
        let failures = collect_checksum_failures(&image);
        format!(", checksum validation failed ({})", failures.join(", "))
    };

    Ok(SignatureResult {
        offset,
        size: image.total_size,
        confidence,
        description: format!(
            "{}, {}, {}{}{}",
            DESCRIPTION, kernel_phrase, records_desc, signature_desc, validation_desc,
        ),
        ..Default::default()
    })
}

fn record_desc(label: &str, record: &EvaTiRecord) -> String {
    format!(
        "{label} load: {:#X}, entry: {:#X}, compressed: {} bytes, uncompressed: {} bytes",
        record.load_addr,
        record.entry_addr,
        record.lzma.compressed_len,
        record.lzma.uncompressed_len,
    )
}

fn collect_checksum_failures(image: &crate::structures::eva::EvaImage) -> Vec<&'static str> {
    let mut failures: Vec<&'static str> = Vec::new();
    match &image.kind {
        EvaImageKind::SingleKernel(rec) => {
            if !rec.checksum_valid {
                failures.push("primary TI");
            }
            if !rec.lzma.data_checksum_valid {
                failures.push("primary LZMA data");
            }
        }
        EvaImageKind::SecondaryFragment(rec) => {
            if !rec.checksum_valid {
                failures.push("secondary TI");
            }
            if !rec.lzma.data_checksum_valid {
                failures.push("secondary LZMA data");
            }
        }
        EvaImageKind::DualKernel {
            primary,
            secondary,
            trailer_checksum_valid,
        } => {
            if !primary.checksum_valid {
                failures.push("primary TI");
            }
            if !primary.lzma.data_checksum_valid {
                failures.push("primary LZMA data");
            }
            if !secondary.checksum_valid {
                failures.push("secondary TI");
            }
            if !secondary.lzma.data_checksum_valid {
                failures.push("secondary LZMA data");
            }
            if !trailer_checksum_valid {
                failures.push("dual trailer");
            }
        }
    }
    if image.file_signature.is_some_and(|sig| !sig.valid) {
        failures.push("file signature");
    }
    failures
}

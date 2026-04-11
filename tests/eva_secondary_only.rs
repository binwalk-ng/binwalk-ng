mod common;

use binwalk_ng::signatures::common::CONFIDENCE_HIGH;

const SIGNATURE_TYPE: &str = "eva";
const INPUT_FILE_NAME: &str = "eva_secondary_only.bin";

#[test]
fn integration_test_secondary_only_eva() {
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn secondary_only_eva_reports_full_size_and_validates_crcs() {
    let file_path = std::path::Path::new("tests")
        .join("inputs")
        .join(INPUT_FILE_NAME);
    let expected_size = std::fs::metadata(&file_path).unwrap().len() as usize;

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert_eq!(results.file_map.len(), 1);
    let signature = &results.file_map[0];
    assert_eq!(signature.offset, 0);
    assert_eq!(
        signature.size, expected_size,
        "reported signature size must cover the full fragment"
    );
    assert_eq!(signature.confidence, CONFIDENCE_HIGH);
    assert!(signature.description.contains("secondary-kernel fragment"));
    // Secondary-only fragments never carry a trailing file signature.
    assert!(
        !signature.description.contains("file signature CRC"),
        "secondary-only fragments must not report a file signature: {}",
        signature.description
    );
    assert!(
        !signature.description.contains("checksum validation failed"),
        "description must not report checksum failures: {}",
        signature.description
    );
    assert!(results.extractions[&signature.id].success);
}

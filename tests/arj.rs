use crate::common::assert_results_ok;

mod common;

#[test]
fn integration_test_valid_arj() {
    const SIGNATURE_TYPE: &str = "arj";
    const INPUT_FILE_NAME: &str = "arj.embedded.bin";

    // Two archives back-to-back (after 13 pad bytes); each archive yields a
    // signature at its comment header AND at its readme.txt entry header.
    let expected_signature_offsets: Vec<usize> = vec![0xD, 0x4A, 0x15D4F, 0x15D8C];
    // Extraction succeeds only where the archive actually starts.
    let expected_extraction_offsets: Vec<usize> = vec![0xD, 0x15D4F];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    )
}

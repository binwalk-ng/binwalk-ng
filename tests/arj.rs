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

    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    )
}

/// A single archive at offset 0 (the first half of arj.embedded.bin):
/// comment header plus readme.txt entry header, extraction only at the start.
#[test]
fn integration_test_single_arj() {
    let results = common::run_binwalk("arj", "arj.archive.arj");
    common::assert_results_ok(results, vec![0, 0x3D], vec![0]);
}

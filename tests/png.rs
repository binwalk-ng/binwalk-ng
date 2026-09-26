mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "png";
    const INPUT_FILE_NAME: &str = "png.malformed.png";

    let expected_signature_offsets: Vec<usize> = vec![];
    let expected_extraction_offsets: Vec<usize> = vec![];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}

#[test]
fn integration_test_valid_png() {
    // PNG has no extractor (extraction_declined): one signature at offset 0,
    // no extraction results.
    let results = common::run_binwalk("png", "png.gradient.png");
    common::assert_results_ok(results, vec![0], vec![]);
}

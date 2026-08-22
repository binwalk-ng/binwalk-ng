mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "bmp";
    const INPUT_FILE_NAME: &str = "bmp.gradient.bmp";

    let expected_signature_offsets: Vec<usize> = vec![0];
    let expected_extraction_offsets: Vec<usize> = vec![0];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}

mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "riff";
    const INPUT_FILE_NAME: &str = "riff.sine.wav";

    // A standalone WAV occupying the whole file: detected at offset 0, and
    // extraction is declined (there is nothing to carve out).
    let expected_signature_offsets: Vec<usize> = vec![0];
    let expected_extraction_offsets: Vec<usize> = vec![];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}

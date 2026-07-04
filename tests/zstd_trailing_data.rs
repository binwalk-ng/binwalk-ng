mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "zstd";
    const INPUT_FILE_NAME: &str = "zstd_trailing_data.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}
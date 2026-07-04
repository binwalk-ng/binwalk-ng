mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lz4";
    const INPUT_FILE_NAME: &str = "lz4_trailing_data.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}
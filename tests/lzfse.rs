mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lzfse";
    const INPUT_FILE_NAME: &str = "lzfse.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

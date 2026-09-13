mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lzma";
    const INPUT_FILE_NAME: &str = "lzma.data.lzma";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

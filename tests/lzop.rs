mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lzop";
    const INPUT_FILE_NAME: &str = "lzop.data.lzo";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

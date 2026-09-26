mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ubifs";
    const INPUT_FILE_NAME: &str = "ubifs.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

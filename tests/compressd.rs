mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "compressd";
    const INPUT_FILE_NAME: &str = "compressd.data.Z";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ubi";
    const INPUT_FILE_NAME: &str = "ubi.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

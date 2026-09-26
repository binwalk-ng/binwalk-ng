mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "fat";
    const INPUT_FILE_NAME: &str = "fat.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

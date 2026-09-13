mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ext";
    const INPUT_FILE_NAME: &str = "ext4.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

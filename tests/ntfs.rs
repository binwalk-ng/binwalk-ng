mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ntfs";
    const INPUT_FILE_NAME: &str = "ntfs.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

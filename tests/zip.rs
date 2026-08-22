mod common;

#[test]
fn integration_test_valid_zip() {
    const SIGNATURE_TYPE: &str = "zip";
    const INPUT_FILE_NAME: &str = "zip.archive.zip";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

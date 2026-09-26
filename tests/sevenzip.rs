mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "7zip";
    const INPUT_FILE_NAME: &str = "archive.7z";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

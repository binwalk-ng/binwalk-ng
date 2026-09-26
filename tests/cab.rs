mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "cab";
    const INPUT_FILE_NAME: &str = "cab.archive.cab";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

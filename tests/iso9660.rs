mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "iso9660";
    const INPUT_FILE_NAME: &str = "iso9660.iso";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

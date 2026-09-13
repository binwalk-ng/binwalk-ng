mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "gpg_signed";
    const INPUT_FILE_NAME: &str = "gpg.signed.gpg";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

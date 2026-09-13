mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "xz";
    const INPUT_FILE_NAME: &str = "xz.data.xz";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

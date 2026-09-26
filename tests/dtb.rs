mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "dtb";
    const INPUT_FILE_NAME: &str = "dtb.sample.dtb";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "srecord";
    const INPUT_FILE_NAME: &str = "srec.hex";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn integration_test_s6() {
    const SIGNATURE_TYPE: &str = "srecord";
    const INPUT_FILE_NAME: &str = "srec_s6.hex";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

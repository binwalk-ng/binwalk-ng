mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "uimage";
    const INPUT_FILE_NAME: &str = "uimage.arm.ub";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn integration_test_gzip() {
    const SIGNATURE_TYPE: &str = "uimage";
    const INPUT_FILE_NAME: &str = "uimage.arm.gzip.ub";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

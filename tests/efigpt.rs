mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "efigpt";
    const INPUT_FILE_NAME: &str = "efigpt.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

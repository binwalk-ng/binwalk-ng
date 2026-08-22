mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "program_store";
    const INPUT_FILE_NAME: &str = "program_store.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn integration_test_dual() {
    const SIGNATURE_TYPE: &str = "program_store";
    const INPUT_FILE_NAME: &str = "program_store.dual.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

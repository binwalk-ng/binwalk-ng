mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lz4";
    const INPUT_FILE_NAME: &str = "lz4.data.lz4";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn trailing_data() {
    common::trailing_data_test("lz4", "lz4.data.lz4");
}

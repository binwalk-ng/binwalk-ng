mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "zstd";
    const INPUT_FILE_NAME: &str = "zstd.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn trailing_data() {
    common::trailing_data_test("zstd", "zstd.bin");
}

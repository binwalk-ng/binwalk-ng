mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "jffs2";
    const INPUT_FILE_NAME: &str = "jffs2.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

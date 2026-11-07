mod common;

use std::fs;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ntfs";
    const INPUT_FILE_NAME: &str = "ntfs.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// End-to-end extraction test: the native NTFS extractor must reproduce the
/// layout and byte-for-byte contents that `mkntfs` + `ntfscp` stored in the
/// fixture. `ntfscp` has no offline mkdir, so this image is flat.
#[test]
fn extraction_produces_expected_files() {
    let payload = common::reference_payload();
    let install_docs = b"installed documentation\n".repeat(20);

    common::extract_and_verify("ntfs", "ntfs.image", |output| {
        let rootfs = output.join("rootfs");
        assert_eq!(
            fs::read(rootfs.join("readme.txt")).unwrap(),
            payload,
            "readme.txt contents differ"
        );
        assert_eq!(
            fs::read(rootfs.join("install.txt")).unwrap(),
            install_docs,
            "install.txt contents differ"
        );
        assert!(
            rootfs.join("payload.gz").is_file(),
            "payload.gz was not extracted"
        );
    });
}

#[test]
fn trailing_data_does_not_break_extraction() {
    common::trailing_data_test("ntfs", "ntfs.image");
}

mod common;

use std::fs;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "fat";
    const INPUT_FILE_NAME: &str = "fat.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// End-to-end extraction test: the native FAT extractor must reproduce the
/// layout and byte-for-byte contents that `mkfs.vfat` + mtools stored in the
/// fixture.
#[test]
fn extraction_produces_expected_files() {
    let payload = common::reference_payload();
    let install_docs = b"installed documentation\n".repeat(20);

    common::extract_and_verify("fat", "fat.image", |output| {
        let rootfs = output.join("rootfs");
        assert_eq!(
            fs::read(rootfs.join("readme.txt")).unwrap(),
            payload,
            "readme.txt contents differ"
        );
        assert_eq!(
            fs::read(rootfs.join("docs/install.txt")).unwrap(),
            install_docs,
            "docs/install.txt contents differ"
        );
        assert!(
            rootfs.join("docs/payload.gz").is_file(),
            "docs/payload.gz was not extracted"
        );
    });
}

#[test]
fn trailing_data_does_not_break_extraction() {
    common::trailing_data_test("fat", "fat.image");
}

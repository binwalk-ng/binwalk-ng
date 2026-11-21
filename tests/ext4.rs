mod common;

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::process::Command;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ext";
    const INPUT_FILE_NAME: &str = "ext4.image";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// End-to-end extraction test: the native ext extractor must reproduce the
/// layout and byte-for-byte contents that `mkfs.ext4 -d` stored in the fixture.
#[test]
fn extraction_produces_expected_files() {
    let payload = common::reference_payload();
    let install_docs = b"installed documentation\n".repeat(20);

    common::extract_and_verify("ext", "ext4.image", |output| {
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
    common::trailing_data_test("ext", "ext4.image");
}

/// Sparse ext files with data after a hole must be extracted correctly.
#[test]
fn sparse_file_with_data_after_hole_is_extracted_correctly() {
    let work = tempfile::tempdir().expect("failed to create temp dir");
    let src = work.path().join("src");
    fs::create_dir(&src).expect("failed to create source dir");

    // "AAAA" at offset 0, a hole, then "BBBB" at offset 16384.
    let sparse_path = src.join("sparse.bin");
    let mut sparse = fs::File::create(&sparse_path).expect("failed to create sparse file");
    sparse.write_all(b"AAAA").expect("failed to write prefix");
    sparse
        .seek(SeekFrom::Start(16384))
        .expect("failed to seek in sparse file");
    sparse
        .write_all(b"BBBB")
        .expect("failed to write data after hole");
    drop(sparse);

    // Create a sized image file first, then format and populate it with -d.
    let image = work.path().join("sparse.ext4");
    {
        let f = fs::File::create(&image).expect("failed to create image file");
        f.set_len(2 * 1024 * 1024)
            .expect("failed to size image file");
    }
    let mkfs_output = Command::new("mkfs.ext4")
        .args([
            "-q",
            "-b",
            "4096",
            "-F",
            "-d",
            src.to_str().expect("temp path is not UTF-8"),
            image.to_str().expect("temp path is not UTF-8"),
        ])
        .output()
        .expect("failed to run mkfs.ext4");
    assert!(
        mkfs_output.status.success(),
        "mkfs.ext4 failed: {}{}",
        String::from_utf8_lossy(&mkfs_output.stdout),
        String::from_utf8_lossy(&mkfs_output.stderr)
    );

    let output_dir = tempfile::tempdir().expect("failed to create output dir");
    let binwalker = binwalk_ng::Binwalk::builder()
        .include("ext")
        .build()
        .expect("Binwalk initialization failed");
    let results = binwalker.analyze(&image, Some(output_dir.path()));

    assert!(!results.file_map.is_empty(), "no ext signature found");
    let mut extracted = None;
    for ext in results.extractions.values() {
        assert!(ext.success, "ext extraction failed");
        extracted = Some(ext.output_directory.clone());
    }
    let output = extracted.expect("no successful ext extraction");
    let data = fs::read(output.join("rootfs").join("sparse.bin"))
        .expect("failed to read extracted sparse file");

    let mut expected = vec![0u8; 16388];
    expected[0..4].copy_from_slice(b"AAAA");
    expected[16384..16388].copy_from_slice(b"BBBB");
    assert_eq!(data, expected, "sparse file contents mismatch");
}

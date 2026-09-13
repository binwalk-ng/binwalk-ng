mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "gzip";
    const INPUT_FILE_NAME: &str = "gzip.data.gz";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// Two concatenated gzip members: gzip.data.gz (88055 bytes) followed by a
/// second small member. Both must be detected and extracted.
#[test]
fn multimember() {
    let results = common::run_binwalk("gzip", "gzip.multimember.gz");
    common::assert_results_ok(results, vec![0, 88055], vec![0, 88055]);
}

/// gzip stream behind 4096 zero pad bytes: exactly one signature at 0x1000.
#[test]
fn embedded_at_offset() {
    let results = common::run_binwalk("gzip", "gzip.embedded.gz.bin");
    common::assert_results_ok(results, vec![0x1000], vec![0x1000]);
}

/// Prebuilt trailing-garbage fixture: decompression must stop at the member
/// boundary (reported size excludes the garbage) and succeed.
#[test]
fn trailing_fixture() {
    common::integration_test("gzip", "gzip.trailing.bin");
}

/// gzip containing a tarball: outer extraction succeeds, and the decompressed
/// output scans as a tarball at offset 0 (manual matryoshka; the library does
/// not recurse on its own, see main.rs).
#[test]
fn nested_tarball() {
    common::extract_and_verify("gzip", "tarball.tar.gz", |root| {
        let inner_path = root.join("decompressed.bin");
        let inner_data = std::fs::read(&inner_path).unwrap();
        let inner_map = binwalk_ng::Binwalk::builder()
            .include("tarball")
            .build()
            .expect("Binwalk initialization failed")
            .scan(&inner_data);
        assert_eq!(inner_map.len(), 1);
        assert_eq!(inner_map[0].offset, 0);
        assert_eq!(inner_map[0].name, "tarball");
    });
}

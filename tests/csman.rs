mod common;

use binwalk_ng::Binwalk;

/// A valid, zlib-compressed CSMAN DAT file should be identified and extracted successfully.
/// This guards against the decompression-bomb fix breaking extraction of legitimate files.
#[test]
fn integration_test() {
    common::integration_test("csman", "csman.bin");
}

/// Regression test for the CSMAN decompression-bomb DoS.
///
/// The CSMAN signature parser dry-runs the extractor during the *scan* phase (no `-e` flag
/// needed), which decompresses the file's zlib-compressed entry data. The bomb fixture is a
/// fully valid CSMAN entry stream that decompresses to ~120MiB from a ~120KiB file. Without an
/// upper bound on the decompressed size, scanning it would allocate the entire payload in one
/// contiguous buffer, enabling memory-exhaustion denial of service.
///
/// With the size limit in place, decompression aborts and the file produces no signature match.
/// (This exercises the scan phase only, so no extraction/file writes occur even on regression.)
#[test]
fn decompression_bomb_test() {
    let file_path = std::path::Path::new("tests")
        .join("inputs")
        .join("csman_decompression_bomb.bin");
    let file_data = std::fs::read(&file_path).expect("failed to read decompression bomb fixture");

    let binwalker = Binwalk::configure(None, None, vec!["csman".to_string()], vec![], None, false)
        .expect("Binwalk initialization failed");

    let results = binwalker.scan(&file_data);

    assert!(
        results.is_empty(),
        "decompression bomb exceeding the size limit must not produce a signature match"
    );
}

mod common;

use std::fs;

/// The RAR3 fixtures (rar3.rar / rar3.solid.rar / rar3.dos_sfx.exe) are
/// committed upstream archives whose inner file is testfile.txt. The
/// generated RAR5 samples (rar5.rar / rar5.solid.rar) store the samples
/// repo's shared payload text as readme.txt (see generate_samples.py:
/// `rar a -ep1 readme.txt`).
const TESTFILE_TXT: &[u8] = b"Testing 123\n";

/// Smoke test: exactly one RAR signature is detected at offset 0, and its
/// extraction reports success.
#[test]
fn integration_test() {
    common::integration_test("rar", "rar3.rar");
}

// ── Content-verification (via `common::extract_and_verify`) ─────────────

#[test]
fn v3_extraction() {
    common::extract_and_verify("rar", "rar3.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn v5_extraction() {
    common::extract_and_verify("rar", "rar5.rar", |root| {
        let p = root.join("readme.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), common::reference_payload());
    });
}

#[test]
fn v3_solid_extraction() {
    common::extract_and_verify("rar", "rar3.solid.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn v5_solid_extraction() {
    common::extract_and_verify("rar", "rar5.solid.rar", |root| {
        let p = root.join("readme.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), common::reference_payload());
    });
}

#[test]
fn sfx_extraction() {
    common::extract_and_verify("rar", "rar3.dos_sfx.exe", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists(), "missing testfile.txt");
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);

        let p = root.join("acknow.txt");
        assert!(p.exists(), "missing acknowledg.txt");
        assert!(!fs::read(&p).unwrap().is_empty(), "acknowledg.txt is empty");
    });
}

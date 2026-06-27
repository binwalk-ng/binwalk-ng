mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

const TESTFILE_TXT: &[u8] = b"Testing 123\n";

/// Smoke test: exactly one RAR signature is detected at offset 0, and its
/// extraction reports success.
#[test]
fn integration_test() {
    common::integration_test("rar", "testfile.rar3.rar");
}

// ── Helpers ──────────────────────────────────────────────────────────

fn run_rar_binwalk(input: &str, output_dir: &Path) -> binwalk_ng::AnalysisResults {
    let path = Path::new("tests").join("inputs").join(input);
    let binwalker = Binwalk::configure(
        Some(&path),
        Some(output_dir),
        vec!["rar".to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");
    binwalker.analyze(&binwalker.base_target_file, true)
}

#[track_caller]
fn extract_and_verify(input: &str, checker: impl Fn(&Path)) {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk(input, output_dir.path());

    assert!(!results.file_map.is_empty(), "'{}': no signatures", input);

    let mut any_success = false;
    for ext in results.extractions.values() {
        assert!(ext.success, "'{}': extraction failed", input);
        checker(&ext.output_directory);
        any_success = true;
    }
    assert!(any_success, "'{}': no successful extraction", input);
}

// ── Content-verification ─────────────────────────────────────────────

#[test]
fn v3_extraction() {
    extract_and_verify("testfile.rar3.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn v5_extraction() {
    extract_and_verify("testfile.rar5.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn v3_solid_extraction() {
    extract_and_verify("testfile.rar3.solid.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn v5_solid_extraction() {
    extract_and_verify("testfile.rar5.solid.rar", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
    });
}

#[test]
fn sfx_extraction() {
    extract_and_verify("testfile.rar3.dos_sfx.exe", |root| {
        let p = root.join("testfile.txt");
        assert!(p.exists(), "missing testfile.txt");
        assert_eq!(&fs::read(&p).unwrap(), TESTFILE_TXT);

        let p = root.join("acknow.txt");
        assert!(p.exists(), "missing acknowledg.txt");
        assert!(!fs::read(&p).unwrap().is_empty(), "acknowledg.txt is empty");
    });
}

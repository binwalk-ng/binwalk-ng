mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::formats::rar::rar_extractor;
use binwalk_ng::extractors::ExtractorType;
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

// ── Extractor type ───────────────────────────────────────────────────

/// The RAR extractor must be internal (no external `unrar` dependency).
#[test]
fn extractor_is_internal() {
    let extractor = rar_extractor();
    assert!(
        matches!(extractor.utility, ExtractorType::Internal(_)),
        "Expected Internal extractor, got {:?}",
        extractor.utility
    );
}

// ── Signature description sanity ─────────────────────────────────────

/// The signature description for a RAR v3 (format v4) file must mention "version: 4".
#[test]
fn v3_signature_description_mentions_version_4() {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk("testfile.rar3.rar", output_dir.path());
    assert!(!results.file_map.is_empty(), "no signatures for v3 file");
    let sig = &results.file_map[0];
    assert_eq!(sig.offset, 0);
    assert!(
        sig.description.contains("version: 4"),
        "expected 'version: 4' in description, got: {}",
        sig.description
    );
}

/// The signature description for a RAR v5 file must mention "version: 5".
#[test]
fn v5_signature_description_mentions_version_5() {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk("testfile.rar5.rar", output_dir.path());
    assert!(!results.file_map.is_empty(), "no signatures for v5 file");
    let sig = &results.file_map[0];
    assert_eq!(sig.offset, 0);
    assert!(
        sig.description.contains("version: 5"),
        "expected 'version: 5' in description, got: {}",
        sig.description
    );
}

/// Signature descriptions must include the total size in bytes.
#[test]
fn signature_description_includes_total_size() {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk("testfile.rar3.rar", output_dir.path());
    assert!(!results.file_map.is_empty());
    let sig = &results.file_map[0];
    assert!(
        sig.description.contains("total size:"),
        "expected 'total size:' in description, got: {}",
        sig.description
    );
}

/// A non-RAR binary must produce zero RAR signatures.
#[test]
fn non_rar_file_has_no_rar_signatures() {
    // Reuse a known non-RAR test input. gzip.bin is present in the repo and
    // cannot contain a valid RAR header.
    let output_dir = tempfile::tempdir().unwrap();
    let path = Path::new("tests").join("inputs").join("gzip.bin");
    // Skip the test if the input file is missing (other test suites own it).
    if !path.exists() {
        return;
    }
    let binwalker = Binwalk::configure(
        Some(&path),
        Some(output_dir.path()),
        vec!["rar".to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");
    let results = binwalker.analyze(&binwalker.base_target_file, true);
    assert!(
        results.file_map.is_empty(),
        "expected no RAR signatures in gzip.bin, found {}",
        results.file_map.len()
    );
}

/// Solid RAR v3 archives are detected at offset 0.
#[test]
fn v3_solid_detected_at_offset_0() {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk("testfile.rar3.solid.rar", output_dir.path());
    assert!(!results.file_map.is_empty(), "no signatures for v3 solid file");
    assert_eq!(results.file_map[0].offset, 0);
}

/// Solid RAR v5 archives are detected at offset 0.
#[test]
fn v5_solid_detected_at_offset_0() {
    let output_dir = tempfile::tempdir().unwrap();
    let results = run_rar_binwalk("testfile.rar5.solid.rar", output_dir.path());
    assert!(!results.file_map.is_empty(), "no signatures for v5 solid file");
    assert_eq!(results.file_map[0].offset, 0);
}

/// Extracting the same archive twice to different directories must both succeed
/// (no shared mutable state between runs).
#[test]
fn v3_extraction_is_idempotent() {
    for _ in 0..2 {
        let output_dir = tempfile::tempdir().unwrap();
        let results = run_rar_binwalk("testfile.rar3.rar", output_dir.path());
        let mut succeeded = false;
        for ext in results.extractions.values() {
            assert!(ext.success, "extraction failed on repeated run");
            let p = Path::new(&ext.output_directory).join("testfile.txt");
            assert!(p.exists(), "testfile.txt missing on repeated run");
            assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
            succeeded = true;
        }
        assert!(succeeded, "no extractions on repeated run");
    }
}

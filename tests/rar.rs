mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

const TESTFILE_TXT: &[u8] = b"Testing 123\n";

// ── Helpers ──────────────────────────────────────────────────────────

/// Smoke test for .rar / .cbr files where RAR magic is at offset 0.
#[track_caller]
fn smoke_rar(input: &str) {
    common::integration_test("rar", input);
}

/// Smoke test + content verification for SFX files (RAR at non-zero offset).
fn smoke_sfx(input: &str) {
    let path = Path::new("tests").join("inputs").join(input);
    let output_dir = tempfile::tempdir().unwrap();

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
        !results.file_map.is_empty(),
        "SFX '{}': no signatures found",
        input
    );

    for ext in results.extractions.values() {
        assert!(ext.success, "SFX '{}': extraction failed", input);
    }

    // Verify content for the first successful extraction
    for ext in results.extractions.values() {
        if ext.success {
            let root = &ext.output_directory;

            let p = root.join("testfile.txt");
            assert!(p.exists(), "SFX '{}': missing testfile.txt", input);
            assert_eq!(&fs::read(&p).unwrap(), TESTFILE_TXT);

            let p = root.join("acknow.txt");
            assert!(p.exists(), "SFX '{}': missing acknowledg.txt", input);
            assert!(
                !fs::read(&p).unwrap().is_empty(),
                "SFX '{}': acknowledg.txt is empty",
                input
            );

            return;
        }
    }
    panic!("SFX '{}': no successful extraction", input);
}

/// Extract and verify file contents for a RAR archive.
fn extract_and_check(
    input: &str,
    expected: &[(&str, &[u8])],
    description: &str,
) {
    let path = Path::new("tests").join("inputs").join(input);
    let output_dir = tempfile::tempdir().unwrap();

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

    assert!(!results.file_map.is_empty(), "{}: no signatures", description);

    for ext in results.extractions.values() {
        assert!(ext.success, "{}: extraction failed", description);
    }

    for ext in results.extractions.values() {
        if ext.success {
            let root = &ext.output_directory;
            for (name, content) in expected {
                let p = root.join(name);
                assert!(p.exists(), "{}: missing '{}'", description, name);
                assert_eq!(&fs::read(&p).unwrap(), content);
            }
            return;
        }
    }
    panic!("{}: no successful extraction", description);
}

// ── RAR v3 smoke tests (offset 0) ────────────────────────────────────

#[test]
fn v3_rar() {
    smoke_rar("testfile.rar3.rar");
}
#[test]
fn v3_locked_rar() {
    smoke_rar("testfile.rar3.locked.rar");
}
#[test]
fn v3_solid_rar() {
    smoke_rar("testfile.rar3.solid.rar");
}
#[test]
fn v3_av_rar() {
    smoke_rar("testfile.rar3.av.rar");
}
#[test]
fn v3_rr_rar() {
    smoke_rar("testfile.rar3.rr.rar");
}

// ── RAR v5 smoke tests (offset 0) ────────────────────────────────────

#[test]
fn v5_rar() {
    smoke_rar("testfile.rar5.rar");
}
#[test]
fn v5_locked_rar() {
    smoke_rar("testfile.rar5.locked.rar");
}
#[test]
fn v5_solid_rar() {
    smoke_rar("testfile.rar5.solid.rar");
}
#[test]
fn v5_rr_rar() {
    smoke_rar("testfile.rar5.rr.rar");
}

// ── CBR v3 smoke tests (offset 0) ────────────────────────────────────

#[test]
fn v3_cbr() {
    smoke_rar("testfile.rar3.cbr");
}
#[test]
fn v3_locked_cbr() {
    smoke_rar("testfile.rar3.locked.cbr");
}
#[test]
fn v3_solid_cbr() {
    smoke_rar("testfile.rar3.solid.cbr");
}
#[test]
fn v3_av_cbr() {
    smoke_rar("testfile.rar3.av.cbr");
}
#[test]
fn v3_rr_cbr() {
    smoke_rar("testfile.rar3.rr.cbr");
}

// ── CBR v5 smoke tests (offset 0) ────────────────────────────────────

#[test]
fn v5_cbr() {
    smoke_rar("testfile.rar5.cbr");
}
#[test]
fn v5_locked_cbr() {
    smoke_rar("testfile.rar5.locked.cbr");
}
#[test]
fn v5_solid_cbr() {
    smoke_rar("testfile.rar5.solid.cbr");
}
#[test]
fn v5_rr_cbr() {
    smoke_rar("testfile.rar5.rr.cbr");
}

// ── SFX tests (RAR at non-zero offset) ───────────────────────────────

#[test]
fn sfx_v3_dos() {
    smoke_sfx("testfile.rar3.dos_sfx.exe");
}
#[test]
fn sfx_v3_wincon() {
    smoke_sfx("testfile.rar3.wincon.sfx.exe");
}
#[test]
fn sfx_v3_wingui() {
    smoke_sfx("testfile.rar3.wingui.sfx.exe");
}
#[test]
fn sfx_v5_wincon() {
    smoke_sfx("testfile.rar5.wincon.sfx.exe");
}
#[test]
fn sfx_v5_wingui() {
    smoke_sfx("testfile.rar5.wingui.sfx.exe");
}
#[test]
fn sfx_v5_linux() {
    smoke_sfx("testfile.rar5.linux_sfx.bin");
}

// ── Content-verification for RAR files ────────────────────────────────

#[test]
fn check_v3_rar() {
    extract_and_check("testfile.rar3.rar", &[("testfile.txt", TESTFILE_TXT)], "v3.rar");
}
#[test]
fn check_v3_locked_rar() {
    extract_and_check(
        "testfile.rar3.locked.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v3.locked.rar",
    );
}
#[test]
fn check_v3_solid_rar() {
    extract_and_check(
        "testfile.rar3.solid.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v3.solid.rar",
    );
}
#[test]
fn check_v3_av_rar() {
    extract_and_check(
        "testfile.rar3.av.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v3.av.rar",
    );
}
#[test]
fn check_v3_rr_rar() {
    extract_and_check(
        "testfile.rar3.rr.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v3.rr.rar",
    );
}
#[test]
fn check_v5_rar() {
    extract_and_check("testfile.rar5.rar", &[("testfile.txt", TESTFILE_TXT)], "v5.rar");
}
#[test]
fn check_v5_locked_rar() {
    extract_and_check(
        "testfile.rar5.locked.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v5.locked.rar",
    );
}
#[test]
fn check_v5_solid_rar() {
    extract_and_check(
        "testfile.rar5.solid.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v5.solid.rar",
    );
}
#[test]
fn check_v5_rr_rar() {
    extract_and_check(
        "testfile.rar5.rr.rar",
        &[("testfile.txt", TESTFILE_TXT)],
        "v5.rr.rar",
    );
}

// ── Content-verification for CBR files (store images) ────────────────

const JPG_SIZE: usize = 220;
const PNG_SIZE: usize = 87;

#[test]
fn check_v3_cbr() {
    extract_and_check_sizes("testfile.rar3.cbr", "v3.cbr");
}
#[test]
fn check_v3_locked_cbr() {
    extract_and_check_sizes("testfile.rar3.locked.cbr", "v3.locked.cbr");
}
#[test]
fn check_v3_solid_cbr() {
    extract_and_check_sizes("testfile.rar3.solid.cbr", "v3.solid.cbr");
}
#[test]
fn check_v3_av_cbr() {
    extract_and_check_sizes("testfile.rar3.av.cbr", "v3.av.cbr");
}
#[test]
fn check_v3_rr_cbr() {
    extract_and_check_sizes("testfile.rar3.rr.cbr", "v3.rr.cbr");
}
#[test]
fn check_v5_cbr() {
    extract_and_check_sizes("testfile.rar5.cbr", "v5.cbr");
}
#[test]
fn check_v5_locked_cbr() {
    extract_and_check_sizes("testfile.rar5.locked.cbr", "v5.locked.cbr");
}
#[test]
fn check_v5_solid_cbr() {
    extract_and_check_sizes("testfile.rar5.solid.cbr", "v5.solid.cbr");
}
#[test]
fn check_v5_rr_cbr() {
    extract_and_check_sizes("testfile.rar5.rr.cbr", "v5.rr.cbr");
}

fn extract_and_check_sizes(input: &str, description: &str) {
    let path = Path::new("tests").join("inputs").join(input);
    let output_dir = tempfile::tempdir().unwrap();

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

    assert!(!results.file_map.is_empty(), "{}: no signatures", description);

    for ext in results.extractions.values() {
        assert!(ext.success, "{}: extraction failed", description);
    }

    for ext in results.extractions.values() {
        if ext.success {
            let root = &ext.output_directory;
            for (name, expected_size, first_bytes) in &[
                ("testfile.jpg", JPG_SIZE, &b"\xFF\xD8\xFF\xE0"[..]),
                ("testfile.png", PNG_SIZE, &[0x89, 0x50, 0x4E, 0x47][..]),
            ] {
                let p = root.join(name);
                assert!(p.exists(), "{}: missing '{}'", description, name);
                let data = fs::read(&p).unwrap();
                assert_eq!(
                    data.len(),
                    *expected_size,
                    "{}: '{}' size mismatch",
                    description,
                    name
                );
                assert!(
                    data.starts_with(first_bytes),
                    "{}: '{}' wrong signature",
                    description,
                    name
                );
            }
            return;
        }
    }
    panic!("{}: no successful extraction", description);
}

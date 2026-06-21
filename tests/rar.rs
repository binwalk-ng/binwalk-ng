mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

const TESTFILE_TXT: &[u8] = b"Testing 123\n";

// ── Helpers ──────────────────────────────────────────────────────────

#[track_caller]
fn smoke_rar(input: &str) {
    common::integration_test("rar", input);
}

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

fn smoke_sfx(input: &str) {
    extract_and_verify(input, |root| {
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
    });
}

// ── Content-verification for RAR files ────────────────────────────────

macro_rules! check_rar_tests {
    ($($name:ident => $file:literal,)*) => {
        $(
            #[test]
            fn $name() {
                extract_and_verify($file, |root| {
                    let p = root.join("testfile.txt");
                    assert!(p.exists(), "missing testfile.txt in {}", $file);
                    assert_eq!(fs::read(&p).unwrap(), TESTFILE_TXT);
                });
            }
        )*
    }
}

check_rar_tests! {
    check_v3_rar => "testfile.rar3.rar",
    check_v3_locked_rar => "testfile.rar3.locked.rar",
    check_v3_solid_rar => "testfile.rar3.solid.rar",
    check_v3_av_rar => "testfile.rar3.av.rar",
    check_v3_rr_rar => "testfile.rar3.rr.rar",
    check_v5_rar => "testfile.rar5.rar",
    check_v5_locked_rar => "testfile.rar5.locked.rar",
    check_v5_solid_rar => "testfile.rar5.solid.rar",
    check_v5_rr_rar => "testfile.rar5.rr.rar",
}

// ── Content-verification for CBR files (store images) ────────────────

const JPG_SIZE: usize = 220;
const PNG_SIZE: usize = 87;

macro_rules! check_cbr_tests {
    ($($name:ident => $file:literal,)*) => {
        $(
            #[test]
            fn $name() {
                extract_and_verify($file, |root| {
                    for (name, expected_size, magic) in &[
                        ("testfile.jpg", JPG_SIZE, &b"\xFF\xD8\xFF\xE0"[..]),
                        ("testfile.png", PNG_SIZE, &[0x89, 0x50, 0x4E, 0x47][..]),
                    ] {
                        let p = root.join(name);
                        assert!(p.exists(), "missing '{}' in {}", name, $file);
                        let data = fs::read(&p).unwrap();
                        assert_eq!(
                            data.len(), *expected_size,
                            "'{}' size mismatch in {}", name, $file
                        );
                        assert!(
                            data.starts_with(magic),
                            "'{}' wrong signature in {}", name, $file
                        );
                    }
                });
            }
        )*
    }
}

check_cbr_tests! {
    check_v3_cbr => "testfile.rar3.cbr",
    check_v3_locked_cbr => "testfile.rar3.locked.cbr",
    check_v3_solid_cbr => "testfile.rar3.solid.cbr",
    check_v3_av_cbr => "testfile.rar3.av.cbr",
    check_v3_rr_cbr => "testfile.rar3.rr.cbr",
    check_v5_cbr => "testfile.rar5.cbr",
    check_v5_locked_cbr => "testfile.rar5.locked.cbr",
    check_v5_solid_cbr => "testfile.rar5.solid.cbr",
    check_v5_rr_cbr => "testfile.rar5.rr.cbr",
}

mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

/// The original content used to generate lzop.bin and lzop_highcomp.bin.
const DECOMPRESSED_REFERENCE: &str = "tests/inputs/lzop_std.txt";

// ── Standard detection + extraction tests ────────────────────────────

/// Multi-block LZOP detected at offset 0 and extractable (level 1).
#[test]
fn standard_extraction() {
    common::integration_test("lzop", "lzop.bin");
}

/// Single-block LZOP (small input) detected and extractable.
#[test]
fn single_block_file() {
    common::integration_test("lzop", "lzop_single.bin");
}

/// High-compression level 9 file.
#[test]
fn high_compression() {
    common::integration_test("lzop", "lzop_highcomp.bin");
}

/// LZOP with no original filename stored (lzop -n).
#[test]
fn no_name_file() {
    let results = common::run_binwalk("lzop", "lzop_noname.bin");
    assert_eq!(results.file_map.len(), 1);
    assert!(results.extractions.values().all(|e| e.success));
}

/// LZOP with original path stored (lzop -P).
#[test]
fn with_path_file() {
    let results = common::run_binwalk("lzop", "lzop_withpath.bin");
    assert_eq!(results.file_map.len(), 1);
    assert!(results.extractions.values().all(|e| e.success));
}

/// LZOP with a very long (255 char) original filename.
#[test]
fn long_filename() {
    let results = common::run_binwalk("lzop", "lzop_longname.bin");
    assert_eq!(results.file_map.len(), 1);
    assert!(results.extractions.values().all(|e| e.success));
}

/// LZOP compressing a file with .bin suffix.
#[test]
fn dot_bin_suffix() {
    common::integration_test("lzop", "lzop_dotbin.bin");
}

/// LZOP with CRC32 checksums (lzop --crc32).
#[test]
fn crc32_checksums() {
    common::integration_test("lzop", "lzop_crc32.bin");
}

// ── Edge cases ───────────────────────────────────────────────────────

/// Trailing garbage after the LZOP blocks must not break extraction.
#[test]
fn trailing_data() {
    common::trailing_data_test("lzop", "lzop.bin");
}

/// LZOP with empty uncompressed content has no data blocks,
/// so the parser cannot validate it.
#[test]
fn empty_content_rejected() {
    let results = common::run_binwalk("lzop", "lzop_empty.bin");
    assert!(results.file_map.is_empty());
}

// ── Negative / rejection tests ───────────────────────────────────────

/// Random bytes produce no false-positive LZOP match.
#[test]
fn negative_random() {
    let random_data: Vec<u8> = (0..1024).map(|i| (i & 0xFF) as u8).collect();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp.as_file(), &random_data).unwrap();
    let results = run_binwalk_path("lzop", tmp.path());
    assert!(results.file_map.is_empty());
}

/// Corrupted version field (> LZO_MAX_VERSION = 0x1040) is rejected.
#[test]
fn corrupted_header_rejected() {
    let mut raw = read_test_file("lzop.bin");
    raw[9] = 0xFF;
    raw[10] = 0xFF;
    let results = run_binwalk_data("lzop", &raw);
    assert!(results.file_map.is_empty());
}

/// Corrupted magic bytes (first byte changed) is rejected.
#[test]
fn bad_magic_rejected() {
    let mut raw = read_test_file("lzop.bin");
    raw[0] ^= 0x01;
    let results = run_binwalk_data("lzop", &raw);
    assert!(results.file_map.is_empty());
}

/// Truncated LZOP data (missing blocks) is rejected.
#[test]
fn truncated_rejected() {
    let raw = read_test_file("lzop.bin");
    // Keep only the header, cut off before the first block.
    let header_only = &raw[..59];
    let results = run_binwalk_data("lzop", header_only);
    assert!(results.file_map.is_empty());
}

// ── Content verification ─────────────────────────────────────────────

#[test]
fn extraction_verification() {
    let expected = fs::read(DECOMPRESSED_REFERENCE).unwrap();
    extract_and_verify("lzop.bin", |root| {
        let extracted = root.join("lzop_std.txt");
        assert!(extracted.exists(), "extracted file not found");
        assert_eq!(fs::read(&extracted).unwrap(), expected);
    });
}

// ── Description / metadata checks ────────────────────────────────────

#[track_caller]
fn check_description(input: &str, expected_prefix: &str) {
    let results = common::run_binwalk("lzop", input);
    assert_eq!(results.file_map.len(), 1);
    let desc = &results.file_map[0].description;
    assert!(
        desc.starts_with(expected_prefix),
        "expected description starting with '{expected_prefix}', got '{desc}'"
    );
}

#[test]
fn description_contains_lzo() {
    check_description("lzop.bin", "LZO compressed data, total size:");
}

#[test]
fn description_contains_total_size() {
    let results = common::run_binwalk("lzop", "lzop.bin");
    let desc = &results.file_map[0].description;
    let reported_size = results.file_map[0].size;
    assert!(desc.contains(&format!("{} bytes", reported_size)));
    assert_eq!(reported_size, results.file_map[0].size);
}

// ── Helpers ──────────────────────────────────────────────────────────

fn read_test_file(name: &str) -> Vec<u8> {
    let path = Path::new("tests").join("inputs").join(name);
    fs::read(&path).unwrap()
}

fn run_binwalk_path(signature_filter: &str, file_path: &Path) -> binwalk_ng::AnalysisResults {
    let output_dir = tempfile::tempdir().unwrap();
    let binwalker = Binwalk::configure(
        Some(file_path),
        Some(output_dir.as_ref()),
        vec![signature_filter.to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");
    binwalker.analyze(&binwalker.base_target_file, true)
}

fn run_binwalk_data(signature_filter: &str, data: &[u8]) -> binwalk_ng::AnalysisResults {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp.as_file(), data).unwrap();
    run_binwalk_path(signature_filter, tmp.path())
}

#[track_caller]
fn extract_and_verify(input: &str, checker: impl Fn(&Path)) {
    let output_dir = tempfile::tempdir().unwrap();
    let path = Path::new("tests").join("inputs").join(input);
    let binwalker = Binwalk::configure(
        Some(&path),
        Some(output_dir.as_ref()),
        vec!["lzop".to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");
    let results = binwalker.analyze(&binwalker.base_target_file, true);

    assert!(!results.file_map.is_empty(), "'{}': no signatures", input);

    let mut any_success = false;
    for ext in results.extractions.values() {
        assert!(ext.success, "'{}': extraction failed", input);
        checker(&ext.output_directory);
        any_success = true;
    }
    assert!(any_success, "'{}': no successful extraction", input);
}

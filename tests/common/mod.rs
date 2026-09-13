//! Shared helpers for `tests/*.rs` integration tests.
//! Every test crate compiles this module separately, so not every crate uses
//! every helper.
#![allow(dead_code)]

use std::panic::Location;
use std::path::{Path, PathBuf};

use binwalk_ng::extractors::ExtractionResult;
use binwalk_ng::{AnalysisResults, Binwalk};

/// Directory inside the samples submodule that holds the fixture files.
/// Checked out at `tests/testdata` (see .gitmodules), files live under
/// `testdata/samples/` (the submodule's own `samples/` output directory).
pub const SAMPLES_DIR: &str = "tests/testdata/samples";

pub fn sample_path(file_name: impl AsRef<Path>) -> PathBuf {
    Path::new(SAMPLES_DIR).join(file_name)
}

/// The shared payload text used by the samples generator
/// (`scripts/data/extraction_reference.txt` in the samples repo). Every
/// archive/filesystem sample stores exactly these bytes as `readme.txt`,
/// so extraction tests can assert exact contents without re-vendoring data.
pub fn reference_payload() -> Vec<u8> {
    std::fs::read(
        Path::new("tests")
            .join("testdata")
            .join("scripts")
            .join("data")
            .join("extraction_reference.txt"),
    )
    .unwrap()
}

/// Convenience function for running an integration test against the specified file, with the provided signature filter.
/// Assumes that there will be one signature result and one extraction result at file offset 0.
#[track_caller]
pub fn integration_test(signature_filter: &str, file_name: &str) {
    let expected_signature_offsets: Vec<usize> = vec![0];
    let expected_extraction_offsets: Vec<usize> = vec![0];

    // Run binwalk, get analysis/extraction results
    let results = run_binwalk(signature_filter, file_name);

    // Assert that there was a valid signature and successful result at, and only at, file offset 0
    assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}

/// Assert that there was a valid signature match and corresponding extraction at, and only at, the specified file offsets
#[track_caller]
pub fn assert_results_ok(
    results: AnalysisResults,
    signature_offsets: Vec<usize>,
    extraction_offsets: Vec<usize>,
) {
    let caller_loc = Location::caller();
    let base = format!(
        "{}-{}-{}",
        caller_loc.file(),
        caller_loc.line(),
        caller_loc.column()
    );
    insta::assert_yaml_snapshot!(format!("{base}_file_map"), results.file_map, {
        "[].id" => "[uuid]",
    });

    let ordered_extractions: Vec<Option<&ExtractionResult>> = results
        .file_map
        .iter()
        .map(|extraction_result| results.extractions.get(&extraction_result.id))
        .collect();
    insta::assert_yaml_snapshot!(format!("{base}_ordered_extractions"), ordered_extractions, {
        "[].output_directory" => "[output_directory]",
    });

    // Assert that the number of signature results and extractions match the expected results
    assert_eq!(results.file_map.len(), signature_offsets.len());
    assert_eq!(results.extractions.len(), extraction_offsets.len());

    // Assert that each signature match was at an expected offset and that extraction, if expected, was successful
    for signature_result in &results.file_map {
        assert!(signature_offsets.contains(&signature_result.offset));
        if extraction_offsets.contains(&signature_result.offset) {
            assert!(results.extractions[&signature_result.id].success);
        }
    }
}

/// Run Binwalk, with extraction, against the specified file data with trailing garbage appended.
/// This verifies that extractors properly bound decompression to the parsed range.
pub fn trailing_data_test(signature_filter: &str, file_name: &str) {
    let mut data = std::fs::read(sample_path(file_name)).unwrap();
    data.extend_from_slice(b"TRAILING GARBAGE DATA THAT SHOULD BE IGNORED");

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, &data).unwrap();

    let output_directory = tempfile::tempdir().unwrap();
    let binwalker = Binwalk::builder()
        .include(signature_filter)
        .build()
        .expect("Binwalk initialization failed");

    let results = binwalker.analyze(tmp.path(), Some(output_directory.path()));

    // Assert that there was a valid signature and successful extraction at offset 0
    assert_eq!(results.file_map.len(), 1, "expected one signature result");
    assert_eq!(
        results.extractions.len(),
        1,
        "expected one extraction result"
    );
    let sig = &results.file_map[0];
    assert_eq!(sig.offset, 0);
    assert!(
        results.extractions[&sig.id].success,
        "extraction should succeed despite trailing garbage"
    );
}

/// Run Binwalk, with extraction, against the specified file, with the provided signature filter
pub fn run_binwalk(signature_filter: &str, file_name: impl AsRef<Path>) -> AnalysisResults {
    // Build the path to the input file
    let file_path = sample_path(file_name);

    let output_directory = tempfile::tempdir().unwrap();

    // Configure binwalk
    let binwalker = Binwalk::builder()
        .include(signature_filter)
        .build()
        .expect("Binwalk initialization failed");

    binwalker.analyze(&file_path, Some(output_directory.path()))
}

/// Run Binwalk with extraction and check the extracted tree with `checker`.
///
/// Unlike `run_binwalk` (whose tempdir is dropped before returning), the output
/// directory lives for the duration of the check, so extracted file contents
/// can be asserted. Asserts at least one signature and one successful extraction.
#[track_caller]
pub fn extract_and_verify(
    signature_filter: &str,
    file_name: impl AsRef<Path>,
    checker: impl Fn(&Path),
) {
    let file_path = sample_path(file_name);
    let display = file_path.display().to_string();
    let output_dir = tempfile::tempdir().unwrap();

    let binwalker = Binwalk::builder()
        .include(signature_filter)
        .build()
        .expect("Binwalk initialization failed");
    let results = binwalker.analyze(&file_path, Some(output_dir.path()));

    assert!(!results.file_map.is_empty(), "'{display}': no signatures");

    let mut any_success = false;
    for ext in results.extractions.values() {
        assert!(ext.success, "'{display}': extraction failed");
        checker(&ext.output_directory);
        any_success = true;
    }
    assert!(any_success, "'{display}': no successful extraction");
}

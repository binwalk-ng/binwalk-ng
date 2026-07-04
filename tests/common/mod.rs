use std::panic::Location;
use std::path::Path;

use binwalk_ng::extractors::ExtractionResult;
use binwalk_ng::{AnalysisResults, Binwalk};

/// Convenience function for running an integration test against the specified file, with the provided signature filter.
/// Assumes that there will be one signature result and one extraction result at file offset 0.
#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn trailing_data_test(signature_filter: &str, file_name: &str) {
    let mut data = std::fs::read(Path::new("tests").join("inputs").join(file_name)).unwrap();
    data.extend_from_slice(b"TRAILING GARBAGE DATA THAT SHOULD BE IGNORED");

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, &data).unwrap();

    let output_directory = tempfile::tempdir().unwrap();
    let binwalker = Binwalk::configure(
        Some(tmp.path()),
        Some(output_directory.as_ref()),
        vec![signature_filter.to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");

    let results = binwalker.analyze(&binwalker.base_target_file, true);

    // Assert that there was a valid signature and successful extraction at offset 0
    assert_eq!(results.file_map.len(), 1, "expected one signature result");
    assert_eq!(results.extractions.len(), 1, "expected one extraction result");
    let sig = &results.file_map[0];
    assert_eq!(sig.offset, 0);
    assert!(results.extractions[&sig.id].success, "extraction should succeed despite trailing garbage");
}

/// Run Binwalk, with extraction, against the specified file, with the provided signature filter
pub fn run_binwalk(signature_filter: &str, file_name: impl AsRef<Path>) -> AnalysisResults {
    // Build the path to the input file
    let file_path = Path::new("tests").join("inputs").join(file_name);

    let output_directory = tempfile::tempdir().unwrap();

    // Configure binwalk
    let binwalker = Binwalk::configure(
        Some(file_path.as_path()),
        Some(output_directory.as_ref()),
        vec![signature_filter.to_string()],
        vec![],
        None,
        false,
    )
    .expect("Binwalk initialization failed");

    binwalker.analyze(&binwalker.base_target_file, true)
}

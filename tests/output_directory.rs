//! Guards that all output lands in the requested output directory, and that nothing is
//! ever written beside the input file the user pointed binwalk at.
//!
//! These drive the real CLI binary rather than the library: the extraction output
//! directory, matryoshka recursion, and data carving are all wired up in main.rs.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Copy the gzip test input into its own directory, so that anything written next to it
/// is unambiguously output that leaked out of the extraction directory.
///
/// gzip's extractor is internal, so these tests need no external extraction utilities.
fn stage_input(source_directory: &Path) {
    fs::copy(
        Path::new("tests").join("inputs").join("gzip.bin"),
        source_directory.join("gzip.bin"),
    )
    .expect("failed to stage gzip.bin");
}

fn sorted_file_names(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(directory)
        .expect("failed to read directory")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Run binwalk with extraction, carving and matryoshka recursion all enabled.
fn run_binwalk(working_directory: &Path, input: &Path, output_directory: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_binwalk"))
        .args(["-q", "-M", "-e", "-c", "-d"])
        .arg(output_directory)
        .arg(input)
        .current_dir(working_directory)
        // The dev container sets this, which would delete the symlink mid-test
        .env_remove("BINWALK_RM_EXTRACTION_SYMLINK")
        .status()
        .expect("failed to run binwalk");

    assert!(status.success(), "binwalk exited with {status}");
}

/// Everything the run produces must be inside the output directory.
fn assert_output_in_directory(source_directory: &Path, output_directory: &Path) {
    assert_eq!(
        sorted_file_names(source_directory),
        ["gzip.bin"],
        "binwalk wrote output beside the input file, in {}",
        source_directory.display()
    );

    let extracted = output_directory
        .join("gzip.bin.extracted")
        .join("0")
        .join("decompressed.bin");
    assert!(
        extracted.exists(),
        "expected extracted file was not created: {}",
        extracted.display()
    );

    let carved = output_directory.join("gzip.bin_0_gzip.raw");
    assert!(
        carved.exists(),
        "expected carved file was not created: {}",
        carved.display()
    );
}

#[test]
fn absolute_input_writes_only_to_the_output_directory() {
    let source_directory = tempfile::tempdir().unwrap();
    let output_directory = tempfile::tempdir().unwrap();
    stage_input(source_directory.path());

    run_binwalk(
        source_directory.path(),
        &source_directory.path().join("gzip.bin"),
        output_directory.path(),
    );

    assert_output_in_directory(source_directory.path(), output_directory.path());
}

/// A relative input path must behave identically. The whole-file carve optimization
/// symlinks the input into the extraction directory, so a path that is not resolved up
/// front produces a dangling symlink and no extraction at all.
#[test]
fn relative_input_writes_only_to_the_output_directory() {
    let source_directory = tempfile::tempdir().unwrap();
    let output_directory = tempfile::tempdir().unwrap();
    stage_input(source_directory.path());

    run_binwalk(
        source_directory.path(),
        Path::new("gzip.bin"),
        output_directory.path(),
    );

    assert_output_in_directory(source_directory.path(), output_directory.path());
}

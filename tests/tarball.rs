mod common;

use std::fs;
use std::path::Path;

use binwalk_ng::Binwalk;

/// Signature + extraction smoke test: exactly one tarball signature is detected at
/// offset 0, and its extraction reports success.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "tarball";
    const INPUT_FILE_NAME: &str = "tarball.archive.tar";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

/// End-to-end extraction test that pins the extracted file tree *and* its contents.
///
/// This is the regression guard for swapping out the external `tar` extractor: it
/// asserts that whichever extractor is wired up reproduces exactly the layout and
/// byte-for-byte contents that the fixture was built from. The fixture is the
/// samples repo's `tarball.archive.tar` (see its generate_samples.py); the
/// expected tree/contents below stay in sync with that generator's "tree".
#[test]
fn extraction_produces_expected_files() {
    // Expected archive layout and contents -- kept in sync with the samples
    // repo's generate_samples.py (tar --sort=name --mtime=@0 over its "tree").
    let expected: [(&str, Vec<u8>); 3] = [
        ("readme.txt", common::reference_payload()),
        ("docs/notes.txt", b"documentation\n".repeat(50)),
        ("subdir/payload.bin", vec![0xAB; 256]),
    ];

    // Bind the output directory in this scope so it lives until the assertions are
    // done. (The common::run_binwalk helper drops its tempdir before returning,
    // which would delete the extracted files we want to inspect.)
    let output_directory = tempfile::tempdir().unwrap();
    let input_path = Path::new(common::SAMPLES_DIR).join("tarball.archive.tar");

    let binwalker = Binwalk::builder()
        .include("tarball")
        .build()
        .expect("Binwalk initialization failed");

    let results = binwalker.analyze(&input_path, Some(output_directory.path()));

    // Exactly one signature and one successful extraction.
    assert_eq!(results.file_map.len(), 1);
    assert_eq!(results.extractions.len(), 1);

    let extraction = results
        .extractions
        .values()
        .next()
        .expect("missing extraction result");
    assert!(extraction.success, "tarball extraction did not succeed");

    // The extractor unpacks archive-relative paths into its output directory.
    let root = &extraction.output_directory;

    for (relative_path, expected_contents) in expected {
        let path = root.join(relative_path);
        assert!(
            path.exists(),
            "expected extracted file was not created: {}",
            path.display()
        );
        let actual_contents = fs::read(&path).unwrap();
        assert_eq!(
            actual_contents,
            expected_contents,
            "contents mismatch for extracted file {}",
            path.display()
        );
    }

    // The explicit directory entry must be extracted as a directory.
    let subdir = root.join("subdir");
    assert!(
        subdir.is_dir(),
        "expected extracted directory was not created: {}",
        subdir.display()
    );

    // The symlink entry must be extracted as a symlink whose target is rewritten to a
    // chroot-contained *relative* path (never host-absolute), so it stays inside the
    // extraction tree and reading through it resolves to readme.txt.
    let symlink = root.join("link.txt");
    let link_metadata =
        fs::symlink_metadata(&symlink).expect("expected symlink link.txt was not extracted");
    assert!(
        link_metadata.file_type().is_symlink(),
        "expected {} to be a symlink",
        symlink.display()
    );
    let link_target = fs::read_link(&symlink).unwrap();
    assert!(
        link_target.is_relative(),
        "symlink target {link_target:?} must be relative (chroot-contained)"
    );
    // Relative alone is not containment: a crafted "../../outside/readme.txt" would
    // still be relative yet escape the extraction root. Resolve the symlink and pin
    // the real location inside it.
    let canonical_root = fs::canonicalize(root).unwrap();
    let resolved = fs::canonicalize(&symlink).unwrap();
    assert!(
        resolved.starts_with(&canonical_root),
        "symlink {} resolves to {}, outside the extraction root {}",
        symlink.display(),
        resolved.display(),
        canonical_root.display()
    );
    assert_eq!(
        fs::read(&symlink).unwrap(),
        common::reference_payload(),
        "symlink {} did not resolve to readme.txt within the extraction tree",
        symlink.display()
    );

    // The extractor must preserve the archived Unix mode: the executable file keeps its
    // execute bits and the directory keeps its sticky bit. (Ownership/uid+gid is
    // best-effort and only applies when extracting as root, so it isn't asserted here.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let script_mode = fs::metadata(root.join("run.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            script_mode & 0o777,
            0o755,
            "executable bits not preserved on run.sh (mode {script_mode:#o})"
        );

        let subdir_mode = fs::metadata(&subdir).unwrap().permissions().mode();
        assert_eq!(
            subdir_mode & 0o1000,
            0o1000,
            "sticky bit not preserved on subdir (mode {subdir_mode:#o})"
        );
    }
}

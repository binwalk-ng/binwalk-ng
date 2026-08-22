mod common;

use std::fs;
use std::path::{Path, PathBuf};

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

/// Recursively collects every path under `dir` (files, directories, symlinks;
/// symlinked directories are not followed).
#[allow(dead_code)]
fn walk_paths(dir: &Path, collected: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        collected.push(path.clone());
        if is_dir {
            walk_paths(&path, collected);
        }
    }
}

/// Appends one raw tar entry, bypassing the tar crate's Builder sanitization
/// (which refuses absolute member names and `..` components). This lets the
/// test craft entries exactly as an attacker would.
fn append_tar_entry(
    builder: &mut tar::Builder<Vec<u8>>,
    name: &str,
    entry_type: tar::EntryType,
    data: &[u8],
    link_name: Option<&str>,
) {
    let mut header = tar::Header::new_gnu();
    {
        let gnu = header.as_gnu_mut().expect("GNU header representation");
        let bytes = name.as_bytes();
        assert!(bytes.len() <= gnu.name.len(), "entry name too long: {name}");
        gnu.name[..bytes.len()].copy_from_slice(bytes);
        if let Some(link) = link_name {
            let link_bytes = link.as_bytes();
            assert!(
                link_bytes.len() <= gnu.linkname.len(),
                "link name too long: {link}"
            );
            gnu.linkname[..link_bytes.len()].copy_from_slice(link_bytes);
        }
    }
    header.set_entry_type(entry_type);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(data.len() as u64);
    // Checksum last: it covers every field mutated above.
    header.set_cksum();
    builder.append(&header, data).expect("append tar entry");
}

/// Lexically resolves `link_path`'s stored target relative to the link's own
/// directory and reports whether it stays inside `root` (never climbing above
/// it). Purely lexical: unlike `fs::canonicalize`, this also works for links
/// whose rewritten targets dangle inside the extraction root.
#[allow(dead_code)]
fn symlink_target_stays_within(root: &Path, link_path: &Path) -> bool {
    let Ok(target) = fs::read_link(link_path) else {
        return false;
    };
    if target.is_absolute() {
        return false;
    }
    let base = link_path.parent().unwrap_or_else(|| Path::new("/"));
    let Ok(relative_base) = base.strip_prefix(root) else {
        return false;
    };
    let mut depth = relative_base.components().count();
    for component in target.components() {
        match component {
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::ParentDir => match depth.checked_sub(1) {
                Some(new_depth) => depth = new_depth,
                None => return false,
            },
            _ => return false,
        }
    }
    true
}

/// End-to-end containment test with a hostile archive crafted in memory:
/// traversal and absolute member names, escaping symlink targets, a hardlink,
/// and a fifo. Nothing may be written outside the extraction directory, hostile
/// symlinks must never resolve to host files, and the benign sibling entries
/// must still be extracted.
#[test]
fn extraction_contains_hostile_entries() {
    let payload = common::reference_payload();

    // Entry order matters only in that the benign file comes first, proving the
    // hostile entries neither abort nor corrupt the rest of the extraction.
    let mut builder = tar::Builder::new(Vec::new());
    append_tar_entry(
        &mut builder,
        "benign.txt",
        tar::EntryType::Regular,
        &payload,
        None,
    );
    append_tar_entry(
        &mut builder,
        "../evil.txt",
        tar::EntryType::Regular,
        b"escaped?",
        None,
    );
    append_tar_entry(
        &mut builder,
        "/tmp/abs_evil.txt",
        tar::EntryType::Regular,
        b"escaped?",
        None,
    );
    append_tar_entry(
        &mut builder,
        "rel_escape",
        tar::EntryType::Symlink,
        b"",
        Some("../../outside_readme.txt"),
    );
    append_tar_entry(
        &mut builder,
        "abs_escape",
        tar::EntryType::Symlink,
        b"",
        Some("/etc/passwd"),
    );
    append_tar_entry(
        &mut builder,
        "hardlink.txt",
        tar::EntryType::Link,
        b"",
        Some("benign.txt"),
    );
    append_tar_entry(&mut builder, "pipe.fifo", tar::EntryType::Fifo, b"", None);
    let archive = builder.into_inner().unwrap();

    let input = tempfile::NamedTempFile::new().unwrap();
    fs::write(input.path(), &archive).unwrap();

    // The extraction directory is nested inside an owned scratch directory, so
    // anything that escapes lands somewhere we can inspect deterministically.
    let scratch = tempfile::tempdir().unwrap();
    let output_directory = tempfile::tempdir_in(scratch.path()).unwrap();

    let binwalker = Binwalk::builder()
        .include("tarball")
        .build()
        .expect("Binwalk initialization failed");
    let results = binwalker.analyze(input.path(), Some(output_directory.path()));

    // One signature at offset 0; extraction succeeds despite the hostile entries.
    assert_eq!(results.file_map.len(), 1);
    assert_eq!(results.file_map[0].offset, 0);
    assert_eq!(results.extractions.len(), 1);
    let extraction = results.extractions.values().next().unwrap();
    assert!(
        extraction.success,
        "hostile entries must not fail extraction"
    );

    // Containment: every path created under the scratch dir is inside the
    // directory we handed to binwalk. The scratch dir is fresh and owned by
    // this test, so any escape would show up here.
    let mut found = Vec::new();
    walk_paths(scratch.path(), &mut found);
    for path in found {
        assert!(
            path.starts_with(output_directory.path()),
            "extraction escaped the output directory: {}",
            path.display()
        );
    }

    let root = &extraction.output_directory;

    // The benign sibling entry was extracted with intact contents...
    assert_eq!(fs::read(root.join("benign.txt")).unwrap(), payload);

    // ...and hostile member names were clamped inside the root (`..` collapsed,
    // leading '/' stripped), not skipped outright.
    assert!(
        root.join("evil.txt").is_file(),
        "'../evil.txt' should be clamped to 'evil.txt' inside the root"
    );
    assert!(
        root.join("tmp/abs_evil.txt").is_file(),
        "'/tmp/abs_evil.txt' should be clamped to 'tmp/abs_evil.txt' inside the root"
    );

    // Escaping symlink targets are rewritten to chroot-relative paths: still
    // relative, lexically pinned inside the root, and dangling (the rewritten
    // targets were never created), so no host file is reachable through them.
    for link in ["rel_escape", "abs_escape"] {
        let link_path = root.join(link);
        let is_symlink = fs::symlink_metadata(&link_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false);
        assert!(
            is_symlink,
            "{link} must be extracted as a symlink inside the root"
        );
        assert!(
            symlink_target_stays_within(root, &link_path),
            "{link}'s target must resolve inside the extraction root"
        );
        assert!(
            fs::read(&link_path).is_err(),
            "{link} must not resolve to any host file"
        );
    }

    // Hardlinks are represented as symlinks to their target's contents.
    let hardlink = root.join("hardlink.txt");
    let hardlink_metadata =
        fs::symlink_metadata(&hardlink).expect("expected hardlink.txt to be extracted");
    assert!(
        hardlink_metadata.file_type().is_symlink(),
        "hardlink.txt must be extracted as a symlink"
    );
    assert_eq!(
        fs::read(&hardlink).unwrap(),
        payload,
        "hardlink.txt must resolve to benign.txt within the extraction tree"
    );

    // Metadata-only entries (fifo) carve nothing but must not fail extraction.
    assert!(!root.join("pipe.fifo").exists());
}

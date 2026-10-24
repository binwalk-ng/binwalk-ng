use binwalk_ng::{AnalysisResults, Binwalk};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use qnx_ifs::Endian;
use std::io::Write;
use std::path::{Path, PathBuf};

const FILE_DATA: &[u8] = b"#!/bin/sh\necho qnx-ifs\n";
const MOUNTPOINT: &str = "/fs";
// QNX image filesystem header (signature plus fixed fields), before mountpoint.
// Must match the crate's `QNX_IMAGE_HEADER_SIZE`, cross-checked at compile time
// by an assert in src/formats/qnx.rs.
const IMAGE_HEADER_SIZE: usize = 88;

const fn u16(value: u16, endian: Endian) -> [u8; 2] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

const fn u32(value: u32, endian: Endian) -> [u8; 4] {
    match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    }
}

const fn align4(value: usize) -> usize {
    value.div_ceil(4) * 4
}

fn attr(size: u16, ino: u32, mode: u32, endian: Endian) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&u16(size, endian));
    value.extend_from_slice(&u16(0, endian)); // extattr_offset
    value.extend_from_slice(&u32(ino, endian));
    value.extend_from_slice(&u32(mode, endian));
    value.extend_from_slice(&u32(0, endian)); // gid
    value.extend_from_slice(&u32(0, endian)); // uid
    value.extend_from_slice(&u32(1, endian)); // mtime
    value
}

fn dirent(path: &str, extra: &[u8], ino: u32, mode: u32, endian: Endian) -> Vec<u8> {
    let size = align4(24 + extra.len() + path.len() + 1);
    let mut value = attr(size as u16, ino, mode, endian);
    value.extend_from_slice(extra);
    value.extend_from_slice(path.as_bytes());
    value.push(0);
    value.resize(size, 0);
    value
}

fn file_extra(offset: usize, size: usize, endian: Endian) -> Vec<u8> {
    [u32(offset as u32, endian), u32(size as u32, endian)].concat()
}

fn symlink_extra(path: &str, target: &str, endian: Endian) -> Vec<u8> {
    [
        u16((path.len() + 1) as u16, endian),
        u16((target.len() + 1) as u16, endian),
    ]
    .concat()
}

fn symlink_dirent(path: &str, target: &str, ino: u32, endian: Endian) -> Vec<u8> {
    let size = align4(24 + 4 + path.len() + 1 + target.len() + 1);
    let mut value = attr(size as u16, ino, 0o120777, endian);
    value.extend_from_slice(&symlink_extra(path, target, endian));
    value.extend_from_slice(path.as_bytes());
    value.push(0);
    value.extend_from_slice(target.as_bytes());
    value.push(0);
    value.resize(size, 0);
    value
}

fn build_filesystem(endian: Endian) -> Vec<u8> {
    let header_len = align4(IMAGE_HEADER_SIZE + 1 + MOUNTPOINT.len());
    let root = dirent("", &[], 1, 0o040755, endian);
    let bin = dirent("bin", &[], 2, 0o040755, endian);
    let file_size = align4(24 + 8 + "bin/sh".len() + 1);
    let link = symlink_dirent("bin/link", "sh", 4, endian);
    let dev = dirent("dev", &[], 5, 0o040755, endian);
    let console = dirent(
        "dev/console",
        &[u32(0x1234, endian), u32((1 << 10) | 2, endian)].concat(),
        6,
        0o020600,
        endian,
    );

    let dir_area = root.len() + bin.len() + file_size + link.len() + dev.len() + console.len() + 4;
    let data_offset = header_len + dir_area;
    let image_size = align4(data_offset + FILE_DATA.len()) + 4;

    let file = dirent(
        "bin/sh",
        &file_extra(data_offset, FILE_DATA.len(), endian),
        3,
        0o100755,
        endian,
    );
    assert_eq!(file.len(), file_size);

    let mut filesystem = Vec::new();
    filesystem.extend_from_slice(qnx_ifs::image::IMAGE_SIGNATURE);
    filesystem.push(match endian {
        Endian::Little => 0,
        Endian::Big => qnx_ifs::image::image_flags::BIGENDIAN,
    });
    filesystem.extend_from_slice(&u32(image_size as u32, endian));
    filesystem.extend_from_slice(&u32((header_len + dir_area) as u32, endian));
    filesystem.extend_from_slice(&u32(header_len as u32, endian));
    filesystem.extend_from_slice(&[0u8; 4 * 4]); // boot_ino
    filesystem.extend_from_slice(&u32(0, endian)); // script_ino
    filesystem.extend_from_slice(&u32(0, endian)); // chain_paddr
    filesystem.extend_from_slice(&[0u8; 10 * 4]); // spare
    filesystem.extend_from_slice(&u32(0, endian)); // mountflags
    filesystem.extend_from_slice(MOUNTPOINT.as_bytes());
    filesystem.push(0);
    filesystem.resize(header_len, 0);

    filesystem.extend_from_slice(&root);
    filesystem.extend_from_slice(&bin);
    filesystem.extend_from_slice(&file);
    filesystem.extend_from_slice(&link);
    filesystem.extend_from_slice(&dev);
    filesystem.extend_from_slice(&console);
    filesystem.extend_from_slice(&[0u8; 4]); // dirent terminator
    filesystem.extend_from_slice(FILE_DATA);
    filesystem.resize(image_size - 4, 0);
    filesystem.extend_from_slice(&[0u8; 4]); // image trailer
    filesystem
}

fn wrap_in_startup_image(filesystem: &[u8], zlib: bool, endian: Endian) -> Vec<u8> {
    let payload = if zlib {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(filesystem).unwrap();
        encoder.finish().unwrap()
    } else {
        filesystem.to_vec()
    };

    const HEADER_SIZE: usize = 256;
    const STARTUP_SIZE: usize = HEADER_SIZE + 4;
    let stored_size = STARTUP_SIZE + payload.len();

    let magic: &[u8; 4] = match endian {
        Endian::Little => b"\xEB\x7E\xFF\x00",
        Endian::Big => b"\x00\xFF\x7E\xEB",
    };
    let mut flags1 = match endian {
        Endian::Little => 0,
        Endian::Big => 0x02,
    };
    if zlib {
        flags1 |= 0x04;
    }

    let mut image = Vec::new();
    image.extend_from_slice(magic);
    image.extend_from_slice(&u16(1, endian)); // version
    image.push(flags1); // endianness and compression
    image.push(0); // flags2
    image.extend_from_slice(&u16(HEADER_SIZE as u16, endian));
    image.extend_from_slice(&u16(1, endian)); // machine
    image.extend_from_slice(&u32(0, endian)); // startup_vaddr
    image.extend_from_slice(&u32(0, endian)); // paddr_bias
    image.extend_from_slice(&u32(0, endian)); // image_paddr
    image.extend_from_slice(&u32(0, endian)); // ram_paddr
    image.extend_from_slice(&u32(0, endian)); // ram_size
    image.extend_from_slice(&u32(STARTUP_SIZE as u32, endian));
    image.extend_from_slice(&u32(stored_size as u32, endian));
    image.extend_from_slice(&u32(0, endian)); // imagefs_paddr
    image.extend_from_slice(&u32(filesystem.len() as u32, endian));
    image.extend_from_slice(&u16(0, endian)); // preboot_size
    image.extend_from_slice(&[0u8; 14]); // zero fields
    assert_eq!(image.len(), 64);
    image.resize(HEADER_SIZE, 0);
    image.extend_from_slice(&[0u8; 4]); // startup trailer
    image.extend_from_slice(&payload);
    assert_eq!(image.len(), stored_size);
    image
}

fn analyze(image: &[u8]) -> (tempfile::TempDir, AnalysisResults) {
    let temp_dir = tempfile::tempdir().unwrap();
    let input_path = temp_dir.path().join("qnx.bin");
    let output_path = temp_dir.path().join("extracted");

    std::fs::write(&input_path, image).unwrap();
    std::fs::create_dir(&output_path).unwrap();

    let binwalker = Binwalk::builder()
        .include("qnx_ifs")
        .build()
        .expect("Binwalk initialization failed");
    let results = binwalker.analyze(&input_path, Some(&output_path));

    (temp_dir, results)
}

fn assert_extracted_tree(output_directory: &Path) {
    assert_eq!(
        std::fs::read(output_directory.join("bin/sh")).unwrap(),
        FILE_DATA
    );
    assert_eq!(
        std::fs::read(output_directory.join("bin/link")).unwrap(),
        FILE_DATA
    );
    assert_eq!(
        std::fs::read_to_string(output_directory.join("dev/console")).unwrap(),
        "c 1 2"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(output_directory.join("bin/sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }
}

/// Assert that `image` produced exactly one successful extraction of its full
/// length, and return the directory it was extracted into.
fn assert_single_extraction(results: &AnalysisResults, image: &[u8]) -> PathBuf {
    assert_eq!(results.file_map.len(), 1);
    let signature = &results.file_map[0];
    assert_eq!(signature.name, "qnx_ifs");
    assert_eq!(signature.offset, 0);
    assert_eq!(signature.size, image.len());

    let extraction = results
        .extractions
        .get(&signature.id)
        .expect("extraction result");
    assert!(extraction.success, "extraction failed: {extraction:?}");
    assert_eq!(extraction.size, Some(image.len()));

    extraction.output_directory.clone()
}

fn assert_extracts_bare_imagefs(endian: Endian) {
    let filesystem = build_filesystem(endian);
    // Sanity check the hand-built fixture before handing it to Binwalk.
    binwalk_ng::formats::qnx::qnx_ifs_parser(&filesystem, 0).expect("fixture should parse");
    let (_temp_dir, results) = analyze(&filesystem);

    assert_extracted_tree(&assert_single_extraction(&results, &filesystem));
}

fn assert_extracts_startup_image(endian: Endian, zlib: bool) {
    let image = wrap_in_startup_image(&build_filesystem(endian), zlib, endian);
    let (_temp_dir, results) = analyze(&image);

    assert_extracted_tree(&assert_single_extraction(&results, &image));
}

#[test]
fn extracts_bare_imagefs() {
    assert_extracts_bare_imagefs(Endian::Little);
}

#[test]
fn extracts_big_endian_bare_imagefs() {
    assert_extracts_bare_imagefs(Endian::Big);
}

#[test]
fn extracts_uncompressed_startup_image() {
    assert_extracts_startup_image(Endian::Little, false);
}

#[test]
fn extracts_big_endian_startup_image() {
    assert_extracts_startup_image(Endian::Big, false);
}

#[test]
fn extracts_zlib_compressed_startup_image() {
    assert_extracts_startup_image(Endian::Little, true);
}

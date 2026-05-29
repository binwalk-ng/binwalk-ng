use crate::common::{get_cstring, is_offset_safe};
use crate::extractors::{Chroot, ExtractionError, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::StructureError;
use log::warn;
use std::path::Path;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "RomFS filesystem";

/// ROMFS magic bytes
pub fn romfs_magic() -> Vec<Vec<u8>> {
    vec![b"-rom1fs-".to_vec()]
}

/// Validate a ROMFS signature
pub fn romfs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        offset,
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry run
    let dry_run = extract_romfs(file_data, offset, None);

    // If the dry run was a success, everything should be good to go
    if dry_run.success
        && let Some(romfs_size) = dry_run.size
    {
        // Parse the RomFS header to get the volume name
        if let Ok(romfs_header) = parse_romfs_header(&file_data[offset..]) {
            // Report the result
            result.size = romfs_size;
            result.description = format!(
                "{}, volume name: \"{}\", total size: {} bytes",
                result.description, romfs_header.volume_name, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Stores RomFS header info
#[derive(Default, Debug, Clone)]
pub struct RomFSHeader {
    pub image_size: usize,
    pub header_size: usize,
    pub volume_name: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct RomFSHeaderBytes {
    magic: zerocopy::U64<BE>,
    image_size: zerocopy::U32<BE>,
    checksum: zerocopy::U32<BE>,
}

/// Parse a RomFS header
pub fn parse_romfs_header(romfs_data: &[u8]) -> Result<RomFSHeader, StructureError> {
    // Maximum amount of data that the RomFS CRC is calculated over
    const MAX_HEADER_CRC_DATA_LEN: usize = 512;

    // Get the size of the defined header structure
    let header_size = std::mem::size_of::<RomFSHeaderBytes>();

    // Parse the header structure
    let (header, _) = RomFSHeaderBytes::ref_from_prefix(romfs_data).map_err(|_| StructureError)?;
    let image_size = header.image_size.get() as usize;
    // Sanity check the reported image size
    if image_size > header_size {
        // The volume name is a NULL-terminated string that immediately follows the RomFS header
        if let Some(volume_name_bytes) = romfs_data.get(header_size..) {
            let volume_name = get_cstring(volume_name_bytes);

            let mut crc_data_len: usize = MAX_HEADER_CRC_DATA_LEN;

            if image_size < crc_data_len {
                crc_data_len = image_size;
            }

            // Validate the header CRC
            if let Some(crc_data) = romfs_data.get(0..crc_data_len)
                && romfs_crc_valid(crc_data)
            {
                return Ok(RomFSHeader {
                    image_size,
                    volume_name: volume_name.clone(),
                    // Volume name has a NULL terminator and is padded to a 16 byte boundary alignment
                    header_size: header_size + romfs_align(volume_name.len() + 1),
                });
            }
        }
    }

    Err(StructureError)
}

/// Struct to store info on a RomFS file entry
#[derive(Debug, Default, Clone)]
pub struct RomFSFileHeader {
    pub info: usize,
    pub size: usize,
    pub name: String,
    pub checksum: u32,
    /// Offset to the start of the file data, *relative to the beginning of this header*
    pub data_offset: usize,
    pub file_type: u32,
    pub executable: bool,
    pub symlink: bool,
    pub directory: bool,
    pub regular: bool,
    pub block_device: bool,
    pub character_device: bool,
    pub fifo: bool,
    pub socket: bool,
    /// Offset to the next file header, *relative to the beginning of the RomFS image*
    pub next_header_offset: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct FileHeaderBytes {
    next_header_offset: zerocopy::U32<BE>,
    info: zerocopy::U32<BE>,
    size: zerocopy::U32<BE>,
    checksum: zerocopy::U32<BE>,
}

/// Parse a RomFS file entry
pub fn parse_romfs_file_entry(romfs_data: &[u8]) -> Result<RomFSFileHeader, StructureError> {
    // Bit masks
    const FILE_TYPE_MASK: u32 = 0b0111;
    const FILE_EXEC_MASK: u32 = 0b1000;
    const NEXT_OFFSET_MASK: u32 = 0b11111111_11111111_11111111_11110000;

    // We only support extraction of these file types
    const ROMFS_DIRECTORY: u32 = 1;
    const ROMFS_REGULAR_FILE: u32 = 2;
    const ROMFS_SYMLINK: u32 = 3;
    const ROMFS_BLOCK_DEVICE: u32 = 4;
    const ROMFS_CHAR_DEVICE: u32 = 5;
    const ROMFS_SOCKET: u32 = 6;
    const ROMFS_FIFO: u32 = 7;

    // Size of the defined file header structure
    let file_header_size = std::mem::size_of::<FileHeaderBytes>();

    // Parse the file header
    let (file_entry_header, _) =
        FileHeaderBytes::ref_from_prefix(romfs_data).map_err(|_| StructureError)?;

    // Null terminated file name immediately follows the header
    if let Some(file_name_bytes) = romfs_data.get(file_header_size..) {
        let file_name = get_cstring(file_name_bytes);

        // A file should have a name
        if !file_name.is_empty() {
            // Instantiate a new RomFSEntry structure
            let mut file_header = RomFSFileHeader::default();

            // Populate basic info
            file_header.size = file_entry_header.size.get() as usize;
            file_header.info = file_entry_header.info.get() as usize;
            file_header.checksum = file_entry_header.checksum.get();
            file_header.name = file_name.clone();

            // File data begins immediately after the file header, including the NULL-terminated, 16-byte alignment padded file name
            file_header.data_offset = file_header_size + romfs_align(file_name.len() + 1);

            // These values are encoded into the next header offset field
            file_header.file_type = file_entry_header.next_header_offset.get() & FILE_TYPE_MASK;
            file_header.executable = (file_entry_header.next_header_offset & FILE_EXEC_MASK) != 0;

            // Set the type of entry that this is
            file_header.fifo = file_header.file_type == ROMFS_FIFO;
            file_header.socket = file_header.file_type == ROMFS_SOCKET;
            file_header.symlink = file_header.file_type == ROMFS_SYMLINK;
            file_header.regular = file_header.file_type == ROMFS_REGULAR_FILE;
            file_header.directory = file_header.file_type == ROMFS_DIRECTORY;
            file_header.block_device = file_header.file_type == ROMFS_BLOCK_DEVICE;
            file_header.character_device = file_header.file_type == ROMFS_CHAR_DEVICE;

            // The next file header offset is an offset from the beginning of the RomFS image
            file_header.next_header_offset =
                (file_entry_header.next_header_offset.get() & NEXT_OFFSET_MASK) as usize;

            return Ok(file_header);
        }
    }

    Err(StructureError)
}

/// RomFS aligns things to a 16-byte boundary
const fn romfs_align(x: usize) -> usize {
    const ALIGNMENT: usize = 16;

    match x % ALIGNMENT {
        0 => x,
        rem => x + (ALIGNMENT - rem),
    }
}

/// Pretty simple checksum used by RomFS
fn romfs_crc_valid(crc_data: &[u8]) -> bool {
    const WORD_SIZE: usize = std::mem::size_of::<u32>();

    // Checksum size must be 4-byte aligned
    if crc_data.len().is_multiple_of(WORD_SIZE) {
        let sum: u32 = crc_data
            .chunks_exact(WORD_SIZE)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .fold(0u32, u32::wrapping_add);

        /*
         * The header checksum is set such that summing the bytes should result in a sum of 0.
         */
        return sum == 0;
    }

    false
}

#[derive(Default, Debug, Clone)]
struct RomFSEntry {
    info: usize,
    size: usize,
    name: String,
    offset: usize,
    executable: bool,
    directory: bool,
    regular: bool,
    block_device: bool,
    character_device: bool,
    fifo: bool,
    socket: bool,
    symlink: bool,
    symlink_target: String,
    device_major: usize,
    device_minor: usize,
    children: Vec<Self>,
}

/// Defines the internal extractor function for extracting RomFS file systems */
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::romfs::romfs_extractor;
///
/// match romfs_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn romfs_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_romfs),
        ..Default::default()
    }
}

/// Internal RomFS extractor
pub fn extract_romfs(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult::default();

    // Parse the RomFS header
    if let Ok(romfs_header) = parse_romfs_header(&file_data[offset..]) {
        // Calculate start and end offsets of RomFS image
        let romfs_data_start: usize = offset;
        let romfs_data_end: usize = romfs_data_start + romfs_header.image_size;

        // Sanity check reported image size and get the romfs data
        if let Some(romfs_data) = file_data.get(romfs_data_start..romfs_data_end) {
            // Process the RomFS file entries
            if let Ok(root_entries) = process_romfs_entries(romfs_data, romfs_header.header_size) {
                // We expect at least one file entry in the root of the RomFS image
                if !root_entries.is_empty() {
                    // Everything looks good
                    result.success = true;
                    result.size = Some(romfs_header.image_size);

                    // Do extraction, if an output directory was provided
                    if let Some(output_directory) = output_directory {
                        let mut file_count: usize = 0;
                        let root_parent = "".to_string();

                        // RomFS files will be extracted to a sub-directory under the specified
                        // extraction directory whose name is the RomFS volume name.
                        let chroot = Chroot::new(output_directory);
                        let romfs_chroot_dir = chroot.chrooted_path(&romfs_header.volume_name);

                        // Create the romfs output directory, ensuring that it is contained inside the specified extraction directory
                        if chroot.create_directory(&romfs_chroot_dir) {
                            // Extract RomFS contents
                            file_count = extract_romfs_entries(
                                romfs_data,
                                &root_entries,
                                &root_parent,
                                &romfs_chroot_dir,
                            );
                        }

                        // If no files were extracted, extraction was a failure
                        if file_count == 0 {
                            result.success = false;
                        }
                    }
                }
            }
        }
    }

    result
}

// Recursively processes all RomFS file entries and their children, and returns a list of RomFSEntry structures
fn process_romfs_entries(
    romfs_data: &[u8],
    offset: usize,
) -> Result<Vec<RomFSEntry>, ExtractionError> {
    let mut previous_file_offset = None;
    let mut file_entries: Vec<RomFSEntry> = vec![];
    let mut processed_entries: Vec<usize> = vec![];
    let ignore_file_names: Vec<String> = vec![".".to_string(), "..".to_string()];

    // Total available data
    let available_data = romfs_data.len();

    // File data starts immediately after the image header; the offset passed in should be the end of the header
    let mut file_offset: usize = offset;

    /*
     * Sanity check the available file data against the offset of the next file entry.
     * The file offset for the next file entry will be 0 when we've reached the end of the entry list.
     */
    while file_offset != 0 && is_offset_safe(available_data, file_offset, previous_file_offset) {
        // Sanity check, no two entries should exist at the same offset, if so, infinite recursion could ensue
        if processed_entries.contains(&file_offset) {
            break;
        } else {
            processed_entries.push(file_offset);
        }

        // Parse the next file entry
        if let Ok(file_header) = parse_romfs_file_entry(&romfs_data[file_offset..]) {
            // Instantiate a new RomFSEntry structure and populate basic info
            let mut file_entry = RomFSEntry {
                size: file_header.size,
                info: file_header.info,
                name: file_header.name.clone(),
                symlink: file_header.symlink,
                regular: file_header.regular,
                directory: file_header.directory,
                executable: file_header.executable,
                block_device: file_header.block_device,
                character_device: file_header.character_device,
                fifo: file_header.fifo,
                socket: file_header.socket,
                offset: file_offset + file_header.data_offset, //            Make file_entry.offset an offset relative to the beginning of the RomFS image
                ..Default::default()
            };

            // Sanity check the file data offset and size fields
            if (file_entry.offset + file_entry.size) > romfs_data.len() {
                warn!("Invalid offset/size specified for file {}", file_entry.name);
                return Err(ExtractionError);
            }

            // Don't do anything special for '.' or '..' directory entries
            if !ignore_file_names.contains(&file_entry.name) {
                // Symlinks need their target paths
                if file_entry.symlink {
                    if let Some(symlink_bytes) =
                        romfs_data.get(file_entry.offset..file_entry.offset + file_entry.size)
                    {
                        match String::from_utf8(symlink_bytes.to_vec()) {
                            Err(e) => {
                                warn!("Failed to convert symlink target path to string: {e}");
                                return Err(ExtractionError);
                            }
                            Ok(path) => {
                                file_entry.symlink_target = path.clone();
                            }
                        }
                    } else {
                        break;
                    }
                // Device files have their major/minor numbers encoded into the info field
                } else if file_entry.block_device || file_entry.character_device {
                    file_entry.device_minor = file_entry.info & 0xFFFF;
                    file_entry.device_major = (file_entry.info >> 16) & 0xFFFF;
                }

                // Directories have children; process them
                if file_entry.directory {
                    match process_romfs_entries(romfs_data, file_entry.info) {
                        Err(e) => return Err(e),
                        Ok(children) => file_entry.children = children,
                    }
                }

                // Only add supported file types to the list of file entries
                if file_entry.directory || file_entry.symlink || file_entry.regular {
                    file_entries.push(file_entry);
                }
            }

            // The next file header offset is an offset from the beginning of the RomFS image
            previous_file_offset = Some(file_offset);
            file_offset = file_header.next_header_offset;
        } else {
            // File entry header parsing failed, gtfo
            break;
        }
    }

    Ok(file_entries)
}

// Recursively extract all RomFS entries, returns the number of extracted files/directories
fn extract_romfs_entries(
    romfs_data: &[u8],
    romfs_files: &Vec<RomFSEntry>,
    parent_directory: impl AsRef<Path>,
    chroot_directory: impl AsRef<Path>,
) -> usize {
    let mut file_count: usize = 0;

    let chroot_directory = chroot_directory.as_ref();
    let chroot = Chroot::new(chroot_directory);

    for file_entry in romfs_files {
        let extraction_success: bool;
        let file_path = chroot.safe_path_join(parent_directory.as_ref(), &file_entry.name);

        if file_entry.directory {
            extraction_success = chroot.create_directory(&file_path);
        } else if file_entry.regular {
            extraction_success =
                chroot.carve_file(&file_path, romfs_data, file_entry.offset, file_entry.size);
        } else if file_entry.symlink {
            extraction_success = chroot.create_symlink(&file_path, &file_entry.symlink_target);
        } else if file_entry.fifo {
            extraction_success = chroot.create_fifo(&file_path);
        } else if file_entry.socket {
            extraction_success = chroot.create_socket(&file_path);
        } else if file_entry.block_device {
            extraction_success = chroot.create_block_device(
                &file_path,
                file_entry.device_major,
                file_entry.device_minor,
            );
        } else if file_entry.character_device {
            extraction_success = chroot.create_character_device(
                &file_path,
                file_entry.device_major,
                file_entry.device_minor,
            );
        } else {
            continue;
        }

        if extraction_success {
            file_count += 1;

            // Extract the children of a directory
            if file_entry.directory && !file_entry.children.is_empty() {
                file_count += extract_romfs_entries(
                    romfs_data,
                    &file_entry.children,
                    &file_path,
                    chroot_directory,
                );
            }

            // Make executable files executable
            if file_entry.regular && file_entry.executable {
                chroot.make_executable(&file_path);
            }
        } else {
            warn!("Failed to extract RomFS file {}", file_path.display());
        }
    }

    // Return the number of files extracted
    file_count
}

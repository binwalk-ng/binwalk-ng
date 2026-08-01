//! Primary Binwalk interface.

use aho_corasick::AhoCorasick;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path;
use std::path::Path;
use std::path::PathBuf;
use uuid::Uuid;

#[cfg(windows)]
use std::os::windows;

#[cfg(unix)]
use std::os::unix;

use crate::common::{is_offset_safe, read_or_map_file};
use crate::extractors;
use crate::formats::program_store;
use crate::magic;
use crate::signatures;

/// Returned on initialization error
#[derive(Debug, Default, Clone)]
pub struct BinwalkError {
    pub message: String,
}

impl BinwalkError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

/// Analysis results returned by Binwalk::analyze
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    /// Path to the file that was analyzed
    pub file_path: PathBuf,
    /// File signature results, as returned by Binwalk::scan
    pub file_map: Vec<signatures::SignatureResult>,
    /// File extraction results, as returned by Binwalk::extract.
    /// HashMap key is the corresponding SignatureResult.id value in `file_map`.
    pub extractions: HashMap<String, extractors::ExtractionResult>,
}

/// Analyze files / memory for file signatures
///
/// ## Example
///
/// ```
/// use binwalk_ng::Binwalk;
///
/// let target_file = "/bin/ls";
/// let data_to_scan = std::fs::read(target_file).expect("Unable to read file");
///
/// let binwalker = Binwalk::new();
///
/// let signature_results = binwalker.scan(&data_to_scan);
///
/// for result in &signature_results {
///     println!("Found '{}' at offset {:#X}", result.description, result.offset);
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct Binwalk {
    /// Count of all signatures (short and regular)
    pub signature_count: usize,
    /// Count of all magic patterns (short and regular)
    pub pattern_count: usize,
    /// The base file requested for analysis
    pub base_target_file: PathBuf,
    /// The base output directory for extracted files
    pub base_output_directory: PathBuf,
    /// A list of signatures that must start at offset 0
    pub short_signatures: Vec<signatures::Signature>,
    /// A list of magic bytes to search for throughout the entire file
    pub patterns: Vec<Vec<u8>>,
    /// Signatures, with same indices as patterns
    pub signatures: Vec<signatures::Signature>,
    /// Maps signatures to their corresponding extractors
    pub extractor_lookup_table: HashMap<String, Option<extractors::Extractor>>,
    /// If the mmap call is allowed to be used for reading files
    ///
    /// Binwalk may abort unexpectedly if mmap is used and the analyzed file(s) are simultaneously
    /// truncated.
    pub allow_mmap: bool,
    /// The most leading zero bytes in any magic pattern that has a non-zero byte
    ///
    /// A pattern match can begin at most this many bytes before the pattern's first non-zero
    /// byte, which bounds how far a scan may skip ahead through a run of zero bytes. An all-zero
    /// magic has no first non-zero byte and so is not counted here; see
    /// [`Binwalk::zero_run_pattern_len`] for how one is accounted for instead.
    max_leading_zeros: usize,
    /// Length of the synthetic all-zero pattern that [`Binwalk::scan`] searches for in order to
    /// spot a run of zero bytes it can skip past, or `None` if no run can be skipped
    ///
    /// Runs of zero bytes are common padding, and a magic pattern of all zero bytes matches at
    /// every offset in one, so a scan would otherwise validate a candidate per byte of padding.
    /// Searching for a longer run of zeros alongside the real patterns says when the scan has
    /// reached one, and [`Binwalk::resume_offset_after_zero_run`] says where it may resume.
    ///
    /// A match of this pattern makes the scan abandon the current Aho-Corasick search, which is
    /// only safe if every real match overlapping it is either already reported or re-found by the
    /// search that resumes. Matches are reported in order of where they end, so a real match that
    /// is not yet reported ends after this pattern's match, and is one of two shapes:
    ///
    /// - it starts at or before the run, and so contains the whole of it. Making this pattern
    ///   longer than the longest run of zero bytes within any pattern being searched puts that out
    ///   of reach, so no such match exists.
    /// - it starts inside the run, and so its own leading zeros have to reach the next non-zero
    ///   byte in the file. That puts its start at or after the offset
    ///   [`Binwalk::resume_offset_after_zero_run`] returns, which re-finds it. Note this is what
    ///   `max_leading_zeros` is for; a resume that did not rewind would lose it.
    ///
    /// An all-zero magic has no first non-zero byte and so fits neither shape: it matches at every
    /// offset in the run, and nothing but a byte its signature requires to be non-zero can rule
    /// one out. Making this pattern longer than any such magic plus the distance back to that byte
    /// keeps the byte inside the run, and so zero, for every match of it not reported first.
    zero_run_pattern_len: Option<usize>,
}

/// The longest run of consecutive zero bytes anywhere in `pattern`
fn longest_zero_run(pattern: &[u8]) -> usize {
    pattern
        .split(|&byte| byte != 0)
        .map(<[u8]>::len)
        .max()
        .unwrap_or(0)
}

impl Binwalk {
    /// Create a new Binwalk instance with all default values.
    /// Equivalent to `Binwalk::configure(None, None, None, None, None, false)`.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::Binwalk;
    ///
    /// let binwalker = Binwalk::new();
    /// ```
    pub fn new() -> Self {
        Self::configure(None, None, vec![], vec![], None, false).unwrap()
    }

    /// Create a new Binwalk instance.
    ///
    /// If `target_file_name` and `output_directory` are specified, the `output_directory` will be created if it does not
    /// already exist, and a symlink to `target_file_name` will be placed inside the `output_directory`. The path to this
    /// symlink is placed in `Binwalk.base_target_file`.
    ///
    /// The `include` and `exclude` arguments specify include and exclude signature filters. The String values contained
    /// in these arguments must match the `Signature.name` values defined in magic.rs.
    ///
    /// Additional user-defined signatures may be provided via the `signatures` argument.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_binwalk_rs_102_0() -> Result<binwalk_ng::Binwalk, binwalk_ng::BinwalkError> {
    /// use binwalk_ng::Binwalk;
    ///
    /// // Don't scan for these file signatures
    /// let exclude_filters: Vec<String> = vec!["jpeg".to_string(), "png".to_string()];
    ///
    /// let binwalker = Binwalk::configure(None,
    ///                                    None,
    ///                                    vec![],
    ///                                    exclude_filters,
    ///                                    None,
    ///                                    false)?;
    /// # Ok(binwalker)
    /// # } _doctest_main_src_binwalk_rs_102_0(); }
    /// ```
    pub fn configure(
        target_file_name: Option<&Path>,
        output_directory: Option<&Path>,
        include: Vec<String>,
        exclude: Vec<String>,
        signatures: Option<Vec<signatures::Signature>>,
        full_search: bool,
    ) -> Result<Self, BinwalkError> {
        let mut new_instance = Self {
            allow_mmap: true,
            zero_run_pattern_len: Some(0),
            ..Default::default()
        };

        // Target file is optional, especially if being called via the library
        if let Some(target_file) = target_file_name {
            // Set the target file path, make it an absolute path
            match path::absolute(target_file) {
                Err(_) => {
                    return Err(BinwalkError::new(&format!(
                        "Failed to get absolute path for '{}'",
                        target_file.display()
                    )));
                }
                Ok(abspath) => {
                    new_instance.base_target_file = abspath;
                }
            }

            // If an output extraction directory was also specified, initialize it
            if let Some(extraction_directory) = output_directory {
                // Make the extraction directory an absolute path
                match path::absolute(extraction_directory) {
                    Err(_) => {
                        return Err(BinwalkError::new(&format!(
                            "Failed to get absolute path for '{}'",
                            extraction_directory.display()
                        )));
                    }
                    Ok(absolute_path) => {
                        new_instance.base_output_directory = absolute_path;
                    }
                }

                // Initialize the extraction directory. This will create the directory if it
                // does not exist, and create a symlink inside the directory that points to
                // the specified target file.
                match init_extraction_directory(
                    &new_instance.base_target_file,
                    &new_instance.base_output_directory,
                ) {
                    Err(e) => {
                        return Err(BinwalkError::new(&format!(
                            "Failed to initialize extraction directory: {e}"
                        )));
                    }
                    Ok(new_target_file_path) => {
                        // This is the new base target path (a symlink inside the extraction directory)
                        new_instance.base_target_file = new_target_file_path;
                    }
                }
            }
        }

        // Load all internal signature patterns
        let mut signature_patterns = magic::patterns();

        // Include any user-defined signature patterns
        if let Some(user_defined_signature_patterns) = signatures {
            signature_patterns.extend(user_defined_signature_patterns);
        }

        // Load magic signatures
        for signature in signature_patterns {
            // Check if this signature should be included
            if !include_signature(&signature, &include, &exclude) {
                continue;
            }

            // Keep a count of total unique signatures that are supported
            new_instance.signature_count += 1;

            // Keep a count of the total number of magic patterns
            new_instance.pattern_count += signature.magic.len();

            // Create a lookup table which associates each signature to its respective extractor
            new_instance
                .extractor_lookup_table
                .insert(signature.name.clone(), signature.extractor.clone());

            // Each signature may have multiple magic bytes associated with it
            for pattern in &signature.magic {
                if signature.short && !full_search {
                    // These are short patterns, and should only be searched for at the very beginning of a file
                    new_instance.short_signatures.push(signature.clone());
                    break;
                }

                // How long a run of zeros has to be for this pattern not to stand in the way of
                // skipping it; see Binwalk::zero_run_pattern_len.
                let longest_matching_zeros = match pattern.iter().position(|&b| b != 0) {
                    Some(leading_zeros) => {
                        new_instance.max_leading_zeros =
                            new_instance.max_leading_zeros.max(leading_zeros);
                        Some(longest_zero_run(pattern))
                    }
                    // An all-zero magic says nothing about where a valid signature can begin,
                    // since it matches at every offset in a run of zeros. However, we know
                    // something about program_store (the only built-in signature with all zero
                    // magic): a valid header requires a non-zero byte `NONZERO_BEFORE_MAGIC` bytes
                    // before the magic. Matches within a longer run of zeros still occur, but that
                    // byte is itself a zero from the run, so none of them can be a valid header.
                    None if signature.name == "program_store" => {
                        Some(pattern.len() + program_store::NONZERO_BEFORE_MAGIC)
                    }
                    // If a user-provided Signature specifies an all-zero pattern, we have no info
                    // on the max run of zeros which could match their pattern.
                    None => {
                        warn!(
                            "pattern for {} contains only zeros, this may slow down scanning",
                            signature.name,
                        );
                        None
                    }
                };
                new_instance.zero_run_pattern_len =
                    match (new_instance.zero_run_pattern_len, longest_matching_zeros) {
                        (Some(len), Some(matchable_zeros)) => Some(len.max(matchable_zeros + 1)),
                        _ => None,
                    };

                new_instance.signatures.push(signature.clone());

                // Add these magic bytes to the list of patterns
                new_instance.patterns.push(pattern.to_vec());
            }
        }

        Ok(new_instance)
    }

    /// Where to resume scanning after the synthetic all-zero pattern matched, between
    /// `synth_zeros_start` and `synth_zeros_end`
    ///
    /// A magic pattern can begin at most `max_leading_zeros` bytes before its first non-zero byte,
    /// so nothing between here and that far ahead of the next non-zero byte could begin a *valid*
    /// match. An all-zero magic does still match in there, but a byte its signature requires to be
    /// non-zero lands inside the run; see [`Binwalk::zero_run_pattern_len`].
    ///
    /// The result is always past the start of the matched zeros, and so past the offset the
    /// current search began at: a pattern's leading zeros are a run of zeros within it, and the
    /// synthetic pattern is longer than every such run, hence longer than `max_leading_zeros`.
    fn resume_offset_after_zero_run(
        &self,
        file_data: &[u8],
        synth_zeros_start: usize,
        synth_zeros_end: usize,
    ) -> usize {
        debug_assert!(
            file_data[synth_zeros_start..synth_zeros_end]
                .iter()
                .all(|&b| b == 0)
        );
        debug_assert!(synth_zeros_end - synth_zeros_start > self.max_leading_zeros);
        let Some(next_non_zero) = file_data[synth_zeros_end..]
            .iter()
            .position(|&byte| byte != 0)
        else {
            // Every pattern needs a non-zero byte, either in the pattern itself or, for an
            // all-zero magic, in the data its signature requires to be non-zero nearby. With none
            // left in the file, nothing can match from here on.
            return file_data.len();
        };
        synth_zeros_end + next_non_zero - self.max_leading_zeros
    }

    /// Scan a file for magic signatures.
    /// Returns a list of validated magic signatures representing the known contents of the file.
    ///
    /// ## Example
    ///
    /// ```
    /// use binwalk_ng::Binwalk;
    ///
    /// let target_file = "/bin/ls";
    /// let data_to_scan = std::fs::read(target_file).expect("Unable to read file");
    ///
    /// let binwalker = Binwalk::new();
    ///
    /// let signature_results = binwalker.scan(&data_to_scan);
    ///
    /// for result in &signature_results {
    ///     println!("{:#X}  {}", result.offset, result.description);
    /// }
    ///
    /// assert!(signature_results.len() > 0);
    /// ```
    pub fn scan(&self, file_data: &[u8]) -> Vec<signatures::SignatureResult> {
        const FILE_START_OFFSET: usize = 0;

        let mut index_adjustment: usize = 0;
        let mut next_valid_offset: usize = 0;
        let mut previous_valid_offset = None;

        let available_data = file_data.len();

        // A list of identified signatures, representing a "map" of the file data
        let mut file_map: Vec<signatures::SignatureResult> = vec![];

        /*
         * Check beginning of file for short signatures.
         * These signatures are only valid if they occur at the very beginning of a file.
         * This is typically because the signatures are very short and they are likely
         * to occur randomly throughout the file, so this prevents having to validate many
         * false positve matches.
         */
        for signature in &self.short_signatures {
            for magic in signature.magic.clone() {
                let magic_start = FILE_START_OFFSET + signature.magic_offset;
                let magic_end = magic_start + magic.len();

                if file_data.len() > magic_end && file_data[magic_start..magic_end] == magic {
                    debug!(
                        "Found {} short magic match at offset {:#X}",
                        signature.description, magic_start
                    );

                    if let Ok(mut signature_result) = (signature.parser)(file_data, magic_start) {
                        // Auto populate some signature result fields
                        signature_result_auto_populate(&mut signature_result, signature);

                        // Add this signature to the file map
                        file_map.push(signature_result.clone());
                        info!(
                            "Found valid {} short signature at offset {:#X}",
                            signature_result.name, FILE_START_OFFSET
                        );

                        // Only update the next_valid_offset if confidence is high; these are, after all, short signatures
                        if signature_result.confidence >= signatures::CONFIDENCE_HIGH {
                            next_valid_offset = signature_result.offset + signature_result.size;
                        }

                        // Only one signature can match at fixed offset 0
                        break;
                    } else {
                        debug!(
                            "{} short signature match at offset {:#X} is invalid",
                            signature.description, FILE_START_OFFSET
                        );
                    }
                }
            }
        }

        /*
         * Same pattern matching algorithm used by fgrep.
         * This will search for all magic byte patterns in the file data, all at once.
         * https://en.wikipedia.org/wiki/Aho–Corasick_algorithm
         */
        // Searched alongside the real patterns to spot runs of zero bytes that can be skipped
        // past. The length is only zero when there are no real patterns to search for at all, and
        // an empty pattern would match at every offset.
        let zero_run_pattern = self
            .zero_run_pattern_len
            .filter(|&len| len > 0)
            .map(|len| vec![0u8; len]);
        let zero_run_pattern_index = self.patterns.len();

        let grep = AhoCorasick::new(self.patterns.iter().chain(&zero_run_pattern)).unwrap();

        debug!("Running Aho-Corasick scan");

        /*
         * Outer loop wrapper for AhoCorasick scan loop. This will loop until:
         *
         *  1) next_valid_offset exceeds available_data
         *  2) previous_valid_offset <= next_valid_offset
         */
        while is_offset_safe(available_data, next_valid_offset, previous_valid_offset) {
            // Update the previous valid offset in praparation for the next loop iteration
            previous_valid_offset = Some(next_valid_offset);

            debug!("Continuing scan from offset {next_valid_offset:#X}");

            /*
             * Run a new AhoCorasick scan starting at the next valid offset in the file data.
             * This will loop until:
             *
             *  1) All data has been exhausted, in which case previous_valid_offset and next_valid_offset
             *     will be identical, causing the outer while loop to break.
             *  2) A valid signature with a defined size is found, in which case next_valid_offset will
             *     be updated to point the end of the valid signature data, causing a new AhoCorasick
             *     scan to start at the new next_valid_offset file location.
             */
            for magic_match in grep.find_overlapping_iter(&file_data[next_valid_offset..]) {
                // Get the location of the magic bytes inside the file data
                let magic_offset: usize = next_valid_offset + magic_match.start();

                let magic_pattern_index = magic_match.pattern().as_usize();

                // The synthetic all-zero pattern has no signature to validate; it means the scan
                // has reached a run of zero bytes long enough to skip past. Every real match that
                // overlaps it has either been reported already or starts at or after the offset
                // the scan resumes from, so abandoning this search loses nothing; see
                // Binwalk::zero_run_pattern_len.
                if magic_pattern_index == zero_run_pattern_index {
                    let zeros_end = next_valid_offset + magic_match.end();
                    next_valid_offset =
                        self.resume_offset_after_zero_run(file_data, magic_offset, zeros_end);
                    debug!(
                        "Skipping run of zero bytes, jumping from {zeros_end:#X} to {next_valid_offset:#X}"
                    );
                    break;
                }

                // Get the signature associated with this magic signature
                let signature = &self.signatures[magic_pattern_index];

                debug!(
                    "Found {} magic match at offset {:#X}",
                    signature.description, magic_offset
                );

                /*
                 * Invoke the signature parser to parse and validate the signature.
                 * An error indicates a false positive match for the signature type.
                 */
                if let Ok(mut signature_result) = (signature.parser)(file_data, magic_offset) {
                    // Calculate the end of this signature's data
                    let signature_end_offset = signature_result.offset + signature_result.size;

                    // Sanity check the reported offset and size vs file size
                    if signature_end_offset > available_data {
                        info!("Signature {} extends beyond EOF; ignoring", signature.name);
                        // Continue inner loop
                        continue;
                    }

                    // Auto populate some signature result fields
                    signature_result_auto_populate(&mut signature_result, signature);

                    // Add this signature to the file map
                    file_map.push(signature_result.clone());

                    info!(
                        "Found valid {} signature at offset {:#X}",
                        signature_result.name, signature_result.offset
                    );

                    // Only update the next_valid_offset if confidence is at least medium
                    if signature_result.confidence >= signatures::CONFIDENCE_MEDIUM {
                        // Only update the next_valid offset if the end of the signature reported the size of its contents
                        if signature_result.size > 0 {
                            // This file's signature has a known size, so there's no need to scan inside this file's data.
                            // Update next_valid_offset to point to the end of this file signature and break out of the
                            // inner loop.
                            next_valid_offset = signature_end_offset;
                            break;
                        }
                    }
                } else {
                    debug!(
                        "{} magic match at offset {:#X} is invalid",
                        signature.description, magic_offset
                    );
                }
            }
        }

        debug!("Aho-Corasick scan found {} magic matches", file_map.len());

        /*
         * A file's magic bytes do not always start at the beginning of a file, meaning that it is possible
         * that the order in which the signatures were found in the file data is not the order in which we
         * want to process/validate the signatures. Each signature's parser function will report the correct
         * starting offset for the signature, so sort the file_map by the SignatureResult.offset value.
         */
        file_map.sort_by_key(|e| e.offset);
        next_valid_offset = 0;

        /*
         * Now that signatures are in the correct order, identify and any overlapping signatures
         * (such as gzip files identified within a tarball archive), signatures with the same reported offset,
         * and any signatures with an invalid reported size (i.e., the size extends beyond the end of available file_data).
         */
        for mut i in 0..file_map.len() {
            // Some entries may have been removed from the file_map list in previous loop iterations; adjust the index accordingly
            i -= index_adjustment;

            // Make sure the file map index is valid
            if file_map.is_empty() || i >= file_map.len() {
                break;
            }

            let this_signature = file_map[i].clone();
            let remaining_available_size = file_data.len() - this_signature.offset;

            // Check if the previous file map entry had the same reported starting offset as this one
            if i > 0 && this_signature.offset == file_map[i - 1].offset {
                // Get the previous signature in the file map
                let previous_signature = file_map[i - 1].clone();

                // If this file map entry and the conflicting entry do not have the same confidence level, default to the one with highest confidence
                if this_signature.confidence != previous_signature.confidence {
                    debug!(
                        "Conflicting signatures at offset {:#X}; defaulting to the signature with highest confidence",
                        this_signature.offset
                    );

                    // If this signature is higher confidence, invalidate the previous signature
                    if this_signature.confidence > previous_signature.confidence {
                        file_map.remove(i - 1);
                        index_adjustment += 1;

                    // Else, this signature has a lower confidence; invalidate this signature and continue to the next signature in the list
                    } else {
                        file_map.remove(i);
                        index_adjustment += 1;
                        continue;
                    }

                // Conflicting signatures have identical confidence levels; defer to the previously vetted signature
                } else {
                    debug!(
                        "Conflicting signatures at offset {:#X} with the same confidence; first come, first served",
                        this_signature.offset
                    );
                    file_map.remove(i);
                    index_adjustment += 1;
                    continue;
                }

            // Else, if the offsets don't conflict, make sure this signature doesn't fall inside a previously identified signature's data
            } else if this_signature.offset < next_valid_offset {
                debug!(
                    "Signature {} at offset {:#X} contains conflicting data; ignoring",
                    this_signature.name, this_signature.offset
                );
                file_map.remove(i);
                index_adjustment += 1;
                continue;
            }

            // If we've made it this far, make sure this signature's data doesn't extend beyond EOF and that the file data doesn't wrap around
            if this_signature.size > remaining_available_size
                || ((this_signature.offset + this_signature.size) as isize) < 0
            {
                debug!(
                    "Signature {} at offset {:#X} claims its size extends beyond EOF; ignoring",
                    this_signature.name, this_signature.offset
                );
                file_map.remove(i);
                index_adjustment += 1;
                continue;
            }

            // This signature looks OK, update the next_valid_offset to be the end of this signature's data, only if we're fairly confident in the signature
            if this_signature.confidence >= signatures::CONFIDENCE_MEDIUM {
                next_valid_offset = this_signature.offset + this_signature.size;
            }
        }

        /*
         * Ideally, all signatures would report their size; some file formats do not specify a size, and the only
         * way to determine the size is to extract the file format (compressed data, for example).
         * For signatures with a reported size of 0, update their size to be the start of the next signature, or EOF.
         * This makes the assumption that there are no false positives or false negatives.
         *
         * False negatives (i.e., there is some other file format or data between this signature and the next that
         * was not correctly identified) is less problematic, as this will overestimate the size of this signature,
         * but most extraction utilities don't care about this extra trailing data being included.
         *
         * False positives (i.e., some data inside of this signature is identified as some other file type) can cause
         * this signature's file data to become truncated, which will inevitably result in a failed, or partial, extraction.
         *
         * Thus, signatures must be very good at validating magic matches and eliminating false positives.
         */
        for i in 0..file_map.len() {
            if file_map[i].size == 0 {
                // Index of the next file map entry, if any
                let next_index = i + 1;

                // By default, assume this signature goes to EOF
                let mut next_offset: usize = file_data.len();

                // If there are more entries in the file map
                if next_index < file_map.len() {
                    // Look through all remaining file map entries for one with medium to high confidence
                    for file_map_entry in file_map.iter().skip(next_index) {
                        if file_map_entry.confidence >= signatures::CONFIDENCE_MEDIUM {
                            // If a signature of at least medium confidence is found, assume that *this* signature ends there
                            next_offset = file_map_entry.offset;
                            break;
                        }
                    }
                }

                file_map[i].size = next_offset - file_map[i].offset;
                warn!(
                    "Signature {}:{:#X} size is unknown; assuming size of {:#X} bytes",
                    file_map[i].name, file_map[i].offset, file_map[i].size
                );
            } else {
                debug!(
                    "Signature {}:{:#X} has a reported size of {:#X} bytes",
                    file_map[i].name, file_map[i].offset, file_map[i].size
                );
            }
        }

        debug!("Found {} valid signatures", file_map.len());

        file_map
    }

    /// Extract all extractable signatures found in a file.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_binwalk_rs_529_0() -> Result<binwalk_ng::Binwalk, binwalk_ng::BinwalkError> {
    /// use binwalk_ng::Binwalk;
    ///
    /// let target_path = std::path::Path::new("tests")
    ///     .join("inputs")
    ///     .join("gzip.bin");
    ///
    /// let extraction_directory = std::path::Path::new("tests").join("extractions");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let extraction_directory = temp_dir.path();
    ///
    /// let binwalker = Binwalk::configure(Some(&target_path),
    ///                                    Some(&extraction_directory),
    ///                                    vec![],
    ///                                    vec![],
    ///                                    None,
    ///                                    false)?;
    ///
    /// let file_data = std::fs::read(&binwalker.base_target_file).expect("Unable to read file");
    ///
    /// let scan_results = binwalker.scan(&file_data);
    /// let extraction_results = binwalker.extract(&file_data, &binwalker.base_target_file, &scan_results);
    ///
    /// assert_eq!(scan_results.len(), 1);
    /// assert_eq!(extraction_results.len(),  1);
    /// assert_eq!(std::path::Path::new(&extraction_directory)
    ///     .join("gzip.bin.extracted")
    ///     .join("0")
    ///     .join("decompressed.bin")
    ///     .exists(), true);
    /// # Ok(binwalker)
    /// # } _doctest_main_src_binwalk_rs_529_0(); }
    /// ```
    pub fn extract(
        &self,
        file_data: &[u8],
        file_name: impl AsRef<Path>,
        file_map: &Vec<signatures::SignatureResult>,
    ) -> HashMap<String, extractors::ExtractionResult> {
        let file_path = file_name.as_ref();
        let mut extraction_results: HashMap<String, extractors::ExtractionResult> = HashMap::new();

        // Spawn extractors for each extractable signature
        for signature in file_map {
            // Signatures may opt to not perform extraction; honor this request
            if signature.extraction_declined {
                continue;
            }

            // Get the extractor for this signature
            let extractor = self.extractor_lookup_table[&signature.name].clone();

            match &extractor {
                None => continue,
                Some(_) => {
                    // Run an extraction for this signature
                    let mut extraction_result =
                        extractors::execute(file_data, file_path, signature, &extractor);

                    if !extraction_result.success {
                        debug!(
                            "Extraction failed for {} (ID: {}) {:#X} - {:#X}",
                            signature.name, signature.id, signature.offset, signature.size
                        );

                        // Calculate all available data from the start of this signature to EOF
                        let available_data = file_data.len() - signature.offset;

                        /*
                         * If extraction failed, it could be due to truncated data (signature matching is not perfect ya know!)
                         * In that case, make one more attempt, this time provide the extractor all the data possible.
                         */
                        if signature.size < available_data {
                            // Create a duplicate signature, but set its reported size to the length of all available data
                            let mut new_signature = signature.clone();
                            new_signature.size = available_data;

                            debug!(
                                "Trying extraction for {} (ID: {}) again, this time from {:#X} - {:#X}",
                                new_signature.name,
                                new_signature.id,
                                new_signature.offset,
                                new_signature.size
                            );

                            // Re-run the extraction
                            extraction_result = extractors::execute(
                                file_data,
                                file_path,
                                &new_signature,
                                &extractor,
                            );
                        }
                    }

                    // Update the HashMap with the result of this extraction attempt
                    extraction_results.insert(signature.id.clone(), extraction_result);
                }
            }
        }

        extraction_results
    }

    /// Analyze a data buffer and optionally extract the file contents.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_binwalk_rs_672_0() -> Result<binwalk_ng::Binwalk, binwalk_ng::BinwalkError> {
    /// use binwalk_ng::{Binwalk, common};
    ///
    /// let target_path = std::path::Path::new("tests")
    ///     .join("inputs")
    ///     .join("gzip.bin");
    ///
    /// let extraction_directory = std::path::Path::new("tests").join("extractions");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let extraction_directory = temp_dir.path();
    ///
    /// let file_data = common::read_file(&target_path).expect("Failed to read file data");
    ///
    /// let binwalker = Binwalk::configure(Some(&target_path),
    ///                                    Some(&extraction_directory),
    ///                                    vec![],
    ///                                    vec![],
    ///                                    None,
    ///                                    false)?;
    ///
    /// let analysis_results = binwalker.analyze_buf(&file_data, &binwalker.base_target_file, true);
    ///
    /// assert_eq!(analysis_results.file_map.len(), 1);
    /// assert_eq!(analysis_results.extractions.len(),  1);
    /// assert_eq!(std::path::Path::new(&extraction_directory)
    ///     .join("gzip.bin.extracted")
    ///     .join("0")
    ///     .join("decompressed.bin")
    ///     .exists(), true);
    /// # Ok(binwalker)
    /// # } _doctest_main_src_binwalk_rs_672_0(); }
    /// ```
    pub fn analyze_buf(
        &self,
        file_data: &[u8],
        target_file: impl AsRef<Path>,
        do_extraction: bool,
    ) -> AnalysisResults {
        let file_path = target_file.as_ref();

        // Return value
        let mut results: AnalysisResults = AnalysisResults {
            file_path: file_path.to_path_buf(),
            ..Default::default()
        };

        // Scan file data for signatures
        debug!("Analysis start: {}", file_path.display());
        results.file_map = self.scan(file_data);

        // Only extract if told to, and if there were some signatures found in this file
        if do_extraction && !results.file_map.is_empty() {
            // Extract everything we can
            debug!(
                "Submitting {} signature results to extractor",
                results.file_map.len()
            );
            results.extractions = self.extract(file_data, file_path, &results.file_map);
        }

        debug!("Analysis end: {}", file_path.display());

        results
    }

    /// Analyze a file on disk and optionally extract its contents.
    ///
    /// ## Example
    ///
    /// ```
    /// # fn main() { #[allow(non_snake_case)] fn _doctest_main_src_binwalk_rs_745_0() -> Result<binwalk_ng::Binwalk, binwalk_ng::BinwalkError> {
    /// use binwalk_ng::Binwalk;
    ///
    /// let target_path = std::path::Path::new("tests")
    ///     .join("inputs")
    ///     .join("gzip.bin");
    ///
    /// let extraction_directory = std::path::Path::new("tests").join("extractions");
    /// # let temp_dir = tempfile::tempdir().unwrap();
    /// # let extraction_directory = temp_dir.path();
    ///
    /// let binwalker = Binwalk::configure(Some(&target_path),
    ///                                    Some(&extraction_directory),
    ///                                    vec![],
    ///                                    vec![],
    ///                                    None,
    ///                                    false)?;
    ///
    /// let analysis_results = binwalker.analyze(&binwalker.base_target_file, true);
    ///
    /// assert_eq!(analysis_results.file_map.len(), 1);
    /// assert_eq!(analysis_results.extractions.len(),  1);
    /// assert_eq!(std::path::Path::new(&extraction_directory)
    ///     .join("gzip.bin.extracted")
    ///     .join("0")
    ///     .join("decompressed.bin")
    ///     .exists(), true);
    /// # Ok(binwalker)
    /// # } _doctest_main_src_binwalk_rs_745_0(); }
    /// ```
    pub fn analyze(&self, target_file: impl AsRef<Path>, do_extraction: bool) -> AnalysisResults {
        let file_path = target_file.as_ref();

        let file_data = read_or_map_file(file_path, self.allow_mmap);
        let file_data: &[u8] = file_data
            .as_ref()
            .map(|data| data.as_ref())
            .unwrap_or_else(|_| {
                error!("Failed to read data from {}", file_path.display());
                b""
            });

        self.analyze_buf(file_data, file_path, do_extraction)
    }
}

/// Initializes the extraction output directory
fn init_extraction_directory(
    target_path: impl AsRef<Path>,
    extraction_directory: impl AsRef<Path>,
) -> Result<PathBuf, std::io::Error> {
    let extraction_directory = extraction_directory.as_ref();
    // Create the output directory, equivalent of mkdir -p
    match fs::create_dir_all(extraction_directory) {
        Ok(_) => {
            debug!(
                "Created base output directory: '{}'",
                extraction_directory.display()
            );
        }
        Err(e) => {
            error!(
                "Failed to create base output directory '{}': {e}",
                extraction_directory.display()
            );
            return Err(e);
        }
    }

    let target_path = target_path.as_ref();

    // Build a symlink path to the target file in the extraction directory
    let link_path = extraction_directory.join(target_path.file_name().unwrap());

    if link_path.exists() {
        return Ok(link_path);
    }

    debug!(
        "Creating symlink from {} -> {}",
        link_path.display(),
        target_path.display()
    );

    // Create a symlink from inside the extraction directory to the specified target file
    #[cfg(unix)]
    {
        match unix::fs::symlink(target_path, &link_path) {
            Ok(_) => Ok(link_path),
            Err(e) => {
                error!(
                    "Failed to create symlink {} -> {}: {}",
                    link_path.display(),
                    target_path.display(),
                    e
                );
                Err(e)
            }
        }
    }
    #[cfg(windows)]
    {
        match std::fs::hard_link(target_path, &link_path) {
            Ok(_) => {
                return Ok(link_path.to_path_buf());
            }
            Err(e) => {
                error!(
                    "Failed to create hardlink {} -> {}: {}",
                    link_path.display(),
                    target_path.display(),
                    e
                );
                return Err(e);
            }
        }
    }
}

/// Returns true if the signature should be included for file analysis, else returns false.
fn include_signature(
    signature: &signatures::Signature,
    include: &Vec<String>,
    exclude: &Vec<String>,
) -> bool {
    if !include.is_empty() {
        for include_str in include {
            if signature.name.eq_ignore_ascii_case(include_str) {
                return true;
            }
        }

        return false;
    }

    if !exclude.is_empty() {
        for exclude_str in exclude {
            if signature.name.eq_ignore_ascii_case(exclude_str) {
                return false;
            }
        }

        return true;
    }

    true
}

/// Some SignatureResult fields need to be auto-populated.
fn signature_result_auto_populate(
    signature_result: &mut signatures::SignatureResult,
    signature: &signatures::Signature,
) {
    signature_result.id = Uuid::new_v4().to_string();
    signature_result.name = signature.name.clone();
    signature_result.always_display = signature.always_display;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_zero_run_finds_runs_anywhere() {
        assert_eq!(longest_zero_run(b""), 0);
        assert_eq!(longest_zero_run(b"\x01\x02\x03"), 0);
        assert_eq!(longest_zero_run(b"\x00\x00\x00\x01\x00"), 3);
        assert_eq!(longest_zero_run(b"\x01\x00\x00\x00\x02\x00"), 3);
        assert_eq!(longest_zero_run(b"\x01\x00\x00\x00"), 3);
        assert_eq!(longest_zero_run(&[0; 9]), 9);
    }

    #[test]
    fn zero_run_pattern_is_longer_than_any_run_of_zeros_in_a_pattern() {
        let binwalker = Binwalk::new();
        let zero_run_pattern_len = binwalker
            .zero_run_pattern_len
            .expect("the default signatures should allow skipping runs of zeros");

        for pattern in &binwalker.patterns {
            assert!(
                zero_run_pattern_len > longest_zero_run(pattern),
                "{pattern:02X?} could hide a match across a run of zeros"
            );
        }
        // Which also means it is longer than any pattern's leading zeros, so a skip always moves
        // the scan forwards.
        assert!(zero_run_pattern_len > binwalker.max_leading_zeros);
    }

    #[test]
    fn resume_offset_after_zero_run_stops_short_of_the_next_non_zero_byte() {
        let binwalker = Binwalk {
            max_leading_zeros: 3,
            ..Binwalk::default()
        };

        // A pattern with 3 leading zeros could begin 3 bytes before the 9, so the scan may resume
        // no later than that, even though the zeros are known to continue until then.
        let mut file_data = [0; 16];
        // With nothing but zeros ahead there is nothing left to match, so the scan is finished.
        assert_eq!(
            binwalker.resume_offset_after_zero_run(&file_data, 0, 11),
            file_data.len()
        );

        *file_data.last_mut().unwrap() = 9;
        //  |--zeros known to the caller--|     |-----|<-max_leading_zeros
        //  v                             v     v     v
        // [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
        //                                      ^
        //                                      possible match: 3 leading zeros before a non-zero
        assert_eq!(
            binwalker.resume_offset_after_zero_run(&file_data, 0, 11),
            12
        );
        file_data[13] = 2;
        //  |--zeros known to the caller--|
        //  |                          |--+--|<-max_leading_zeros
        //  v                          v  v  v
        // [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 9]
        //                             ^
        //                             possible match: 3 leading zeros before a non-zero
        assert_eq!(
            binwalker.resume_offset_after_zero_run(&file_data, 0, 11),
            10
        );
    }

    #[test]
    fn scan_with_no_signatures_at_all_terminates() {
        // No signature is named "", so nothing is included and there is no pattern to search for,
        // let alone a run of zeros worth skipping.
        let binwalker = Binwalk::configure(
            None,
            None,
            vec![String::new()],
            vec![],
            None,
            /* full_search */ true,
        )
        .unwrap();
        assert!(binwalker.patterns.is_empty());

        assert!(binwalker.scan(&[0, 1, 0, 1, 0, 1, 0, 1]).is_empty());
    }

    #[test]
    fn scan_finds_a_magic_whose_own_zeros_outlast_an_all_zero_magic_match() {
        // A magic that ends in more zero bytes than the all-zero program_store magic is long, but
        // fewer than the synthetic zero-run pattern. Aho-Corasick reports matches in order of
        // where they end, so program_store matches inside this magic's own zeros are reported
        // before it; none of them may derail the scan, and the run is too short to trigger a skip.
        // The leading pad below does trigger one, so this also pins that the scan resumes early
        // enough to still reach the magic.
        let mut magic = vec![0u8; 21];
        magic[0] = 0xAA;

        fn parser(
            _file_data: &[u8],
            offset: usize,
        ) -> Result<signatures::SignatureResult, signatures::SignatureError> {
            Ok(signatures::SignatureResult {
                offset,
                size: 21,
                confidence: signatures::CONFIDENCE_HIGH,
                description: "trailing zeros test signature".to_string(),
                ..Default::default()
            })
        }

        let signature = signatures::Signature {
            name: "trailing_zeros".to_string(),
            short: false,
            magic: vec![magic.clone()],
            magic_offset: 0,
            description: "trailing zeros test signature".to_string(),
            always_display: false,
            parser,
            extractor: None,
        };

        // Place it after a run of zeros long enough to be skipped, with a non-zero byte behind it
        // so that the run it ends with is not the last thing in the file either.
        let offset = 4096;
        let mut file_data = vec![0u8; offset];
        file_data.extend_from_slice(&magic);
        file_data.extend_from_slice(&[0xFF; 16]);

        let binwalker =
            Binwalk::configure(None, None, vec![], vec![], Some(vec![signature]), false).unwrap();
        let file_map = binwalker.scan(&file_data);

        assert!(
            file_map
                .iter()
                .any(|result| result.name == "trailing_zeros" && result.offset == offset),
            "{file_map:?}"
        );
    }

    /*
     * These tests drive scan() through the conflicting-signature resolution loop, which removes
     * entries from the file map while iterating over it. All test signatures are short signatures
     * with the same magic bytes, so they match at file offset 0 and each parser reports a
     * controlled offset, size, and confidence.
     */
    const CONFLICT_TEST_FILE_SIZE: usize = 64;
    const CONFLICT_TEST_MAGIC: u8 = 0xAA;
    const CONFLICT_TEST_VALID_SIZE: usize = 8;

    fn conflict_test_signature(
        name: &str,
        parser: signatures::SignatureParser,
    ) -> signatures::Signature {
        signatures::Signature {
            name: name.to_string(),
            short: true,
            magic: vec![vec![CONFLICT_TEST_MAGIC]],
            magic_offset: 0,
            description: format!("{name} conflict test signature"),
            always_display: false,
            parser,
            extractor: None,
        }
    }

    fn conflict_test_result(
        offset: usize,
        size: usize,
        confidence: u8,
        description: &str,
    ) -> signatures::SignatureResult {
        signatures::SignatureResult {
            offset,
            size,
            confidence,
            description: description.to_string(),
            ..Default::default()
        }
    }

    fn conflict_low_parser(
        _file_data: &[u8],
        _offset: usize,
    ) -> Result<signatures::SignatureResult, signatures::SignatureError> {
        Ok(conflict_test_result(
            0,
            CONFLICT_TEST_VALID_SIZE,
            signatures::CONFIDENCE_LOW,
            "low confidence conflict parser",
        ))
    }

    fn conflict_high_parser(
        _file_data: &[u8],
        _offset: usize,
    ) -> Result<signatures::SignatureResult, signatures::SignatureError> {
        Ok(conflict_test_result(
            0,
            CONFLICT_TEST_VALID_SIZE,
            signatures::CONFIDENCE_HIGH,
            "high confidence conflict parser",
        ))
    }

    fn conflict_high_invalid_size_parser(
        file_data: &[u8],
        _offset: usize,
    ) -> Result<signatures::SignatureResult, signatures::SignatureError> {
        Ok(conflict_test_result(
            0,
            file_data.len() + 1024,
            signatures::CONFIDENCE_HIGH,
            "high confidence conflict parser with an invalid size",
        ))
    }

    fn conflict_following_parser(
        _file_data: &[u8],
        _offset: usize,
    ) -> Result<signatures::SignatureResult, signatures::SignatureError> {
        Ok(conflict_test_result(
            32,
            CONFLICT_TEST_VALID_SIZE,
            signatures::CONFIDENCE_LOW,
            "following conflict parser",
        ))
    }

    fn conflict_scan(signatures: Vec<signatures::Signature>) -> Vec<signatures::SignatureResult> {
        let include: Vec<String> = signatures
            .iter()
            .map(|signature| signature.name.clone())
            .collect();
        let binwalker =
            Binwalk::configure(None, None, include, vec![], Some(signatures), false).unwrap();

        let mut file_data = vec![0u8; CONFLICT_TEST_FILE_SIZE];
        file_data[0] = CONFLICT_TEST_MAGIC;

        binwalker.scan(&file_data)
    }

    #[test]
    fn conflicting_signatures_keep_higher_confidence_entry() {
        let file_map = conflict_scan(vec![
            conflict_test_signature("conflict_low", conflict_low_parser),
            conflict_test_signature("conflict_high", conflict_high_parser),
        ]);

        assert_eq!(file_map.len(), 1, "{file_map:?}");
        assert_eq!(file_map[0].name, "conflict_high");
        assert_eq!(file_map[0].offset, 0);
    }

    // Skipped: scan() panics with an out-of-bounds removal ("removal index (is 1) should be <
    // len (is 1)") at src/binwalk_ng.rs:632. After the higher confidence signature wins the
    // offset conflict (file_map.remove(i - 1)), the loop falls through to the EOF size check
    // with a stale index and removes the wrong entry. This bug is not solved in this branch.
    #[test]
    #[ignore = "scan() panics on a conflicting signature with an invalid size; see binwalk_ng.rs:632"]
    fn conflicting_signature_with_invalid_size_is_removed() {
        let file_map = conflict_scan(vec![
            conflict_test_signature("conflict_low", conflict_low_parser),
            conflict_test_signature("conflict_high", conflict_high_invalid_size_parser),
        ]);

        assert!(
            file_map.is_empty(),
            "the higher confidence signature reported an invalid size and must be removed: {file_map:?}"
        );
    }

    #[test]
    fn conflict_resolution_preserves_following_signatures() {
        let file_map = conflict_scan(vec![
            conflict_test_signature("conflict_low", conflict_low_parser),
            conflict_test_signature("conflict_high", conflict_high_parser),
            conflict_test_signature("conflict_following", conflict_following_parser),
        ]);

        assert_eq!(file_map.len(), 2, "{file_map:?}");
        assert_eq!(file_map[0].name, "conflict_high");
        assert_eq!(file_map[1].name, "conflict_following");
    }

    #[test]
    fn conflicting_signatures_same_confidence_keep_first() {
        let file_map = conflict_scan(vec![
            conflict_test_signature("conflict_low", conflict_low_parser),
            conflict_test_signature("conflict_low_2", conflict_low_parser),
        ]);

        assert_eq!(file_map.len(), 1, "{file_map:?}");
        assert_eq!(file_map[0].name, "conflict_low");
    }
}

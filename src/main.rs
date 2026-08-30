use binwalk_ng::extractors::Chroot;
use binwalk_ng::{AnalysisResults, MmapUsage, common, extractors};
use clap::Parser;
use log::{debug, error, info};
use rayon::ThreadPool;
use std::ffi::OsStr;
use std::path;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time;
use std::{fs, panic};

#[cfg(unix)]
use std::os::unix;

mod cli_parser;
mod display;
#[cfg(feature = "entropy-plot")]
mod entropy;
mod json;

fn main() -> ExitCode {
    // Only use one thread if unable to auto-detect available core info
    const DEFAULT_WORKER_COUNT: usize = 1;

    // Number of seconds to wait before printing debug progress info
    const PROGRESS_INTERVAL: time::Duration = time::Duration::from_secs(30);

    // If this env var is set during extraction, the symlink to the target file will
    // be deleted at the end of extraction.
    const BINWALK_RM_SYMLINK: &str = "BINWALK_RM_EXTRACTION_SYMLINK";

    // Statistics variables; keeps track of analyzed file count and total analysis run time
    let mut file_count: usize = 0;
    let run_time = time::Instant::now();

    // Initialize logging with local timezone timestamps
    env_logger::Builder::from_env(env_logger::Env::default())
        .format(|buf, record| {
            use std::io::Write;
            let timestamp = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z");
            writeln!(
                buf,
                "[{} {} {}] {}",
                timestamp,
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    // Process command line arguments
    let cli_args = cli_parser::CliArgs::parse();

    // If --list was specified, just display a list of signatures and return
    if cli_args.list {
        display::print_signature_list(&binwalk_ng::magic::patterns());
        return ExitCode::SUCCESS;
    }

    let mut json_logger = json::JsonLogger::new(cli_args.log.as_deref());

    if cli_args.entropy {
        #[cfg(not(feature = "entropy-plot"))]
        {
            error!(
                "binwalk was built without the \"entropy-plot\" feature, entropy analysis isn't available"
            );
            return ExitCode::FAILURE;
        }

        #[cfg(feature = "entropy-plot")]
        {
            let (entropy_results, png_path) =
                match entropy::plot(cli_args.file_name.unwrap(), cli_args.png.as_deref()) {
                    Ok(results) => results,
                    Err(e) => {
                        error!("Entropy analysis failed: {e}");
                        return ExitCode::FAILURE;
                    }
                };

            json_logger.log(json::JSONType::Entropy(&entropy_results));
            json_logger.close();

            let graph_path_message = format!("Entropy graph saved to '{}'", png_path.display());
            if cli_args.log.as_deref() == Some(Path::new("-")) {
                if !cli_args.quiet {
                    eprintln!("{graph_path_message}");
                }
            } else {
                display::println_plain(cli_args.quiet, &graph_path_message);
            }

            return ExitCode::SUCCESS;
        }
    }

    /*
     * Analysis and extraction results are written relative to the target file path, so it
     * must be absolute: the symlink created below lives in the output directory, which may
     * be anywhere on the file system.
     */
    let target_file = match path::absolute(cli_args.file_name.unwrap()) {
        Ok(path) => path,
        Err(e) => {
            error!("Failed to get an absolute path for the target file: {e}");
            return ExitCode::FAILURE;
        }
    };

    /*
     * If extraction or data carving was requested, everything is written to the output
     * directory. Analyze a symlink to the target file inside that directory, so that all
     * output lands there rather than beside the target file itself.
     */
    let target_file = if cli_args.extract || cli_args.carve {
        match init_extraction_directory(&target_file, &cli_args.directory) {
            Ok(symlink_path) => symlink_path,
            Err(e) => {
                error!("Failed to initialize extraction directory: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        target_file
    };

    // Initialize binwalk
    let binwalker = match binwalk_ng::Binwalk::builder()
        .includes(cli_args.include)
        .excludes(cli_args.exclude)
        .full_search(cli_args.search_all)
        .mmap_usage(if cli_args.no_mmap {
            MmapUsage::Never
        } else {
            MmapUsage::WhenPossible
        })
        .build()
    {
        Ok(binwalker) => Arc::new(binwalker),
        Err(e) => {
            error!("Binwalk initialization failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // If the user specified --threads, honor that request; else, auto-detect available parallelism
    let available_workers = cli_args.threads.map(|t| t as usize).unwrap_or_else(|| {
        // Get CPU core info
        match thread::available_parallelism() {
            // In case of error use the default
            Err(e) => {
                error!("Failed to retrieve CPU core info: {e}");
                DEFAULT_WORKER_COUNT
            }
            Ok(coreinfo) => coreinfo.get(),
        }
    });

    // Initialize thread pool
    debug!("Initializing thread pool with {available_workers} workers");
    let workers = match rayon::ThreadPoolBuilder::new()
        .num_threads(available_workers)
        .build()
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to create thread pool with {available_workers} workers: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (worker_tx, worker_rx) = mpsc::channel();

    /*
     * Set a custom panic handler.
     * This ensures that when any thread panics, the default panic handler will be invoked
     * _and_ the entire process will exit with an error code.
     */
    let default_panic_handler = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_handler(panic_info);
        process::exit(-1);
    }));

    let verbosity = match (cli_args.quiet, cli_args.verbose) {
        (true, _) => Verbosity::Quiet,
        (_, true) => Verbosity::Verbose,
        _ => Verbosity::Normal,
    };

    let flags = AnalysisFlags {
        verbosity,
        do_extract: cli_args.extract,
        matryoshka: cli_args.matryoshka,
    };

    debug!("Queuing initial target file: {}", target_file.display(),);
    // Files waiting to be analyzed, start with the base file only.
    // In matryoshka mode, grows as new nested files are discovered in extraction results
    let mut target_files = vec![target_file.clone()];
    let mut outstanding_files = 0u64;
    let mut next_progress = time::Instant::now() + PROGRESS_INTERVAL;
    /*
     * Main loop.
     * Loop until all pending thread jobs are complete and there are no more files in the queue.
     */
    while !target_files.is_empty() || outstanding_files > 0 {
        // Drain any queued files into the thread pool
        #[allow(clippy::iter_with_drain)] // https://github.com/rust-lang/rust-clippy/issues/8539
        for target_file in target_files.drain(..) {
            outstanding_files += 1;
            spawn_worker(
                &workers,
                binwalker.clone(),
                target_file,
                cli_args.extract,
                cli_args.carve,
                worker_tx.clone(),
            );
        }

        debug_assert!(target_files.is_empty() && outstanding_files > 0);
        if let Ok(results) =
            worker_rx.recv_timeout(next_progress.saturating_duration_since(time::Instant::now()))
        {
            process_analysis_results(
                results,
                &mut file_count,
                &mut json_logger,
                flags,
                &mut target_files,
            );
            outstanding_files -= 1;
        }
        if time::Instant::now() >= next_progress {
            // Some debug info on analysis progress
            info!(
                "Status: pending tasks: {}/{}",
                outstanding_files, available_workers,
            );
            next_progress = time::Instant::now() + PROGRESS_INTERVAL;
        }
    }

    json_logger.close();

    // If BINWALK_RM_SYMLINK env var was set, delete the target file symlink
    if (cli_args.carve || cli_args.extract)
        && std::env::var(BINWALK_RM_SYMLINK).is_ok()
        && let Err(e) = fs::remove_file(&target_file)
    {
        error!(
            "Request to remove extraction symlink file {} failed: {}",
            target_file.display(),
            e
        );
    }

    // All done, show some basic statistics
    if !cli_args.quiet {
        display::print_stats(
            run_time,
            file_count,
            binwalker.signature_count(),
            binwalker.pattern_count(),
        );
    }

    ExitCode::SUCCESS
}

/// Initializes the extraction output directory, creating it if it does not already exist,
/// and placing a symlink to the target file inside it.
///
/// Returns the path to that symlink, which is the path to analyze: extraction and carving
/// write their output relative to the analyzed file's path, so analyzing the symlink is
/// what keeps all output inside the extraction directory.
///
/// A symlink left by a previous run is always replaced, so it cannot still point at some
/// earlier target of the same name. Any other pre-existing entry is an error, rather than
/// something to analyze in the target's place or to delete.
fn init_extraction_directory(
    target_path: &Path,
    extraction_directory: &Path,
) -> Result<PathBuf, std::io::Error> {
    let extraction_directory = path::absolute(extraction_directory)?;

    // Create the output directory, equivalent of mkdir -p
    match fs::create_dir_all(&extraction_directory) {
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

    // Build a symlink path to the target file in the extraction directory
    let Some(file_name) = target_path.file_name() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "'{}' does not name a file to analyze",
                target_path.display()
            ),
        ));
    };
    let link_path = extraction_directory.join(file_name);

    // The target already lives in the extraction directory, so there is nothing to link
    if link_path == target_path {
        return Ok(link_path);
    }

    /*
     * Always recreate the link, so it cannot be left over from an earlier run pointing at
     * a different file that happened to have the same name. Only a symlink is ours to
     * remove; anything else here belongs to the user, and neither analyzing it in the
     * target's place nor deleting it would be right.
     */
    match fs::symlink_metadata(&link_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(metadata) => {
            if !metadata.is_symlink() {
                error!(
                    "'{}' already exists and was not created by binwalk, refusing to replace it",
                    link_path.display()
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "'{}' already exists; use a different --directory",
                        link_path.display()
                    ),
                ));
            }
            fs::remove_file(&link_path)?;
        }
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
        match fs::hard_link(target_path, &link_path) {
            Ok(_) => Ok(link_path),
            Err(e) => {
                error!(
                    "Failed to create hardlink {} -> {}: {}",
                    link_path.display(),
                    target_path.display(),
                    e
                );
                Err(e)
            }
        }
    }
}

/// Returns true if the specified results should be displayed to screen
fn should_display(verbosity: Verbosity, results: &AnalysisResults, file_count: usize) -> bool {
    /*
     * For brevity, when analyzing more than one file only display subsequent files whose results
     * contain signatures that we always want displayed, or which contain extractable signatures.
     */
    if verbosity == Verbosity::Quiet {
        return false;
    }
    if verbosity == Verbosity::Verbose || file_count == 1 || !results.extractions.is_empty() {
        true
    } else {
        results
            .file_map
            .iter()
            .any(|signature| signature.always_display)
    }
}

#[derive(Clone, Copy)]
struct AnalysisFlags {
    verbosity: Verbosity,
    do_extract: bool,
    matryoshka: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

/// Process analysis results from a worker: log, display, and queue nested files.
fn process_analysis_results(
    results: AnalysisResults,
    file_count: &mut usize,
    json_logger: &mut json::JsonLogger,
    flags: AnalysisFlags,
    target_files: &mut Vec<PathBuf>,
) {
    *file_count += 1;
    json_logger.log(json::JSONType::Analysis(&results));

    if results.file_map.is_empty() {
        debug!("Found no results for file {}", results.file_path.display());
        return;
    }

    if should_display(flags.verbosity, &results, *file_count) {
        display::print_analysis_results(flags.do_extract, &results);
    }

    if flags.matryoshka {
        for r in results
            .extractions
            .into_values()
            .filter(|r| !r.do_not_recurse)
        {
            let files = extractors::get_extracted_files(&r.output_directory);
            debug!("Queuing {} files for analysis", files.len());
            target_files.extend(files);
        }
    }
}

/// Spawn a worker thread to analyze a file
fn spawn_worker(
    pool: &ThreadPool,
    bw: Arc<binwalk_ng::Binwalk>,
    target_file: PathBuf,
    do_extraction: bool,
    do_carve: bool,
    worker_tx: mpsc::Sender<AnalysisResults>,
) {
    pool.spawn(move || {
        // Read in file data
        let file_data = common::read_or_map_file(&target_file, bw.mmap_usage());
        let file_data: &[u8] = file_data
            .as_ref()
            .map(|data| data.as_ref())
            .unwrap_or_else(|_| {
                error!("Failed to read {} data", target_file.display());
                b""
            });

        // Analyze target file, with extraction, if specified
        let mut extract_to = None;
        if do_extraction {
            extract_to = extractors::extraction_directory(&target_file);
            if extract_to.is_none() {
                error!(
                    "Skipping extraction of {}: it has no file name to derive an extraction directory from",
                    target_file.display()
                );
            }
        }
        let results = bw.analyze_buf(file_data, &target_file, extract_to.as_deref());

        // If data carving was requested as part of extraction, carve analysis results to disk
        if do_carve {
            let carve_count = carve_file_map(
                file_data,
                &results,
                target_file.parent().unwrap_or_else(|| Path::new("")),
                target_file.file_name().unwrap_or_default(),
            );
            info!(
                "Carved {carve_count} data blocks to disk from {}",
                target_file.display()
            );
        }

        // Report file results back to main thread
        if let Err(e) = worker_tx.send(results) {
            error!(
                "Worker thread for {} failed to send results back to main thread: {e}",
                target_file.display()
            );
        }
    });
}

/// Carve signatures identified during analysis to separate files on disk.
/// Returns the number of carved files created.
/// Note that unknown blocks of file data are also carved to disk, so the number of files
/// created may be larger than the number of results defined in results.file_map.
///
/// Carved files are written to `output_directory`, named after `file_name`. The analyzed
/// file's name is included so that carved data from several files extracted into the same
/// directory remains distinguishable.
fn carve_file_map(
    file_data: &[u8],
    results: &binwalk_ng::AnalysisResults,
    output_directory: &Path,
    file_name: &OsStr,
) -> usize {
    let mut carve_count: usize = 0;
    let mut last_known_offset: usize = 0;
    let mut unknown_bytes: Vec<(usize, usize)> = Vec::new();

    // No results, don't do anything
    if !results.file_map.is_empty() {
        // Loop through all identified signatures in the file
        for signature_result in &results.file_map {
            // If there is data between the last signature and this signature, it is some chunk of unknown data
            if signature_result.offset > last_known_offset {
                unknown_bytes.push((
                    last_known_offset,
                    signature_result.offset - last_known_offset,
                ));
            }

            // Carve this signature's data to disk
            if carve_file_data_to_disk(
                output_directory,
                file_name,
                file_data,
                &signature_result.name,
                signature_result.offset,
                signature_result.size,
            ) {
                carve_count += 1;
            }

            // Update the last known offset to the end of this signature's data
            last_known_offset = signature_result.offset + signature_result.size;
        }

        // Calculate the size of any remaining data from the end of the last signature to EOF
        let remaining_data = file_data.len() - last_known_offset;

        // Add any remaining unknown data to the unknown_bytes list
        if remaining_data > 0 {
            unknown_bytes.push((last_known_offset, remaining_data));
        }

        // All known signature data has been carved to disk, now carve any unknown blocks of data to disk
        for (offset, size) in unknown_bytes {
            if carve_file_data_to_disk(
                output_directory,
                file_name,
                file_data,
                "unknown",
                offset,
                size,
            ) {
                carve_count += 1;
            }
        }
    }

    carve_count
}

/// Carves a block of file data to a new file on disk
fn carve_file_data_to_disk(
    output_directory: &Path,
    file_name: &OsStr,
    file_data: &[u8],
    name: &str,
    offset: usize,
    size: usize,
) -> bool {
    let chroot = Chroot::default();

    // Carved file path will be: <output directory>/<file name>_<offset>_<name>.raw
    let mut carved_file_name = file_name.to_os_string();
    carved_file_name.push(format!("_{offset}_{name}.raw"));
    let carved_file_path = output_directory.join(carved_file_name);

    debug!("Carving {}", carved_file_path.display());

    // Carve the data to disk
    if !chroot.carve_file(&carved_file_path, file_data, offset, size) {
        error!(
            "Failed to carve {} [{:#X}..{:#X}] to disk",
            carved_file_path.display(),
            offset,
            offset + size,
        );
        return false;
    }

    true
}

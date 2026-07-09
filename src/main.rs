use binwalk_ng::extractors::Chroot;
use binwalk_ng::{AnalysisResults, common, extractors};
use clap::Parser;
use log::{debug, error, info};
use rayon::ThreadPool;
use std::collections::VecDeque;
use std::panic;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time;

mod cli_parser;
mod display;
#[cfg(feature = "entropy-plot")]
mod entropy;
mod json;

fn main() -> ExitCode {
    // Only use one thread if unable to auto-detect available core info
    const DEFAULT_WORKER_COUNT: usize = 1;

    // Number of seconds to wait before printing debug progress info
    const PROGRESS_INTERVAL: u64 = 30;

    // If this env var is set during extraction, the Binwalk.base_target_file symlink will
    // be deleted at the end of extraction.
    const BINWALK_RM_SYMLINK: &str = "BINWALK_RM_EXTRACTION_SYMLINK";

    // Output directory for extracted files
    let mut output_directory: Option<PathBuf> = None;

    /*
     * Queue of files waiting to be analyzed.
     * Grows when matryoshka mode discovers nested files in extraction results.
     */
    let mut target_files = VecDeque::new();

    // Statistics variables; keeps track of analyzed file count and total analysis run time
    let mut file_count: usize = 0;
    let run_time = time::Instant::now();
    let mut last_progress_interval = time::Instant::now();

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
        display::print_signature_list(cli_args.quiet, &binwalk_ng::magic::patterns());
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
            // generate the entropy graph and return
            display::print_plain(cli_args.quiet, "Calculating file entropy...");

            if let Ok(entropy_results) =
                entropy::plot(cli_args.file_name.unwrap(), cli_args.png.as_deref())
            {
                // Log entropy results to JSON file, if requested
                json_logger.log(json::JSONType::Entropy(entropy_results));
                json_logger.close();

                display::println_plain(cli_args.quiet, "done.");
            } else {
                error!("Entropy analysis failed!");
                return ExitCode::FAILURE;
            }

            return ExitCode::SUCCESS;
        }
    }

    // If extraction or data carving was requested, we need to initialize the output directory
    if cli_args.extract || cli_args.carve {
        output_directory = Some(cli_args.directory);
    }

    // Initialize binwalk
    let binwalker = match binwalk_ng::Binwalk::configure(
        cli_args.file_name.as_deref(),
        output_directory.as_deref(),
        cli_args.include,
        cli_args.exclude,
        None,
        cli_args.search_all,
    ) {
        Err(e) => {
            error!("Binwalk initialization failed: {}", e.message);
            return ExitCode::FAILURE;
        }
        Ok(bw) => bw,
    };

    // If the user specified --threads, honor that request; else, auto-detect available parallelism
    let available_workers = cli_args.threads.unwrap_or_else(|| {
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
    let pending = Arc::new(AtomicUsize::new(0));
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

    debug!(
        "Queuing initial target file: {}",
        binwalker.base_target_file.display()
    );

    // Queue the initial file path
    target_files.push_back(binwalker.base_target_file.clone());

    let flags = AnalysisFlags {
        verbose: cli_args.verbose,
        quiet: cli_args.quiet,
        do_extract: cli_args.extract,
        matryoshka: cli_args.matryoshka,
    };

    /*
     * Main loop.
     * Loop until all pending thread jobs are complete and there are no more files in the queue.
     */
    loop {
        // Drain any queued files into the thread pool
        while let Some(target_file) = target_files.pop_front() {
            spawn_worker(
                &workers,
                binwalker.clone(),
                target_file,
                cli_args.extract,
                cli_args.carve,
                worker_tx.clone(),
                pending.clone(),
            );
        }

        // Don't spin CPU cycles if there is no backlog of files to analyze
        if target_files.is_empty() {
            let sleep_time = time::Duration::from_millis(1);
            thread::sleep(sleep_time);
        }

        // Some debug info on analysis progress
        if last_progress_interval.elapsed().as_secs() >= PROGRESS_INTERVAL {
            info!(
                "Status: pending tasks: {}/{}, files waiting in queue: {}",
                pending.load(Ordering::Acquire),
                available_workers,
                target_files.len()
            );
            last_progress_interval = time::Instant::now();
        }

        // Drain all available results from the channel
        while let Ok(results) = worker_rx.try_recv() {
            process_analysis_results(
                results,
                &mut file_count,
                &mut json_logger,
                flags,
                &mut target_files,
            );
        }

        // Exit only when no work remains and the channel is truly empty
        if pending.load(Ordering::Acquire) == 0 && target_files.is_empty() {
            match worker_rx.try_recv() {
                Ok(results) => {
                    process_analysis_results(
                        results,
                        &mut file_count,
                        &mut json_logger,
                        flags,
                        &mut target_files,
                    );
                }
                Err(_) => break,
            }
        }
    }

    json_logger.close();

    // If BINWALK_RM_SYMLINK env var was set, delete the base_target_file symlink
    if (cli_args.carve || cli_args.extract)
        && std::env::var(BINWALK_RM_SYMLINK).is_ok()
        && let Err(e) = std::fs::remove_file(&binwalker.base_target_file)
    {
        error!(
            "Request to remove extraction symlink file {} failed: {}",
            binwalker.base_target_file.display(),
            e
        );
    }

    // All done, show some basic statistics
    display::print_stats(
        cli_args.quiet,
        run_time,
        file_count,
        binwalker.signature_count,
        binwalker.pattern_count,
    );

    ExitCode::SUCCESS
}

/// Returns true if the specified results should be displayed to screen
fn should_display(results: &AnalysisResults, file_count: usize, verbose: bool) -> bool {
    /*
     * For brevity, when analyzing more than one file only display subsequent files whose results
     * contain signatures that we always want displayed, or which contain extractable signatures.
     * This can be overridden with the --verbose command line flag.
     */
    if file_count == 1 || verbose || !results.extractions.is_empty() {
        return true;
    } else {
        for signature in &results.file_map {
            if signature.always_display {
                return true;
            }
        }
    }

    false
}

#[derive(Clone, Copy)]
struct AnalysisFlags {
    verbose: bool,
    quiet: bool,
    do_extract: bool,
    matryoshka: bool,
}

/// Process analysis results from a worker: log, display, and queue nested files.
fn process_analysis_results(
    results: AnalysisResults,
    file_count: &mut usize,
    json_logger: &mut json::JsonLogger,
    flags: AnalysisFlags,
    target_files: &mut VecDeque<PathBuf>,
) {
    *file_count += 1;
    json_logger.log(json::JSONType::Analysis(results.clone()));

    if results.file_map.is_empty() {
        debug!("Found no results for file {}", results.file_path.display());
        return;
    }

    if should_display(&results, *file_count, flags.verbose) {
        display::print_analysis_results(flags.quiet, flags.do_extract, &results);
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
    bw: binwalk_ng::Binwalk,
    target_file: impl AsRef<Path>,
    do_extraction: bool,
    do_carve: bool,
    worker_tx: mpsc::Sender<AnalysisResults>,
    pending: Arc<AtomicUsize>,
) {
    let target_file = target_file.as_ref().to_path_buf();
    pending.fetch_add(1, Ordering::Release);
    pool.spawn(move || {
        // Read in file data
        let file_data = common::read_file(&target_file).unwrap_or_else(|_| {
            error!("Failed to read {} data", target_file.display());
            b"".to_vec()
        });

        // Analyze target file, with extraction, if specified
        let results = bw.analyze_buf(&file_data, &target_file, do_extraction);

        // If data carving was requested as part of extraction, carve analysis results to disk
        if do_carve {
            let carve_count = carve_file_map(&file_data, &results);
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

        pending.fetch_sub(1, Ordering::Release);
    });
}

/// Carve signatures identified during analysis to separate files on disk.
/// Returns the number of carved files created.
/// Note that unknown blocks of file data are also carved to disk, so the number of files
/// created may be larger than the number of results defined in results.file_map.
fn carve_file_map(file_data: &[u8], results: &binwalk_ng::AnalysisResults) -> usize {
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
                &results.file_path,
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
            if carve_file_data_to_disk(&results.file_path, file_data, "unknown", offset, size) {
                carve_count += 1;
            }
        }
    }

    carve_count
}

/// Carves a block of file data to a new file on disk
fn carve_file_data_to_disk(
    source_file_path: impl AsRef<Path>,
    file_data: &[u8],
    name: &str,
    offset: usize,
    size: usize,
) -> bool {
    let chroot = Chroot::default();

    // Carved file path will be: <source file path>_<offset>_<name>.raw
    let carved_file_path = format!(
        "{}_{offset}_{name}.raw",
        source_file_path.as_ref().display()
    );

    debug!("Carving {carved_file_path}");

    // Carve the data to disk
    if !chroot.carve_file(&carved_file_path, file_data, offset, size) {
        error!(
            "Failed to carve {} [{:#X}..{:#X}] to disk",
            carved_file_path,
            offset,
            offset + size,
        );
        return false;
    }

    true
}

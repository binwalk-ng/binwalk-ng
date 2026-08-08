use binwalk_ng::AnalysisResults;
use binwalk_ng::extractors;
use binwalk_ng::signatures;
use colored::ColoredString;
use colored::Colorize;
use log::error;
use std::collections::HashMap;
use std::io;
use std::io::Write;
use std::time;
use terminal_size::Width;

const DELIM_CHARACTER: &str = "-";
const DEFAULT_TERMINAL_WIDTH: u16 = 200;

const COLUMN1_WIDTH: usize = 35;
const COLUMN2_WIDTH: usize = 35;

fn terminal_width() -> usize {
    terminal_size::terminal_size().map_or(DEFAULT_TERMINAL_WIDTH, |(Width(w), _)| w) as usize
}

fn line_delimiter() -> String {
    DELIM_CHARACTER.repeat(terminal_width())
}

fn center_text(text: &str) -> String {
    let padding_width = terminal_width().saturating_sub(text.len()) / 2;

    format!("{:>width$}{}", "", text, width = padding_width)
}

fn pad_to_length(text: &str, len: usize) -> String {
    format!("{text:width$}", width = len)
}

fn line_wrap(text: &str, prefix_size: usize) -> String {
    let mut this_line = "".to_string();
    let mut formatted_string = "".to_string();
    let max_line_size: usize = terminal_width() - prefix_size;

    for word in text.split_whitespace() {
        if (this_line.len() + word.len()) < max_line_size {
            this_line = this_line + word + " ";
        } else {
            formatted_string = formatted_string + &this_line + "\n";
            for _i in 0..prefix_size {
                formatted_string += " ";
            }
            this_line = word.to_string() + " ";
        }
    }

    formatted_string = formatted_string + &this_line;

    formatted_string.trim().to_string()
}

fn print_column_headers(col1: &str, col2: &str, col3: &str) {
    let header_string = format!(
        "{}{}{}",
        pad_to_length(col1, COLUMN1_WIDTH),
        pad_to_length(col2, COLUMN2_WIDTH),
        col3
    );

    println!("{}", header_string.bold().bright_blue());
}

fn print_delimiter() {
    println!("{}", line_delimiter().bold().bright_blue());
}

fn print_header(title_text: &str) {
    println!();
    println!("{}", center_text(title_text).bold().magenta());
    print_delimiter();
    print_column_headers("DECIMAL", "HEXADECIMAL", "DESCRIPTION");
    print_delimiter();
}

fn print_footer() {
    print_delimiter();
    println!();
}

fn print_signature(signature: &signatures::SignatureResult) {
    let decimal_string = format!("{}", signature.offset);
    let hexadecimal_string = format!("{:#X}", signature.offset);
    let display_string = format!(
        "{}{}{}",
        pad_to_length(&decimal_string, COLUMN1_WIDTH),
        pad_to_length(&hexadecimal_string, COLUMN2_WIDTH),
        line_wrap(&signature.description, COLUMN1_WIDTH + COLUMN2_WIDTH)
    );

    if signature.confidence >= signatures::CONFIDENCE_HIGH {
        println!("{}", display_string.green());
    } else if signature.confidence >= signatures::CONFIDENCE_MEDIUM {
        println!("{}", display_string.yellow());
    } else {
        println!("{}", display_string.red());
    }
}

fn print_signatures(signatures: &Vec<signatures::SignatureResult>) {
    for signature in signatures {
        print_signature(signature);
    }
}

fn print_extraction(
    signature: &signatures::SignatureResult,
    extraction: Option<&extractors::ExtractionResult>,
) {
    let extraction_message: ColoredString;

    match extraction {
        None => {
            extraction_message = format!(
                "[#] Extraction of {} data at offset {:#X} declined",
                signature.name, signature.offset
            )
            .bold()
            .yellow();
        }
        Some(extraction_result) => {
            if extraction_result.success {
                extraction_message = format!(
                    "[+] Extraction of {} data at offset {:#X} completed successfully",
                    signature.name, signature.offset
                )
                .bold()
                .green();
            } else {
                extraction_message = format!(
                    "[-] Extraction of {} data at offset {:#X} failed!",
                    signature.name, signature.offset
                )
                .bold()
                .red();
            }
        }
    }

    println!("{extraction_message}");
}

fn print_extractions(
    signatures: &Vec<signatures::SignatureResult>,
    extraction_results: &HashMap<String, extractors::ExtractionResult>,
) {
    let mut delimiter_printed = false;

    for signature in signatures {
        let mut printable_extraction = false;
        let mut extraction_result: Option<&extractors::ExtractionResult> = None;

        // Only print extraction results if an extraction was attempted or explicitly declined
        if signature.extraction_declined {
            printable_extraction = true
        } else if let Some(extraction_res) = extraction_results.get(&signature.id) {
            printable_extraction = true;
            extraction_result = Some(extraction_res);
        }

        if printable_extraction {
            // Only print the delimiter line once
            if !delimiter_printed {
                print_delimiter();
                delimiter_printed = true;
            }
            print_extraction(signature, extraction_result);
        }
    }
}

pub fn print_analysis_results(extraction_attempted: bool, results: &AnalysisResults) {
    // Print signature results
    print_header(&results.file_path.display().to_string());
    print_signatures(&results.file_map);

    // If extraction was attempted, print extraction results
    if extraction_attempted {
        print_extractions(&results.file_map, &results.extractions);
    }

    // Print the footer text
    print_footer();
}

// Used by print_signature_list
#[derive(Debug, Default)]
struct SignatureInfo<'a> {
    name: &'a str,
    is_short: bool,
    has_extractor: bool,
    extractor: &'a str,
    description: &'a str,
}

pub fn print_signature_list(signatures: &Vec<signatures::Signature>) {
    let mut extractor_count: usize = 0;
    let mut signature_count: usize = 0;
    let mut signature_infos: Vec<SignatureInfo> = Vec::with_capacity(signatures.len());

    // Print column headers
    print_delimiter();
    print_column_headers(
        "Signature Description",
        "Signature Name",
        "Extraction Utility",
    );
    print_delimiter();

    // Loop through all signatures
    for signature in signatures {
        // Convenience struct for storing some basic info about each signature
        // Keep track of signature name, description, and if the signature is a "short" signature
        let mut signature_info = SignatureInfo {
            name: signature.name.as_str(),
            is_short: signature.short,
            description: signature.description.as_str(),
            ..Default::default()
        };

        // Keep track of which signatures have associated extractors, and if so, what type of extractor
        match &signature.extractor {
            None => {
                signature_info.has_extractor = false;
                signature_info.extractor = "None";
            }
            Some(extractor) => {
                signature_info.has_extractor = true;

                match &extractor.utility {
                    extractors::ExtractorType::External(command) => {
                        signature_info.extractor = command;
                    }
                    extractors::ExtractorType::Internal(_) => {
                        signature_info.extractor = "Built-in";
                    }
                    extractors::ExtractorType::None => error!(
                        "An invalid extractor type exists for the '{}' signature",
                        signature.description
                    ),
                }
            }
        }

        // Increment signature count
        signature_count += 1;

        // If there is an extractor for this signature, increment extractor count
        if signature_info.has_extractor {
            extractor_count += 1;
        }

        signature_infos.push(signature_info);
    }

    // Sort signature descriptions alphabetically
    signature_infos.sort_by(|a, b| {
        a.description
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.description.bytes().map(|c| c.to_ascii_lowercase()))
    });

    // Print signatures, sorted alphabetically by description
    for siginfo in &signature_infos {
        let display_line = format!(
            "{}{}{}",
            pad_to_length(siginfo.description, COLUMN1_WIDTH),
            pad_to_length(siginfo.name, COLUMN2_WIDTH),
            siginfo.extractor
        );

        if siginfo.is_short {
            println!("{}", display_line.yellow());
        } else {
            println!("{}", display_line.green());
        }
    }

    print_delimiter();
    println!();
    println!("Total signatures: {signature_count}");
    println!("Extractable signatures: {extractor_count}");
}

pub fn print_stats(
    run_time: time::Instant,
    file_count: usize,
    signature_count: usize,
    pattern_count: usize,
) {
    const MS_IN_A_SECOND: f64 = 1000.0;
    const SECONDS_IN_A_MINUTE: f64 = 60.0;
    const MINUTES_IN_AN_HOUR: f64 = 60.0;

    let mut file_plural = "";
    let mut units = "milliseconds";
    let mut display_time: f64 = run_time.elapsed().as_millis() as f64;

    // Format the output time in a more human-readable manner
    if display_time >= MS_IN_A_SECOND {
        display_time /= MS_IN_A_SECOND;
        units = "seconds";

        if display_time >= SECONDS_IN_A_MINUTE {
            display_time /= SECONDS_IN_A_MINUTE;
            units = "minutes";

            if display_time >= MINUTES_IN_AN_HOUR {
                display_time /= MINUTES_IN_AN_HOUR;
                units = "hours";
            }
        }
    }

    if file_count != 1 {
        file_plural = "s";
    }

    println!(
        "Analyzed {file_count} file{file_plural} for {signature_count} file signatures ({pattern_count} magic patterns) in {display_time:.1} {units}"
    );
}

pub fn print_plain(quiet: bool, msg: &str) {
    if !quiet {
        print!("{msg}");
        let _ = io::stdout().flush();
    }
}

#[cfg(feature = "entropy-plot")]
pub fn println_plain(quiet: bool, msg: &str) {
    if !quiet {
        println!("{msg}");
    }
}

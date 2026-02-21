use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = None,
    arg_required_else_help = true,
)]
pub struct CliArgs {
    /// List supported signatures and extractors
    #[arg(short = 'L', long)]
    pub list: bool,

    /// Path to the file to analyze, or "-" for stdin
    /// (Required unless listing signatures)
    #[arg(
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
        required_unless_present_any = ["list"],
    )]
    pub file_name: Option<PathBuf>,

    /// Suppress normal stdout output
    #[arg(short, long)]
    pub quiet: bool,

    /// During recursive extraction display *all* results
    #[arg(short, long)]
    pub verbose: bool,

    /// Automatically extract known file types
    #[arg(short, long)]
    pub extract: bool,

    /// Carve both known and unknown file contents to disk
    #[arg(short, long)]
    pub carve: bool,

    /// Recursively scan extracted files
    #[arg(short = 'M', long)]
    pub matryoshka: bool,

    /// Search for all signatures at all offsets
    #[arg(short = 'a', long)]
    pub search_all: bool,

    /// Generate an entropy graph with Plotly
    #[arg(short = 'E', long, conflicts_with = "extract")]
    pub entropy: bool,

    /// Save entropy graph as a PNG file
    #[arg(short, long, value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub png: Option<PathBuf>,

    /// Log JSON results to a file ('-' for stdout)
    #[arg(short, long, value_name = "LOG_FILE", value_hint = clap::ValueHint::FilePath)]
    pub log: Option<PathBuf>,

    /// Manually specify the number of threads to use
    #[arg(short, long, value_name = "INT")]
    pub threads: Option<usize>,

    /// Do not scan for these signatures
    #[arg(
        short = 'x',
        long,
        value_delimiter = ',',
        num_args = 1..,
        value_name = "SIG"
    )]
    pub exclude: Vec<String>, // Removed Option; Vec is empty by default

    /// Only scan for these signatures
    #[arg(
        short = 'y',
        long,
        value_delimiter = ',',
        num_args = 1..,
        conflicts_with = "exclude",
        value_name = "SIG"
    )]
    pub include: Vec<String>,

    /// Extract files/folders to a custom directory
    #[arg(short, long, default_value = "extractions", value_hint = clap::ValueHint::DirPath)]
    pub directory: PathBuf,
}

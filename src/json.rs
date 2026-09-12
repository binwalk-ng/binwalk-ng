use log::error;
use serde::Serialize;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

#[cfg(feature = "entropy-plot")]
use crate::entropy::FileEntropy;
use binwalk_ng::AnalysisResults;

const STDOUT: &str = "-";
const JSON_LIST_START: &str = "[\n";
const JSON_LIST_END: &str = "\n]\n";
const JSON_LIST_SEP: &str = ",\n";

#[derive(Debug, Serialize)]
pub enum JSONType<'a> {
    #[cfg(feature = "entropy-plot")]
    Entropy(&'a FileEntropy),
    Analysis(&'a AnalysisResults),
}

#[derive(Default)]
pub struct JsonLogger {
    pub json_file: Option<PathBuf>,
    pub json_file_initialized: bool,
    /// A single writer to the JSON log output, opened once instead of reopened for every entry
    writer: Option<Box<dyn Write>>,
}

impl JsonLogger {
    pub fn new(log_file: Option<&Path>) -> Self {
        let mut new_instance = Self::default();

        if let Some(log_file) = log_file {
            new_instance.json_file = Some(log_file.to_path_buf());

            // Establish the writer up front, to avoid reopening the log file for every entry
            new_instance.writer = Some(if log_file == STDOUT {
                Box::new(io::stdout())
            } else {
                match fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(log_file)
                {
                    Err(e) => {
                        error!("Failed to open JSON log file '{}': {e}", log_file.display());
                        return new_instance;
                    }
                    Ok(fp) => Box::new(io::BufWriter::new(fp)),
                }
            });
        }

        new_instance
    }

    pub fn close(&mut self) {
        self.write_json(JSON_LIST_END);

        // Ensure all buffered JSON data and the closing list marker are flushed to the log
        if let Some(writer) = &mut self.writer
            && let Err(e) = writer.flush()
        {
            error!("Failed to flush JSON log file: {e}");
        }
    }

    pub fn log(&mut self, results: JSONType) {
        // Write the list header/separator between log entries
        if !self.json_file_initialized {
            self.write_json(JSON_LIST_START);
            self.json_file_initialized = true;
        } else {
            self.write_json(JSON_LIST_SEP);
        }

        // Serialize the analysis results directly to the log writer, avoiding building a String
        if let Some(writer) = &mut self.writer {
            if let Err(e) = serde_json::to_writer_pretty(&mut *writer, &results) {
                error!("Failed to convert analysis results to JSON: {e}");
            }

            // Flush each entry to the log output, so it is promptly visible if the
            // process is interrupted
            if let Err(e) = writer.flush() {
                error!("Failed to flush JSON log file: {e}");
            }
        }
    }

    fn write_json(&mut self, data: &str) {
        let Some(writer) = &mut self.writer else {
            return;
        };

        if let Err(e) = writer.write_all(data.as_bytes()) {
            error!("Failed to write to JSON log file: {e}");
        }

        // Flush each write immediately, as the previous per-write file open/close did
        if let Err(e) = writer.flush() {
            error!("Failed to flush JSON log file: {e}");
        }
    }
}

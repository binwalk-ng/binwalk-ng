use entropy::shannon_entropy;
use log::debug;
use plotters::prelude::*;
use plotters::style::FontStyle;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct EntropyError {
    message: String,
}

impl EntropyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EntropyError {}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlockEntropy {
    pub end: usize,
    pub start: usize,
    pub entropy: f32,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FileEntropy {
    pub file: PathBuf,
    pub blocks: Vec<BlockEntropy>,
}

/// Splits the supplied data up into blocks and calculates the entropy of each block.
fn blocks(data: &[u8]) -> Vec<BlockEntropy> {
    const BLOCK_COUNT: usize = 2048;

    let mut offset: usize = 0;

    if data.is_empty() {
        return vec![];
    }

    let block_size = if data.len() < BLOCK_COUNT {
        data.len()
    } else {
        data.len() / BLOCK_COUNT
    };

    let mut chunker = data.chunks(block_size);
    let mut entropy_blocks: Vec<BlockEntropy> = vec![];

    loop {
        match chunker.next() {
            None => break,
            Some(block_data) => {
                let mut block = BlockEntropy::default();

                block.start = offset;
                block.entropy = shannon_entropy(block_data);
                block.end = block.start + block_data.len();

                offset = block.end;
                entropy_blocks.push(block);
            }
        }
    }

    entropy_blocks
}

static FONT_INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_font() -> Result<(), String> {
    FONT_INIT
        .get_or_init(|| {
            plotters::style::register_font("sans-serif", FontStyle::Normal, dejavu::sans::regular())
                .map_err(|_| "Failed to register DejaVu font".to_string())
        })
        .clone()
}

fn draw_chart<DB: DrawingBackend>(
    root: &DrawingArea<DB, plotters::coord::Shift>,
    blocks: &[BlockEntropy],
) -> Result<(), String>
where
    DB::ErrorType: std::fmt::Debug,
{
    ensure_font()?;
    root.fill(&WHITE).map_err(|e| format!("{e:?}"))?;

    let max_x = blocks.last().map(|b| b.end).unwrap_or(0);
    // plotters panics on empty range, ensure non-zero
    let max_x = if max_x == 0 { 1 } else { max_x };

    let mut chart = ChartBuilder::on(root)
        .caption("Entropy Graph", ("sans-serif", 30).into_font())
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(50)
        .build_cartesian_2d(0..max_x, 0f32..8f32)
        .map_err(|e| format!("{e:?}"))?;

    chart
        .configure_mesh()
        .x_desc("File Offset")
        .y_desc("Entropy")
        .draw()
        .map_err(|e| format!("{e:?}"))?;

    // Step plot: each block as horizontal line from start to end
    let points: Vec<(usize, f32)> = blocks
        .iter()
        .flat_map(|b| [(b.start, b.entropy), (b.end, b.entropy)])
        .collect();

    chart
        .draw_series(LineSeries::new(points, &RED))
        .map_err(|e| format!("{e:?}"))?;

    root.present().map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// Renders the plot to a PNG file in the system temporary directory.
fn render_to_temp_png(
    blocks: &[BlockEntropy],
    target_file: &Path,
) -> Result<PathBuf, EntropyError> {
    let png_path = image_output_path(target_file);

    {
        let root = BitMapBackend::new(&png_path, (2048, 1024)).into_drawing_area();
        draw_chart(&root, blocks)
            .map_err(|e| EntropyError::new(format!("Failed to render entropy chart: {e}")))?;
    }

    Ok(png_path)
}

fn image_output_path(target_file: &Path) -> PathBuf {
    let file_stem = target_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("file");

    std::env::temp_dir().join(format!(
        "binwalk-{file_stem}-entropy-{}.png",
        uuid::Uuid::new_v4()
    ))
}

fn export_image(blocks: &[BlockEntropy], out_file: &Path) -> Result<(), EntropyError> {
    let root = BitMapBackend::new(out_file, (2048, 1024)).into_drawing_area();
    draw_chart(&root, blocks).map_err(|e| {
        EntropyError::new(format!(
            "Failed to export entropy plot to '{}': {e}",
            out_file.display()
        ))
    })
}

pub fn plot(
    file_path: impl AsRef<Path>,
    out_file: Option<&Path>,
) -> Result<(FileEntropy, PathBuf), EntropyError> {
    let target_file = file_path.as_ref();
    let mut file_entropy = FileEntropy {
        file: target_file.to_path_buf(),
        ..Default::default()
    };

    let file_data = std::fs::read(target_file).map_err(|e| {
        EntropyError::new(format!("Failed to read '{}': {e}", target_file.display()))
    })?;
    debug!(
        "Loaded {} bytes from {}",
        file_data.len(),
        target_file.display()
    );

    file_entropy.blocks = blocks(&file_data);

    let png_path = match out_file {
        None => render_to_temp_png(&file_entropy.blocks, target_file)?,
        Some(out_file_name) => {
            export_image(&file_entropy.blocks, out_file_name)?;
            out_file_name.to_path_buf()
        }
    };

    Ok((file_entropy, png_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_has_no_blocks() {
        assert!(blocks(&[]).is_empty());
    }

    #[test]
    fn constant_data_has_zero_entropy() {
        let blocks = blocks(&vec![0x41; 4096]);
        assert!(!blocks.is_empty());
        for block in blocks {
            assert_eq!(block.entropy, 0.0);
        }
    }

    #[test]
    fn blocks_cover_the_entire_input() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();

        let blocks = blocks(&data);

        assert_eq!(blocks.first().unwrap().start, 0);
        assert_eq!(blocks.last().unwrap().end, data.len());
        for pair in blocks.windows(2) {
            assert_eq!(pair[0].end, pair[1].start);
        }
    }

    #[test]
    fn exporting_an_empty_chart_succeeds() {
        // Regression test for the empty-input panic: an empty chart must render
        // rather than aborting the process.
        let temp_dir = tempfile::tempdir().unwrap();
        let png_path = temp_dir.path().join("empty-chart.png");

        export_image(&[], &png_path).unwrap();

        assert!(png_path.exists());
        assert!(png_path.metadata().unwrap().len() > 0);
    }
}

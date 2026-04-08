use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use std::path::Path;

pub fn rar_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_rar),
        ..Default::default()
    }
}

pub fn extract_rar(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    let mut result = ExtractionResult {
        ..Default::default()
    };

    if let Ok(archive) = rar_stream::MemoryArchive::new(&file_data[offset..]) {
        result.size = Some(
            archive
                .entries_iter()
                .map(|x| x.unpacked_size as usize)
                .sum(),
        );
        result.success = true;

        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);

            for (i, entry) in archive.entries_iter().enumerate() {
                if entry.is_directory {
                    chroot.create_directory(entry.name);
                } else if let Ok(data) = archive.extract(i) {
                    chroot.create_file(entry.name, &data);
                }
            }
        }
    }

    result
}

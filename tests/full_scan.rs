use std::path::Path;

use binwalk_ng::Binwalk;

/// Every other integration test passes a single-signature include filter, so none of them scan
/// with the full pattern set and interactions between signatures go unexercised. `bmp.bin` holds
/// several formats, including PE images whose zeroed DOS headers each hold a run of zero bytes
/// long enough for the scan to skip past, and a copyright string behind ~8 KiB of zero padding.
///
/// Scan only, no extraction, so this needs none of the external extractor binaries.
#[test]
fn unfiltered_scan_of_a_multi_format_file() {
    let file_path = Path::new("tests").join("inputs").join("bmp.bin");
    let file_data = std::fs::read(file_path).unwrap();

    let file_map = Binwalk::new().scan(&file_data);

    insta::assert_yaml_snapshot!(file_map, {
        "[].id" => "[uuid]",
    });
}

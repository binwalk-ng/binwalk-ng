mod common;

#[test]
fn integration_test() {
    // No successful extraction for this sample (no extractor / no credentials):
    // one signature at offset 0, no extraction results asserted.
    let results = common::run_binwalk("pcapng", "pcapng.ipv4.pcapng");
    common::assert_results_ok(results, vec![0], vec![]);
}

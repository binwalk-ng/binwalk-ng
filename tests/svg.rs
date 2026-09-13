mod common;

#[test]
fn integration_test() {
    // SVG has no extractor (extraction_declined): one signature at offset 0,
    // no extraction results.
    let results = common::run_binwalk("svg", "svg.vector.svg");
    common::assert_results_ok(results, vec![0], vec![]);
}

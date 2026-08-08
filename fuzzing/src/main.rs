use afl::fuzz;
use binwalk_ng::Binwalk;

fn main() {
    // Building the pattern searcher is expensive, so do it once for the whole fuzz run
    let binwalker = Binwalk::new();

    // AFL makes this real simple...
    fuzz!(|data: &[u8]| {
        // Scan the data provided by AFL
        binwalker.scan(data);
    });
}

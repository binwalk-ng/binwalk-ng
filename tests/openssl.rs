mod common;

#[test]
fn salted_sample_without_password_fails_cleanly() {
    // The salted OpenSSL sample carries no credentials: it must be detected at
    // offset 0, and the built-in extractor must fail cleanly (no panic).
    let results = common::run_binwalk("openssl", "openssl.salted.bin");

    assert_eq!(results.file_map.len(), 1);
    assert_eq!(results.file_map[0].offset, 0);
    assert_eq!(results.extractions.len(), 1);
    assert!(
        !results.extractions.values().next().unwrap().success,
        "decryption without a password must fail"
    );
}

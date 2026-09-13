mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "srecord";
    const INPUT_FILE_NAME: &str = "srec.hdr.srec";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn integration_test_s6() {
    const SIGNATURE_TYPE: &str = "srecord";
    const INPUT_FILE_NAME: &str = "srec_s6.hex";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

#[test]
fn integration_test_from_elf() {
    // Built from an ELF via objcopy: S0 header carries the file name, not
    // "HDR", so this matches the generic short signature, not "srecord".
    const SIGNATURE_TYPE: &str = "srecord_generic";
    const INPUT_FILE_NAME: &str = "srec.from_elf.srec";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}

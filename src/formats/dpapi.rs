use crate::signatures::CONFIDENCE_MEDIUM;
use crate::signatures::{SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "DPAPI blob data";

/// DPAPI blob data header will always start with these bytes
pub fn dpapi_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x01\x00\x00\x00\xD0\x8c\x9d\xdf\x01\x15\xd1\x11\x8c\x7a\x00\xc0\x4f\xc2\x97\xeb"
            .to_vec(),
    ]
}

/// Returns success with additional details
pub fn dpapi_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    if let Ok(header) = parse_dpapi_blob_header(file_data.get(offset..).ok_or(SignatureError)?) {
        return Ok(SignatureResult {
            offset,
            description: format!(
                "{}, header_size: {}, blob_size: {}, version: {}, provider_id: {}, master_key_version: {},
             master_key_id: {}, flags: {}, description_len: {}, crypto_algorithm: {}, crypto_alg_len: {},
             salt_len: {}, hmac_key_len: {}, hash_algorithm: {}, hash_alg_len: {}, hmac2_key_len: {},
             data_len: {}, sign_len: {}",
                DESCRIPTION, header.header_size, header.blob_size, header.version, header.provider_id,
                header.master_key_version, header.master_key_id, header.flags, header.description_len,
                header.crypto_algorithm, header.crypto_alg_len, header.salt_len, header.hmac_key_len,
                header.hash_algorithm, header.hash_alg_len, header.hmac2_key_len, header.data_len, header.sign_len
            ),
            confidence: CONFIDENCE_MEDIUM,
            ..Default::default()
        });
    }

    Err(SignatureError)
}

/*
 Blob structure: from mimikatz repository.
   DWORD	dwVersion;
   GUID	guidProvider;
   DWORD	dwMasterKeyVersion;
   GUID	guidMasterKey;
   DWORD	dwFlags;

   DWORD	dwDescriptionLen;
   PWSTR	szDescription;

   ALG_ID	algCrypt;
   DWORD	dwAlgCryptLen;

   DWORD	dwSaltLen;
   PBYTE	pbSalt;

   DWORD	dwHmacKeyLen;
   PBYTE	pbHmackKey;

   ALG_ID	algHash;
   DWORD	dwAlgHashLen;

   DWORD	dwHmac2KeyLen;
   PBYTE	pbHmack2Key;

   DWORD	dwDataLen;
   PBYTE	pbData;

   DWORD	dwSignLen;
   PBYTE	pbSign;
*/

/// Struct to store DPAPI blob structure
#[derive(Debug, Default, Clone)]
pub struct DPAPIBlobHeader {
    pub header_size: usize,
    pub blob_size: usize,
    pub version: u32,
    pub provider_id: u128,
    pub master_key_version: u32,
    pub master_key_id: u128,
    pub flags: u32,
    pub description_len: usize,
    pub crypto_algorithm: u32,
    pub crypto_alg_len: usize,
    pub salt_len: usize,
    pub hmac_key_len: usize,
    pub hash_algorithm: u32,
    pub hash_alg_len: usize,
    pub hmac2_key_len: usize,
    pub data_len: usize,
    pub sign_len: usize,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP1 {
    version: zerocopy::U32<LE>,
    provider_id: zerocopy::U128<LE>,
    master_key_version: zerocopy::U32<LE>,
    master_key_id: zerocopy::U128<LE>,
    flags: zerocopy::U32<LE>,
    description_len: zerocopy::U32<LE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP2 {
    crypto_algorithm: zerocopy::U32<LE>,
    crypto_alg_len: zerocopy::U32<LE>,
    salt_len: zerocopy::U32<LE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP3 {
    hmac_key_len: zerocopy::U32<LE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP4 {
    hash_algorithm: zerocopy::U32<LE>,
    hash_alg_len: zerocopy::U32<LE>,
    hmac2_key_len: zerocopy::U32<LE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP5 {
    data_len: zerocopy::U32<LE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DPAPIHeaderP6 {
    sign_len: zerocopy::U32<LE>,
}

/// Parse a DPAPI BLOB
pub fn parse_dpapi_blob_header(dpapi_blob_data: &[u8]) -> Result<DPAPIBlobHeader, StructureError> {
    let mut offset: usize = size_of::<DPAPIHeaderP1>();

    let (dpapi_header, _) =
        DPAPIHeaderP1::ref_from_prefix(dpapi_blob_data).map_err(|_| StructureError)?;
    let description_len = dpapi_header.description_len.get() as usize;

    if !description_len.is_multiple_of(2) {
        return Err(StructureError);
    }

    let desc_bytes = dpapi_blob_data
        .get(offset..offset + description_len)
        .ok_or(StructureError)?;
    if description_len != 0 && !is_null_terminated_utf16(desc_bytes) {
        return Err(StructureError);
    }

    offset += description_len;

    let (dpapi_header_p2, _) =
        DPAPIHeaderP2::ref_from_prefix(dpapi_blob_data.get(offset..).ok_or(StructureError)?)
            .map_err(|_| StructureError)?;
    let salt_len = dpapi_header_p2.salt_len.get() as usize;
    offset += size_of::<DPAPIHeaderP2>() + salt_len;

    let (dpapi_header_p3, _) =
        DPAPIHeaderP3::ref_from_prefix(dpapi_blob_data.get(offset..).ok_or(StructureError)?)
            .map_err(|_| StructureError)?;

    let hmac_key_len = dpapi_header_p3.hmac_key_len.get() as usize;
    offset += size_of::<DPAPIHeaderP3>() + hmac_key_len;

    let (dpapi_header_p4, _) =
        DPAPIHeaderP4::ref_from_prefix(dpapi_blob_data.get(offset..).ok_or(StructureError)?)
            .map_err(|_| StructureError)?;
    let hmac2_key_len = dpapi_header_p4.hmac2_key_len.get() as usize;
    offset += size_of::<DPAPIHeaderP4>() + hmac2_key_len;

    let (dpapi_header_p5, _) =
        DPAPIHeaderP5::ref_from_prefix(dpapi_blob_data.get(offset..).ok_or(StructureError)?)
            .map_err(|_| StructureError)?;

    let data_len = dpapi_header_p5.data_len.get() as usize;
    offset += size_of::<DPAPIHeaderP5>() + data_len;

    let (dpapi_header_p6, _) =
        DPAPIHeaderP6::ref_from_prefix(dpapi_blob_data.get(offset..).ok_or(StructureError)?)
            .map_err(|_| StructureError)?;

    let sign_len = dpapi_header_p6.sign_len.get() as usize;
    let blob_size = offset + size_of::<DPAPIHeaderP6>() + sign_len;

    let header_size = size_of::<DPAPIHeaderP1>()
        + size_of::<DPAPIHeaderP2>()
        + size_of::<DPAPIHeaderP3>()
        + size_of::<DPAPIHeaderP4>()
        + size_of::<DPAPIHeaderP5>()
        + size_of::<DPAPIHeaderP6>();

    Ok(DPAPIBlobHeader {
        header_size,
        blob_size,
        version: dpapi_header.version.get(),
        provider_id: dpapi_header.provider_id.get(),
        master_key_version: dpapi_header.master_key_version.get(),
        master_key_id: dpapi_header.master_key_id.get(),
        flags: dpapi_header.flags.get(),
        description_len,
        crypto_algorithm: dpapi_header_p2.crypto_algorithm.get(),
        crypto_alg_len: dpapi_header_p2.crypto_alg_len.get() as usize,
        salt_len,
        hmac_key_len,
        hash_algorithm: dpapi_header_p4.hash_algorithm.get(),
        hash_alg_len: dpapi_header_p4.hash_alg_len.get() as usize,
        hmac2_key_len,
        data_len,
        sign_len,
    })
}

/// Check if `byte_array` contains valid utf-16 which is null terminated correctly
///
/// Returns false if description is invalid utf-16, is not null terminated,
/// or contains embedded nulls
fn is_null_terminated_utf16(byte_array: &[u8]) -> bool {
    let (chars, []) = byte_array.as_chunks::<2>() else {
        return false;
    };
    let mut char_iter = char::decode_utf16(chars.iter().map(|&ch_arr| u16::from_le_bytes(ch_arr)));
    // loop until the first null utf16 character
    loop {
        let Some(Ok(ch)) = char_iter.next() else {
            return false;
        };
        if ch == '\0' {
            break;
        }
    }

    // Require all characters after the first null also be null
    char_iter.all(|ch| ch == Ok('\0'))
}

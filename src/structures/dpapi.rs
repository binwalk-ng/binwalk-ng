use crate::structures::common::StructureError;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

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
    let mut offset: usize = (32 + 128 + 32 + 128 + 32 + 32) / 8;

    let (dpapi_header, _) =
        DPAPIHeaderP1::ref_from_prefix(dpapi_blob_data).map_err(|_| StructureError)?;
    let description_len = dpapi_header.description_len.get() as usize;

    if !description_len.is_multiple_of(2) {
        return Err(StructureError);
    }

    let utf16_vec =
        utf8_to_utf16(&dpapi_blob_data[offset..=offset + description_len]).ok_or(StructureError)?;
    let desc = String::from_utf16(&utf16_vec).map_err(|_| StructureError)?;

    // NULL character becomes size 1 from size 2
    if description_len != desc.len() - 1 {
        return Err(StructureError);
    }

    offset += description_len;

    let (dpapi_header_p2, _) =
        DPAPIHeaderP2::ref_from_prefix(&dpapi_blob_data[offset..]).map_err(|_| StructureError)?;
    let salt_len = dpapi_header_p2.salt_len.get() as usize;
    offset += (32 + 32 + 32) / 8 + salt_len;

    let (dpapi_header_p3, _) =
        DPAPIHeaderP3::ref_from_prefix(&dpapi_blob_data[offset..]).map_err(|_| StructureError)?;

    let hmac_key_len = dpapi_header_p3.hmac_key_len.get() as usize;
    offset += 32 / 8 + hmac_key_len;

    let (dpapi_header_p4, _) =
        DPAPIHeaderP4::ref_from_prefix(&dpapi_blob_data[offset..]).map_err(|_| StructureError)?;
    let hmac2_key_len = dpapi_header_p4.hmac2_key_len.get() as usize;
    offset += (32 + 32 + 32) / 8 + hmac2_key_len;

    let (dpapi_header_p5, _) =
        DPAPIHeaderP5::ref_from_prefix(&dpapi_blob_data[offset..]).map_err(|_| StructureError)?;

    let data_len = dpapi_header_p5.data_len.get() as usize;
    offset += 32 / 8 + data_len;

    let (dpapi_header_p6, _) =
        DPAPIHeaderP6::ref_from_prefix(&dpapi_blob_data[offset..]).map_err(|_| StructureError)?;

    let sign_len = dpapi_header_p6.sign_len.get() as usize;
    offset += 32 / 8 + sign_len;

    Ok(DPAPIBlobHeader {
        header_size: (32 * 13 + 128 * 2) / 8,
        blob_size: offset,
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

/// Convert &[u8] into &[u16] as vec
fn utf8_to_utf16(byte_array: &[u8]) -> Option<Vec<u16>> {
    let mut utf16_vec = Vec::with_capacity(byte_array.len() / 2);
    for i in 0..utf16_vec.len() {
        let buff = byte_array[2 * i..=2 * i + 1].try_into().ok()?;
        utf16_vec[i] = u16::from_be_bytes(buff); // Big endian as to keep bit order
    }
    Some(utf16_vec)
}

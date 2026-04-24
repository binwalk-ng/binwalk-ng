use crate::structures::common::StructureError;
use zerocopy::{BE, FromBytes, Immutable, KnownLayout, Unaligned};

#[derive(Debug, Default, Clone)]
pub struct QcowHeader {
    pub version: u8,
    pub storage_media_size: usize,
    pub cluster_block_bits: u8,
    pub encryption_method: String,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct QcowHeaderBase {
    magic: zerocopy::U32<BE>,
    version: zerocopy::U32<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct QcowHeaderV1 {
    backing_filename_offset: zerocopy::U64<BE>,
    backing_filename_size: zerocopy::U32<BE>,
    modification_timestamp: zerocopy::U32<BE>,
    storage_media_size: zerocopy::U64<BE>,
    cluster_block_bits: u8,
    level2_table_bits: u8,
    reserved1: zerocopy::U16<BE>,
    encryption_method: zerocopy::U32<BE>,
    level1_table_offset: zerocopy::U64<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct QcowHeaderV2 {
    backing_filename_offset: zerocopy::U64<BE>,
    backing_filename_size: zerocopy::U32<BE>,
    cluster_block_bits: zerocopy::U32<BE>,
    storage_media_size: zerocopy::U64<BE>,
    encryption_method: zerocopy::U32<BE>,
    level1_table_refs: zerocopy::U32<BE>,
    level1_table_offset: zerocopy::U64<BE>,
    refcount_table_offset: zerocopy::U64<BE>,
    refcount_table_clusters: zerocopy::U32<BE>,
    snapshot_count: zerocopy::U32<BE>,
    snapshot_offset: zerocopy::U64<BE>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct QcowHeaderV3 {
    backing_filename_offset: zerocopy::U64<BE>,
    backing_filename_size: zerocopy::U32<BE>,
    cluster_block_bits: zerocopy::U32<BE>,
    storage_media_size: zerocopy::U64<BE>,
    encryption_method: zerocopy::U32<BE>,
    level1_table_refs: zerocopy::U32<BE>,
    level1_table_offset: zerocopy::U64<BE>,
    refcount_table_offset: zerocopy::U64<BE>,
    refcount_table_clusters: zerocopy::U32<BE>,
    snapshot_count: zerocopy::U32<BE>,
    snapshot_offset: zerocopy::U64<BE>,
    incompatible_feature_flags: zerocopy::U64<BE>,
    compatible_feature_flags: zerocopy::U64<BE>,
    autoclear_feature_flags: zerocopy::U64<BE>,
    refcount_order: zerocopy::U32<BE>,
    file_hdr_size: zerocopy::U32<BE>, // 104 or 112
}

pub fn parse_qcow_header(qcow_data: &[u8]) -> Result<QcowHeader, StructureError> {
    let (header, _) = QcowHeaderBase::ref_from_prefix(qcow_data).map_err(|_| StructureError)?;

    let qcow_data = qcow_data.get(8..).ok_or(StructureError)?;
    match header.version.get() {
        1 => parse_qcow_header_v1(qcow_data),
        2 => parse_qcow_header_v2(qcow_data),
        3 => parse_qcow_header_v3(qcow_data),
        _ => Err(StructureError),
    }
}

fn get_encryption_name(encryption_type: u32) -> Option<String> {
    match encryption_type {
        0 => Some("None".to_string()),
        1 => Some("AES128-CBC".to_string()),
        2 => Some("LUKS".to_string()),
        _ => None,
    }
}

fn parse_qcow_header_v1(qcow_data: &[u8]) -> Result<QcowHeader, StructureError> {
    let (qcow_header, _) = QcowHeaderV1::ref_from_prefix(qcow_data).map_err(|_| StructureError)?;

    let encryption_method =
        get_encryption_name(qcow_header.encryption_method.get()).ok_or(StructureError)?;

    if !(9..=21).contains(&qcow_header.cluster_block_bits) {
        return Err(StructureError);
    }
    // sanity check: existing offsets need to be aligned to cluster boundary
    if qcow_header.level1_table_offset.get() % (1 << qcow_header.cluster_block_bits) != 0 {
        return Err(StructureError);
    }

    Ok(QcowHeader {
        version: 1,
        storage_media_size: qcow_header.storage_media_size.get() as usize,
        cluster_block_bits: qcow_header.cluster_block_bits,
        encryption_method,
    })
}

fn parse_qcow_header_v2(qcow_data: &[u8]) -> Result<QcowHeader, StructureError> {
    let (qcow_header, _) = QcowHeaderV2::ref_from_prefix(qcow_data).map_err(|_| StructureError)?;

    let encryption_method =
        get_encryption_name(qcow_header.encryption_method.get()).ok_or(StructureError)?;

    let cluster_block_bits = qcow_header.cluster_block_bits.get();
    if !(9..=21).contains(&cluster_block_bits) {
        return Err(StructureError);
    }

    // sanity check: existing offsets need to be aligned to cluster boundary
    if qcow_header.level1_table_offset.get() % (1 << cluster_block_bits) != 0
        || qcow_header.refcount_table_offset.get() % (1 << cluster_block_bits) != 0
        || qcow_header.snapshot_offset.get() % (1 << cluster_block_bits) != 0
    {
        return Err(StructureError);
    }

    Ok(QcowHeader {
        version: 2,
        storage_media_size: qcow_header.storage_media_size.get() as usize,
        cluster_block_bits: cluster_block_bits as u8,
        encryption_method,
    })
}

fn parse_qcow_header_v3(qcow_data: &[u8]) -> Result<QcowHeader, StructureError> {
    let (qcow_header, _) = QcowHeaderV3::ref_from_prefix(qcow_data).map_err(|_| StructureError)?;

    let encryption_method =
        get_encryption_name(qcow_header.encryption_method.get()).ok_or(StructureError)?;

    let cluster_block_bits = qcow_header.cluster_block_bits.get();
    if !(9..=21).contains(&cluster_block_bits) {
        return Err(StructureError);
    }

    // sanity check: existing offsets need to be aligned to cluster boundary
    if qcow_header.level1_table_offset.get() % (1 << cluster_block_bits) != 0
        || qcow_header.refcount_table_offset.get() % (1 << cluster_block_bits) != 0
        || qcow_header.snapshot_offset.get() % (1 << cluster_block_bits) != 0
    {
        return Err(StructureError);
    }

    Ok(QcowHeader {
        version: 3,
        storage_media_size: qcow_header.storage_media_size.get() as usize,
        cluster_block_bits: cluster_block_bits as u8,
        encryption_method,
    })
}

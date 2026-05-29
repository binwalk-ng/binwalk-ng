use crate::extractors::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::signatures::{CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::StructureError;
use std::path::Path;
use zerocopy::{FromBytes, Immutable, KnownLayout, LE, Unaligned};

/// Human readable description
pub const DESCRIPTION: &str = "DirectX shader bytecode";

/// DXBC file magic bytes
pub fn dxbc_magic() -> Vec<Vec<u8>> {
    vec![b"DXBC".to_vec()]
}

/// Validates the DXBC header
pub fn dxbc_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const CHUNK_SM4: [u8; 4] = *b"SHDR";
    const CHUNK_SM5: [u8; 4] = *b"SHEX";

    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(header) = parse_dxbc_header(&file_data[offset..]) {
        result.confidence = CONFIDENCE_HIGH;
        result.size = header.size;

        let shader_model = if header.chunk_ids.contains(&CHUNK_SM4) {
            "Shader Model 4"
        } else if header.chunk_ids.contains(&CHUNK_SM5) {
            "Shader Model 5"
        } else {
            "Unknown Shader Model"
        };

        result.description = format!("{}, {}", result.description, shader_model);

        return Ok(result);
    }

    Err(SignatureError)
}

#[derive(Debug, Default, Clone)]
pub struct DXBCHeader {
    pub size: usize,
    pub chunk_ids: Vec<[u8; 4]>,
}

#[derive(FromBytes, KnownLayout, Unaligned, Immutable)]
#[repr(C, packed)]
struct DXBCHeaderBytes {
    magic: zerocopy::U32<LE>,
    signature: [u8; 16],
    one: zerocopy::U32<LE>,
    total_size: zerocopy::U32<LE>,
    chunk_count: zerocopy::U32<LE>,
}

// http://timjones.io/blog/archive/2015/09/02/parsing-direct3d-shader-bytecode
pub fn parse_dxbc_header(data: &[u8]) -> Result<DXBCHeader, StructureError> {
    // Parse the header
    let (header, _) = DXBCHeaderBytes::ref_from_prefix(data).map_err(|_| StructureError)?;

    if header.one.get() != 1 {
        return Err(StructureError);
    }

    let count = header.chunk_count.get() as usize;

    // Sanity check: There are at least 14 known chunks, but most likely no more than 32.
    // Prevents the for loop from spiraling into an OOM on the offchance that both the magic and "one" check pass on garbage data
    if count > 32 {
        return Err(StructureError);
    }

    let header_end = std::mem::size_of::<DXBCHeaderBytes>();

    let chunk_ids: Result<Vec<[u8; 4]>, StructureError> = data
        .get(header_end..header_end + count * 4)
        .ok_or(StructureError)?
        .chunks_exact(4)
        .map(|offset_bytes| {
            let offset_bytes: [u8; 4] = offset_bytes.try_into().map_err(|_| StructureError)?;
            let offset = u32::from_le_bytes(offset_bytes) as usize;

            let chunk = data.get(offset..offset + 4).ok_or(StructureError)?;

            chunk.try_into().map_err(|_| StructureError)
        })
        .collect();
    let chunk_ids = chunk_ids?;

    Ok(DXBCHeader {
        size: header.total_size.get() as usize,
        chunk_ids,
    })
}

/// Defines the internal extractor function for carving out DXBC images
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk_ng::extractors::ExtractorType;
/// use binwalk_ng::formats::dxbc::dxbc_extractor;
///
/// match dxbc_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn dxbc_extractor() -> Extractor {
    Extractor {
        do_not_recurse: true,
        utility: ExtractorType::Internal(extract_dxbc_file),
        ..Default::default()
    }
}

pub fn extract_dxbc_file(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&Path>,
) -> ExtractionResult {
    const OUTFILE_NAME: &str = "shader.dxbc";

    let mut result = ExtractionResult::default();

    if let Ok(header) = parse_dxbc_header(&file_data[offset..]) {
        // Report success
        result.size = Some(header.size);
        result.success = true;

        // Do extraction, if requested
        if let Some(output_directory) = output_directory {
            let chroot = Chroot::new(output_directory);
            result.success =
                chroot.carve_file(OUTFILE_NAME, file_data, offset, result.size.unwrap());
        }
    }

    result
}

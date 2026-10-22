//! Reading an input file and the parsed result every other workflow starts from.

use omnidecomp_core::{
    BinaryFormatInfo, Context, Error, ErrorCode, InputArtifact, Result,
    SymbolsResult,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub struct Analysis {
    pub artifact: InputArtifact,
    pub info: BinaryFormatInfo,
    pub data: Vec<u8>,
}

pub(crate) fn io_err(what: &str, e: std::io::Error) -> Error {
    Error::new(ErrorCode::Io, format!("{what}: {e}"))
}

pub fn read_input(path: &Path, ctx: &Context) -> Result<Vec<u8>> {
    let max = ctx.limits.max_file_size;
    let meta = fs::metadata(path).map_err(|e| io_err("cannot read input file", e))?;
    if !meta.is_file() {
        return Err(Error::new(ErrorCode::Io, "input is not a regular file"));
    }
    if meta.len() > max {
        return Err(Error::new(
            ErrorCode::LimitExceeded,
            format!("input is {} bytes; limit is {max} bytes", meta.len()),
        ));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    File::open(path)
        .and_then(|f| f.take(max + 1).read_to_end(&mut buf))
        .map_err(|e| io_err("cannot read input file", e))?;
    if buf.len() as u64 > max {
        return Err(Error::new(ErrorCode::LimitExceeded, "input grew beyond the size limit while reading"));
    }
    Ok(buf)
}

pub fn analyze(path: &Path, ctx: &Context) -> Result<Analysis> {
    let data = read_input(path, ctx)?;
    ctx.check()?;
    let info = omnidecomp_formats::parse(&data, ctx)?;
    let artifact = InputArtifact { size: data.len() as u64, sha256: format!("{:x}", Sha256::digest(&data)) };
    Ok(Analysis { artifact, info, data })
}

pub fn debug_info(a: &Analysis, ctx: &Context) -> Result<Option<omnidecomp_core::DebugInfo>> {
    omnidecomp_formats::debug_info(&a.data, &a.info, ctx)
}

/// Java class structure for a `.class` file. JAR/ZIP archives are recognized and refused.
pub fn java_class(path: &Path, ctx: &Context) -> Result<(InputArtifact, omnidecomp_core::JavaClassInfo)> {
    let data = read_input(path, ctx)?;
    if data.starts_with(b"PK\x03\x04") {
        return Err(Error::new(
            ErrorCode::UnsupportedFormat,
            "JAR/ZIP archives are not supported yet; extract a .class file and analyze that",
        ));
    }
    let class = omnidecomp_formats::parse_java_class(&data, ctx)?;
    let artifact = InputArtifact { size: data.len() as u64, sha256: format!("{:x}", Sha256::digest(&data)) };
    Ok((artifact, class))
}

/// .NET metadata; `UnsupportedFormat` when the file is not a .NET assembly.
pub fn dotnet(a: &Analysis, ctx: &Context) -> Result<omnidecomp_core::DotnetInfo> {
    omnidecomp_formats::dotnet_info(&a.data, &a.info, ctx)?
        .ok_or_else(|| Error::new(ErrorCode::UnsupportedFormat, "not a .NET assembly (no CLR header)"))
}

pub fn symbols(a: &Analysis, ctx: &Context) -> Result<SymbolsResult> {
    omnidecomp_formats::symbols(&a.data, &a.info, ctx)
}

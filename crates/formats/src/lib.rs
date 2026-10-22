//! PE and ELF header/section parsing. Format is decided by magic bytes, never by file extension.

mod dotnet;
mod elf;
mod java;
mod macho;
mod pe;
mod reader;

use omnidecomp_core::{BinaryFormatInfo, Context, DebugInfo, DotnetInfo, JavaClassInfo, Error, ErrorCode, Format, Result, SymbolsResult};

pub fn parse(data: &[u8], ctx: &Context) -> Result<BinaryFormatInfo> {
    if data.starts_with(b"MZ") {
        pe::parse(data, ctx)
    } else if data.starts_with(b"\x7fELF") {
        elf::parse(data, ctx)
    } else if macho::is_macho(data) {
        macho::parse(data, ctx)
    } else if java::is_class(data) {
        Err(Error::new(ErrorCode::UnsupportedFormat, "Java class file; use the `java` command"))
    } else if data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) && data.get(4..8).is_some_and(|n| u32::from_be_bytes([n[0], n[1], n[2], n[3]]) < 45) {
        // 0xCAFEBABE is shared with Java class files, whose bytes 4..8 are minor/major version (>= 45).
        Err(Error::new(
            ErrorCode::UnsupportedFormat,
            "universal (fat) Mach-O binary; extract a single architecture slice first",
        ))
    } else {
        Err(Error::new(
            ErrorCode::UnsupportedFormat,
            "unrecognized file magic; only PE, ELF and thin Mach-O are supported in this version",
        ))
    }
}

/// Known function ranges `[start, end)` (absolute). From PE x64 `.pdata` or ELF `.eh_frame`; empty when absent.
pub fn function_ranges(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Vec<(u64, u64)>> {
    match info.format {
        Format::Pe => pe::function_ranges(data, info, ctx),
        Format::Elf => elf::function_ranges(data, info, ctx),
        Format::MachO => Ok(Vec::new()),
    }
}

/// PDB reference (path, GUID, age) from the PE debug directory. `None` for ELF or when absent.
pub fn debug_info(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Option<DebugInfo>> {
    match info.format {
        Format::Pe => pe::debug_info(data, info, ctx),
        Format::Elf | Format::MachO => Ok(None),
    }
}

/// Structure of a Java `.class` file (not a native executable, so it bypasses `parse`).
pub fn parse_java_class(data: &[u8], ctx: &Context) -> Result<JavaClassInfo> {
    java::parse_class(data, ctx)
}

/// .NET metadata summary; `None` when the file has no CLR header.
pub fn dotnet_info(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Option<DotnetInfo>> {
    dotnet::dotnet_info(data, info, ctx)
}

/// Symbols for a file already parsed into `info`: PE imports/exports, ELF `.symtab`/`.dynsym`.
pub fn symbols(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<SymbolsResult> {
    match info.format {
        Format::Pe => pe::symbols(data, info, ctx),
        Format::Elf => elf::symbols(data, ctx),
        Format::MachO => macho::symbols(data, ctx),
    }
}

//! Disassembly of the executable sections through a registered engine.

use omnidecomp_core::{
    Arch, Context, Disassembly, Error, ErrorCode, Format, Result, Section,
};
use crate::analysis::Analysis;

pub struct DisasmOptions<'a> {
    pub engine: &'a str,
    pub arch: Option<&'a str>,
    pub section: Option<&'a str>,
    pub max_instructions: usize,
}

/// Bytes of a section that are real code: for PE, raw data is padded up to file alignment.
/// PE sections store RVAs, so addresses need the image base added. ELF and Mach-O store absolute addresses.
pub(crate) fn rva_base(info: &omnidecomp_core::BinaryFormatInfo) -> u64 {
    if info.format == Format::Pe {
        info.image_base.unwrap_or(0)
    } else {
        0
    }
}

pub(crate) fn code_len(format: Format, s: &Section) -> u64 {
    if format == Format::Pe && s.virtual_size > 0 {
        s.file_size.min(s.virtual_size)
    } else {
        s.file_size
    }
}

pub fn disassemble(a: &Analysis, opts: &DisasmOptions, ctx: &Context) -> Result<Disassembly> {
    let detected = a.info.arch;
    let engine_id = if opts.engine == "auto" {
        omnidecomp_engines::default_for(detected).ok_or_else(|| {
            Error::new(ErrorCode::UnsupportedArch, format!("no registered engine supports architecture {}", detected.as_str()))
        })?
    } else {
        opts.engine
    };
    let engine = omnidecomp_engines::find(engine_id)?;
    if let Some(requested) = opts.arch {
        let want = Arch::from_cli(requested)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("unknown architecture '{requested}'")))?;
        if want != detected {
            return Err(Error::new(
                ErrorCode::UnsupportedArch,
                format!("requested {} but the file is {}", want.as_str(), detected.as_str()),
            ));
        }
    }
    if !engine.supports(detected) {
        return Err(Error::new(
            ErrorCode::UnsupportedArch,
            format!("engine {} does not support architecture {}", engine.id(), detected.as_str()),
        ));
    }

    let sections: Vec<_> = match opts.section {
        Some(name) => {
            let found: Vec<_> = a.info.sections.iter().filter(|s| s.name == name).collect();
            if found.is_empty() {
                return Err(Error::new(ErrorCode::InvalidArgument, format!("section '{name}' not found")));
            }
            found
        }
        None => a.info.sections.iter().filter(|s| s.executable && s.file_size > 0).collect(),
    };
    if sections.is_empty() {
        return Err(Error::new(ErrorCode::Malformed, "no executable sections with file data"));
    }

    let max = opts.max_instructions.min(ctx.limits.max_instructions);
    let base = rva_base(&a.info);
    let mut instructions = Vec::new();
    let mut truncated = false;
    for s in sections {
        ctx.check()?;
        let len = code_len(a.info.format, s);
        let code = usize::try_from(s.file_offset)
            .ok()
            .zip(usize::try_from(len).ok())
            .and_then(|(o, l)| a.data.get(o..o.checked_add(l)?))
            .ok_or_else(|| Error::new(ErrorCode::Truncated, "section data outside file"))?;
        let address = base.wrapping_add(s.virtual_address);
        if engine.disassemble(code, address, detected, &s.name, max, &mut instructions, ctx)? {
            truncated = true;
            break;
        }
    }
    Ok(Disassembly {
        engine: engine.id().to_string(),
        engine_version: engine.version().to_string(),
        arch: detected,
        instructions,
        truncated,
    })
}

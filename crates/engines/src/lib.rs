//! Engine adapter layer. Core and app depend only on `DisassemblyEngine`, never on a concrete engine.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};
use omnidecomp_core::{Arch, Context, EngineCapability, Error, ErrorCode, Instruction, Result};

#[allow(clippy::too_many_arguments)]
pub trait DisassemblyEngine {
    fn id(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn capability(&self) -> EngineCapability;
    fn supports(&self, arch: Arch) -> bool;

    /// Decode `code` (mapped at `address`) and append to `out` until it holds `max` instructions.
    /// Returns true when decoding stopped early because of `max`.
    fn disassemble(
        &self,
        code: &[u8],
        address: u64,
        arch: Arch,
        section: &str,
        max: usize,
        out: &mut Vec<Instruction>,
        ctx: &Context,
    ) -> Result<bool>;
}

/// Control-flow kind and direct target of one decoded instruction.
fn flow_of(ins: &iced_x86::Instruction) -> (Option<&'static str>, Option<u64>) {
    let direct = matches!(ins.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64);
    let target = if direct { Some(ins.near_branch_target()) } else { None };
    match ins.flow_control() {
        FlowControl::Call | FlowControl::IndirectCall => (Some("call"), target),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => (Some("jump"), target),
        FlowControl::ConditionalBranch => (Some("branch"), target),
        FlowControl::Return => (Some("return"), None),
        _ => (None, None),
    }
}

pub const ICED_ID: &str = "iced-x86";
// Must match the exact version pinned in the workspace Cargo.toml.
const ICED_VERSION: &str = "1.21.0";

pub struct IcedEngine;

impl DisassemblyEngine for IcedEngine {
    fn id(&self) -> &'static str {
        ICED_ID
    }

    fn version(&self) -> &'static str {
        ICED_VERSION
    }

    fn capability(&self) -> EngineCapability {
        EngineCapability {
            id: ICED_ID.into(),
            name: "iced-x86".into(),
            version: ICED_VERSION.into(),
            kind: "disassembler".into(),
            formats: vec!["pe".into(), "elf".into()],
            architectures: vec!["x86".into(), "x86_64".into()],
            status: "available".into(),
            install_hint: None,
            limitations: vec![
                "linear sweep only; no function or control-flow recovery".into(),
                "data embedded in code sections is decoded as instructions".into(),
                "Intel syntax output only".into(),
            ],
        }
    }

    fn supports(&self, arch: Arch) -> bool {
        matches!(arch, Arch::X86 | Arch::X86_64)
    }

    fn disassemble(
        &self,
        code: &[u8],
        address: u64,
        arch: Arch,
        section: &str,
        max: usize,
        out: &mut Vec<Instruction>,
        ctx: &Context,
    ) -> Result<bool> {
        let bitness = match arch {
            Arch::X86 => 32,
            Arch::X86_64 => 64,
            other => {
                return Err(Error::new(
                    ErrorCode::UnsupportedArch,
                    format!("engine {ICED_ID} does not support {}", other.as_str()),
                ))
            }
        };
        let mut decoder = Decoder::with_ip(bitness, code, address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut ins = iced_x86::Instruction::default();
        let mut text = String::new();
        let mut n = 0u32;
        while decoder.can_decode() {
            if out.len() >= max {
                return Ok(true);
            }
            n = n.wrapping_add(1);
            if n.is_multiple_of(1024) {
                ctx.check()?;
            }
            let start = decoder.position();
            decoder.decode_out(&mut ins);
            let end = decoder.position();
            let bytes: String = code[start..end].iter().map(|b| format!("{b:02x}")).collect();
            let (mnemonic, operands) = if ins.is_invalid() {
                ("(bad)".to_string(), String::new())
            } else {
                text.clear();
                formatter.format(&ins, &mut text);
                match text.split_once(' ') {
                    Some((m, o)) => (m.to_string(), o.to_string()),
                    None => (text.clone(), String::new()),
                }
            };
            let (flow, target) = if ins.is_invalid() { (None, None) } else { flow_of(&ins) };
            out.push(Instruction {
                address: ins.ip(),
                bytes,
                mnemonic,
                operands,
                section: section.to_string(),
                engine: ICED_ID.to_string(),
                flow,
                target,
            });
        }
        Ok(false)
    }
}

pub const YAXPEAX_ARM_ID: &str = "yaxpeax-arm";
// Must match the exact version pinned in the workspace Cargo.toml.
const YAXPEAX_ARM_VERSION: &str = "0.4.0";

/// AArch64 (A64) decoder. 32-bit ARM is not supported: ARM and Thumb are mixed in one image and the
/// mode of each region cannot be told from the section alone.
pub struct Arm64Engine;

/// Control-flow kind and direct target of one decoded A64 instruction.
fn flow_of_a64(ins: &yaxpeax_arm::armv8::a64::Instruction, pc: u64) -> (Option<&'static str>, Option<u64>) {
    use yaxpeax_arm::armv8::a64::{Opcode, Operand};
    let target = ins.operands.iter().find_map(|o| match o {
        Operand::PCOffset(off) => Some(pc.wrapping_add(*off as u64)),
        _ => None,
    });
    match ins.opcode {
        Opcode::BL => (Some("call"), target),
        Opcode::BLR | Opcode::BLRAA | Opcode::BLRAAZ | Opcode::BLRAB | Opcode::BLRABZ => (Some("call"), None),
        Opcode::B => (Some("jump"), target),
        Opcode::BR | Opcode::BRAA | Opcode::BRAAZ | Opcode::BRAB | Opcode::BRABZ => (Some("jump"), None),
        Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ | Opcode::TBZ | Opcode::TBNZ => (Some("branch"), target),
        Opcode::RET | Opcode::RETAA | Opcode::RETAB | Opcode::ERET | Opcode::ERETAA | Opcode::ERETAB => {
            (Some("return"), None)
        }
        _ => (None, None),
    }
}

impl DisassemblyEngine for Arm64Engine {
    fn id(&self) -> &'static str {
        YAXPEAX_ARM_ID
    }

    fn version(&self) -> &'static str {
        YAXPEAX_ARM_VERSION
    }

    fn capability(&self) -> EngineCapability {
        EngineCapability {
            id: YAXPEAX_ARM_ID.into(),
            name: "yaxpeax-arm (AArch64 only)".into(),
            version: YAXPEAX_ARM_VERSION.into(),
            kind: "disassembler".into(),
            formats: vec!["pe".into(), "elf".into(), "macho".into()],
            architectures: vec!["aarch64".into()],
            status: "available".into(),
            install_hint: None,
            limitations: vec![
                "linear sweep only; no function or control-flow recovery".into(),
                "data embedded in code sections is decoded as instructions".into(),
                "32-bit ARM / Thumb is not supported".into(),
                "a trailing partial word is reported as (bad)".into(),
            ],
        }
    }

    fn supports(&self, arch: Arch) -> bool {
        arch == Arch::Aarch64
    }

    fn disassemble(
        &self,
        code: &[u8],
        address: u64,
        arch: Arch,
        section: &str,
        max: usize,
        out: &mut Vec<Instruction>,
        ctx: &Context,
    ) -> Result<bool> {
        use yaxpeax_arch::{Decoder as _, U8Reader};
        if arch != Arch::Aarch64 {
            return Err(Error::new(
                ErrorCode::UnsupportedArch,
                format!("engine {YAXPEAX_ARM_ID} does not support {}", arch.as_str()),
            ));
        }
        let decoder = yaxpeax_arm::armv8::a64::InstDecoder::default();
        let mut pc = address;
        for (n, chunk) in code.chunks(4).enumerate() {
            if out.len() >= max {
                return Ok(true);
            }
            if n.is_multiple_of(1024) {
                ctx.check()?;
            }
            let bytes: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            let decoded = if chunk.len() == 4 { decoder.decode(&mut U8Reader::new(chunk)).ok() } else { None };
            let (mnemonic, operands, flow, target) = match decoded {
                Some(ins) if ins.opcode != yaxpeax_arm::armv8::a64::Opcode::Invalid => {
                    let text = ins.to_string();
                    let (flow, target) = flow_of_a64(&ins, pc);
                    match text.split_once(' ') {
                        Some((m, o)) => (m.to_string(), o.to_string(), flow, target),
                        None => (text, String::new(), flow, target),
                    }
                }
                _ => ("(bad)".to_string(), String::new(), None, None),
            };
            out.push(Instruction {
                address: pc,
                bytes,
                mnemonic,
                operands,
                section: section.to_string(),
                engine: YAXPEAX_ARM_ID.to_string(),
                flow,
                target,
            });
            pc = pc.wrapping_add(4);
        }
        Ok(false)
    }
}

pub fn all() -> Vec<Box<dyn DisassemblyEngine>> {
    vec![Box::new(IcedEngine), Box::new(Arm64Engine)]
}

/// Engine id used when the caller does not name one; `None` when no engine supports `arch`.
pub fn default_for(arch: Arch) -> Option<&'static str> {
    all().iter().find(|e| e.supports(arch)).map(|e| e.id())
}

pub fn find(id: &str) -> Result<Box<dyn DisassemblyEngine>> {
    all().into_iter().find(|e| e.id() == id).ok_or_else(|| {
        let known: Vec<_> = all().iter().map(|e| e.id()).collect();
        Error::new(ErrorCode::UnknownEngine, format!("unknown engine '{id}'; available: {}", known.join(", ")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a64(words: &[u32]) -> Vec<Instruction> {
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        let ctx = Context::new(omnidecomp_core::Limits::default());
        Arm64Engine.disassemble(&code, 0x1000, Arch::Aarch64, ".text", 100, &mut out, &ctx).unwrap();
        out
    }

    #[test]
    fn a64_flow_and_targets() {
        // bl +8; ret; b.eq +8; b -8; br x16; cbz x0,+8; blr x1
        let got: Vec<_> = a64(&[0x9400_0002, 0xd65f_03c0, 0x5400_0040, 0x17ff_fffe, 0xd61f_0200, 0xb400_0040, 0xd63f_0020])
            .iter()
            .map(|i| (i.address, i.flow, i.target))
            .collect();
        assert_eq!(
            got,
            vec![
                (0x1000, Some("call"), Some(0x1008)),
                (0x1004, Some("return"), None),
                (0x1008, Some("branch"), Some(0x1010)),
                (0x100c, Some("jump"), Some(0x1004)),
                (0x1010, Some("jump"), None),
                (0x1014, Some("branch"), Some(0x101c)),
                (0x1018, Some("call"), None),
            ]
        );
    }

    #[test]
    fn a64_text_and_partial_word() {
        let ins = a64(&[0xaa01_03e0, 0xd503_201f]);
        assert_eq!((ins[0].mnemonic.as_str(), ins[0].operands.as_str()), ("mov", "x0, x1"));
        assert_eq!(ins[1].mnemonic, "nop");
        let mut out = Vec::new();
        let ctx = Context::new(omnidecomp_core::Limits::default());
        Arm64Engine.disassemble(&[0x1f, 0x20], 0, Arch::Aarch64, ".text", 10, &mut out, &ctx).unwrap();
        assert_eq!(out[0].mnemonic, "(bad)");
    }

    /// Pseudo-random words (fixed seed) must decode or report (bad), never panic.
    #[test]
    fn a64_decoder_survives_arbitrary_words() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let words: Vec<u32> = (0..50_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 16) as u32
            })
            .collect();
        let code: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut out = Vec::new();
        let ctx = Context::new(omnidecomp_core::Limits::default());
        Arm64Engine.disassemble(&code, 0, Arch::Aarch64, ".text", usize::MAX, &mut out, &ctx).unwrap();
        assert_eq!(out.len(), words.len());
    }

    #[test]
    fn default_engine_by_arch() {
        assert_eq!(default_for(Arch::X86_64), Some(ICED_ID));
        assert_eq!(default_for(Arch::Aarch64), Some(YAXPEAX_ARM_ID));
        assert_eq!(default_for(Arch::Arm), None);
    }
}

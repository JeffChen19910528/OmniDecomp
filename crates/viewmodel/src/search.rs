//! Search over a loaded file, and parsing of typed addresses.

use crate::loaded::Loaded;

impl Loaded {
    pub fn search(&self, query: &str, scope: Scope, limit: usize) -> Vec<Hit> {
        let q = query.trim();
        let mut hits = Vec::new();
        if q.is_empty() || limit == 0 {
            return hits;
        }
        if let Some(addr) = parse_address(q) {
            if scope == Scope::All || scope == Scope::Instructions {
                if let Some(i) = self.instruction_at_or_after(addr) {
                    let ins = &self.instructions()[i];
                    hits.push(Hit { kind: HitKind::Address, address: Some(ins.address), offset: None, label: format!("go to {:#x}", ins.address) });
                }
            }
        }
        let needle = q.to_lowercase();
        let has = |s: &str| s.to_lowercase().contains(&needle);
        let full = |hits: &Vec<Hit>| hits.len() >= limit;
        if matches!(scope, Scope::All | Scope::Functions) {
            if let Some(f) = &self.functions {
                for x in &f.functions {
                    if full(&hits) {
                        return hits;
                    }
                    let name = x.name.as_deref().unwrap_or("");
                    if has(name) || has(&format!("{:x}", x.address)) {
                        let label = format!("{:#x} {} ({}, {} confidence)", x.address, if name.is_empty() { "sub_unnamed" } else { name }, x.source, x.confidence);
                        hits.push(Hit { kind: HitKind::Function, address: Some(x.address), offset: None, label });
                    }
                }
            }
        }
        if matches!(scope, Scope::All | Scope::Symbols) {
            for s in &self.symbols {
                if full(&hits) {
                    return hits;
                }
                if has(&s.name) {
                    let label = format!("{} [{}]", s.name, s.kind);
                    hits.push(Hit { kind: HitKind::Symbol, address: s.address, offset: None, label });
                }
            }
        }
        if matches!(scope, Scope::All | Scope::Strings) {
            for s in &self.strings.strings {
                if full(&hits) {
                    return hits;
                }
                if has(&s.text) {
                    hits.push(Hit { kind: HitKind::String, address: self.address_of_offset(s.offset), offset: Some(s.offset), label: s.text.clone() });
                }
            }
        }
        if matches!(scope, Scope::All | Scope::Instructions) {
            for ins in self.instructions() {
                if full(&hits) {
                    return hits;
                }
                if has(&ins.mnemonic) || has(&ins.operands) {
                    let label = format!("{:#x} {} {}", ins.address, ins.mnemonic, ins.operands);
                    hits.push(Hit { kind: HitKind::Instruction, address: Some(ins.address), offset: None, label });
                }
            }
        }
        hits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    All,
    Functions,
    Symbols,
    Strings,
    Instructions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitKind {
    Address,
    Function,
    Symbol,
    String,
    Instruction,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub kind: HitKind,
    pub address: Option<u64>,
    pub offset: Option<u64>,
    pub label: String,
}

/// Addresses are written in hex, with or without `0x` (disassemblers conventionally show hex).
pub fn parse_address(text: &str) -> Option<u64> {
    let t = text.trim();
    let digits = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let digits = digits.replace('_', "");
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

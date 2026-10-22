//! Coarse instruction classes, used by front ends to pick a mnemonic color.


/// Coarse class of an instruction, used to pick a mnemonic color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicClass {
    Call,
    Jump,
    Branch,
    Return,
    Nop,
    Invalid,
    Other,
}

pub fn mnemonic_class(ins: &omnidecomp_core::Instruction) -> MnemonicClass {
    match ins.flow {
        Some("call") => MnemonicClass::Call,
        Some("jump") => MnemonicClass::Jump,
        Some("branch") => MnemonicClass::Branch,
        Some("return") => MnemonicClass::Return,
        _ if ins.mnemonic == "nop" => MnemonicClass::Nop,
        _ if ins.mnemonic == "(bad)" => MnemonicClass::Invalid,
        _ => MnemonicClass::Other,
    }
}

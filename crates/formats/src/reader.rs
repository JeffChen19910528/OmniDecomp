//! Bounds-checked little/big-endian reader. All parser access to input bytes goes through here.

use omnidecomp_core::{Error, ErrorCode, Result};

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    big_endian: bool,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], big_endian: bool) -> Self {
        Self { data, big_endian }
    }

    pub fn bytes(&self, offset: u64, len: u64) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= self.data.len() as u64)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Truncated,
                    format!(
                        "read of {len} bytes at offset {offset:#x} exceeds file size {}",
                        self.data.len()
                    ),
                )
            })?;
        Ok(&self.data[offset as usize..end as usize])
    }

    fn array<const N: usize>(&self, offset: u64) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(offset, N as u64)?);
        Ok(out)
    }

    pub fn u16(&self, offset: u64) -> Result<u16> {
        let a = self.array::<2>(offset)?;
        Ok(if self.big_endian { u16::from_be_bytes(a) } else { u16::from_le_bytes(a) })
    }

    pub fn u32(&self, offset: u64) -> Result<u32> {
        let a = self.array::<4>(offset)?;
        Ok(if self.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) })
    }

    pub fn u64(&self, offset: u64) -> Result<u64> {
        let a = self.array::<8>(offset)?;
        Ok(if self.big_endian { u64::from_be_bytes(a) } else { u64::from_le_bytes(a) })
    }
}

/// Section names come from untrusted files: cut at NUL, cap the length, and drop control characters.
pub fn sanitize_name(raw: &[u8]) -> String {
    sanitize_text(raw, 64)
}

/// Like `sanitize_name` with a caller-chosen length cap (for paths).
pub fn sanitize_text(raw: &[u8], max: usize) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len()).min(max);
    String::from_utf8_lossy(&raw[..end])
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub fn malformed(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::Malformed, msg)
}

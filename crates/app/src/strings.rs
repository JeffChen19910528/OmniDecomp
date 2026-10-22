//! Printable string extraction.

use omnidecomp_core::{
    Context, Result, StringHit, StringsResult,
};

/// Extracts printable ASCII runs of at least `min_length` bytes.
pub fn extract_strings(data: &[u8], min_length: usize, ctx: &Context) -> Result<StringsResult> {
    const MAX_TEXT: usize = 1024;
    let min_length = min_length.max(1);
    let mut strings = Vec::new();
    let mut truncated = false;
    let mut start = 0usize;
    let flush = |from: usize, to: usize, strings: &mut Vec<StringHit>| -> bool {
        if to - from >= min_length {
            if strings.len() >= ctx.limits.max_strings {
                return false;
            }
            let end = to.min(from + MAX_TEXT);
            strings.push(StringHit {
                offset: from as u64,
                text: String::from_utf8_lossy(&data[from..end]).into_owned(),
            });
        }
        true
    };
    for (i, b) in data.iter().enumerate() {
        if i % 65536 == 0 {
            ctx.check()?;
        }
        if !(*b == b'\t' || (0x20..=0x7e).contains(b)) {
            if !flush(start, i, &mut strings) {
                truncated = true;
                break;
            }
            start = i + 1;
        }
    }
    if !truncated && !flush(start, data.len(), &mut strings) {
        truncated = true;
    }
    Ok(StringsResult { encoding: "ascii", min_length, strings, truncated })
}

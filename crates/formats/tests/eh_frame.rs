use omnidecomp_core::{Context, Limits};
use omnidecomp_formats::{function_ranges, parse};
use omnidecomp_testsamples::{elf64_with_code, elf64_with_eh_frame, JMP_CODE};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn ranges(bytes: &[u8]) -> Vec<(u64, u64)> {
    let info = parse(bytes, &ctx()).unwrap();
    function_ranges(bytes, &info, &ctx()).unwrap()
}

#[test]
fn fde_ranges_are_absolute_and_sorted() {
    let elf = elf64_with_eh_frame(&JMP_CODE, &[(0x40_1006, 2), (0x40_1000, 6)]);
    assert_eq!(ranges(&elf), vec![(0x40_1000, 0x40_1006), (0x40_1006, 0x40_1008)]);
}

#[test]
fn zero_sized_and_duplicate_fdes_are_dropped() {
    let elf = elf64_with_eh_frame(&JMP_CODE, &[(0x40_1000, 6), (0x40_1000, 6), (0x40_1006, 0)]);
    assert_eq!(ranges(&elf), vec![(0x40_1000, 0x40_1006)]);
}

#[test]
fn no_eh_frame_means_no_ranges() {
    assert!(ranges(&elf64_with_code(&JMP_CODE)).is_empty());
}

#[test]
fn range_limit_applies() {
    let elf = elf64_with_eh_frame(&JMP_CODE, &[(0x40_1000, 6), (0x40_1006, 2)]);
    let info = parse(&elf, &ctx()).unwrap();
    let c = Context::new(Limits { max_symbols: 1, ..Limits::default() });
    assert_eq!(function_ranges(&elf, &info, &c).unwrap().len(), 1);
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_eh_frame_never_panics() {
    let sample = elf64_with_eh_frame(&JMP_CODE, &[(0x40_1000, 6), (0x40_1006, 2)]);
    for len in 0..sample.len() {
        if let Ok(i) = parse(&sample[..len], &ctx()) {
            let _ = function_ranges(&sample[..len], &i, &ctx());
        }
    }
    let mut m = sample.clone();
    for k in 0..m.len() {
        for flip in [0xffu8, 0x01, 0x80] {
            let old = m[k];
            m[k] ^= flip;
            if let Ok(i) = parse(&m, &ctx()) {
                let _ = function_ranges(&m, &i, &ctx());
            }
            m[k] = old;
        }
    }
}

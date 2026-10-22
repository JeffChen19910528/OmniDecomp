use omnidecomp_core::{Context, Limits};
use omnidecomp_formats::{function_ranges, parse};
use omnidecomp_testsamples::{minimal_elf64, minimal_pe32, minimal_pe64, pe64_with_pdata, JMP_CODE};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn ranges(bytes: &[u8]) -> Vec<(u64, u64)> {
    let info = parse(bytes, &ctx()).unwrap();
    function_ranges(bytes, &info, &ctx()).unwrap()
}

#[test]
fn pdata_ranges_are_absolute_sorted_and_skip_chained() {
    let pe = pe64_with_pdata(
        &JMP_CODE,
        &[(0x1006, 0x1008, false), (0x1000, 0x1006, false), (0x1004, 0x1005, true), (0x1008, 0x1008, false)],
    );
    assert_eq!(ranges(&pe), vec![(0x1_4000_1000, 0x1_4000_1006), (0x1_4000_1006, 0x1_4000_1008)]);
}

#[test]
fn no_exception_directory_means_no_ranges() {
    assert!(ranges(&minimal_pe64()).is_empty());
    assert!(ranges(&minimal_pe32()).is_empty());
    assert!(ranges(&minimal_elf64()).is_empty());
}

#[test]
fn range_limit_applies() {
    let pe = pe64_with_pdata(&JMP_CODE, &[(0x1000, 0x1006, false), (0x1006, 0x1008, false)]);
    let info = parse(&pe, &ctx()).unwrap();
    let c = Context::new(Limits { max_symbols: 1, ..Limits::default() });
    assert_eq!(function_ranges(&pe, &info, &c).unwrap().len(), 1);
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_pdata_never_panics() {
    let sample = pe64_with_pdata(&JMP_CODE, &[(0x1000, 0x1006, false), (0x1006, 0x1008, true)]);
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

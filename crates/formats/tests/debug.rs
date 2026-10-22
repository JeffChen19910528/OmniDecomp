use omnidecomp_core::{Context, Limits};
use omnidecomp_formats::{debug_info, parse};
use omnidecomp_testsamples::{minimal_elf64, minimal_pe32, minimal_pe64, pe64_with_pdb};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn dbg(bytes: &[u8]) -> Option<omnidecomp_core::DebugInfo> {
    let info = parse(bytes, &ctx()).unwrap();
    debug_info(bytes, &info, &ctx()).unwrap()
}

#[test]
fn codeview_record_is_decoded() {
    let d = dbg(&pe64_with_pdb("C:\\build\\app.pdb")).unwrap();
    assert_eq!(d.kind, "codeview_pdb70");
    assert_eq!(d.pdb_path, "C:\\build\\app.pdb");
    assert_eq!(d.guid, "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(d.age, 3);
}

#[test]
fn control_characters_in_path_are_sanitized() {
    let d = dbg(&pe64_with_pdb("a\x1b[31mb.pdb")).unwrap();
    assert_eq!(d.pdb_path, "a?[31mb.pdb");
}

#[test]
fn no_debug_directory_means_none() {
    assert!(dbg(&minimal_pe64()).is_none());
    assert!(dbg(&minimal_pe32()).is_none());
    assert!(dbg(&minimal_elf64()).is_none());
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_debug_directory_never_panics() {
    let sample = pe64_with_pdb("x.pdb");
    for len in 0..sample.len() {
        if let Ok(i) = parse(&sample[..len], &ctx()) {
            let _ = debug_info(&sample[..len], &i, &ctx());
        }
    }
    let mut m = sample.clone();
    for k in 0..m.len() {
        for flip in [0xffu8, 0x01, 0x80] {
            let old = m[k];
            m[k] ^= flip;
            if let Ok(i) = parse(&m, &ctx()) {
                let _ = debug_info(&m, &i, &ctx());
            }
            m[k] = old;
        }
    }
}

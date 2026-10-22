use omnidecomp_core::{Context, Limits};
use omnidecomp_formats::{dotnet_info, parse};
use omnidecomp_testsamples::{minimal_elf64, minimal_pe64, pe64_dotnet};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn dn(bytes: &[u8]) -> Option<omnidecomp_core::DotnetInfo> {
    let info = parse(bytes, &ctx()).unwrap();
    dotnet_info(bytes, &info, &ctx()).unwrap()
}

#[test]
fn metadata_tables_are_decoded() {
    let d = dn(&pe64_dotnet()).unwrap();
    assert_eq!(d.runtime_version, "v4.0.30319");
    assert!(d.il_only);
    assert_eq!(d.entry_point_token, Some(0x0600_0001));
    let a = d.assembly.unwrap();
    assert_eq!((a.name.as_str(), a.version.as_str()), ("Sample", "1.2.3.4"));
    assert_eq!(d.references.len(), 1);
    assert_eq!((d.references[0].name.as_str(), d.references[0].version.as_str()), ("mscorlib", "4.0.0.0"));
    assert_eq!((d.type_count, d.method_count), (2, 1));
    assert_eq!(d.types[0].name, "<Module>");
    assert!(d.types[0].methods.is_empty());
    assert_eq!((d.types[1].namespace.as_str(), d.types[1].name.as_str()), ("Demo", "Program"));
    assert_eq!(d.types[1].methods, vec!["Main".to_string()]);
    assert!(!d.truncated);
}

#[test]
fn symbol_limit_truncates_type_list() {
    let s = pe64_dotnet();
    let info = parse(&s, &ctx()).unwrap();
    let c = Context::new(Limits { max_symbols: 2, ..Limits::default() });
    let d = dotnet_info(&s, &info, &c).unwrap().unwrap();
    assert!(d.truncated);
    assert_eq!(d.types.len(), 2);
}

#[test]
fn non_dotnet_files_return_none() {
    assert!(dn(&minimal_pe64()).is_none());
    assert!(dn(&minimal_elf64()).is_none());
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_metadata_never_panics() {
    let sample = pe64_dotnet();
    for len in 0..sample.len() {
        if let Ok(i) = parse(&sample[..len], &ctx()) {
            let _ = dotnet_info(&sample[..len], &i, &ctx());
        }
    }
    let mut m = sample.clone();
    for k in 0..m.len() {
        for flip in [0xffu8, 0x01, 0x80] {
            let old = m[k];
            m[k] ^= flip;
            if let Ok(i) = parse(&m, &ctx()) {
                let _ = dotnet_info(&m, &i, &ctx());
            }
            m[k] = old;
        }
    }
}

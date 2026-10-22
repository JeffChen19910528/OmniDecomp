use omnidecomp_core::{Context, ErrorCode, Limits};
use omnidecomp_formats::{parse, parse_java_class};
use omnidecomp_testsamples::{java_class, minimal_elf64};

fn ctx() -> Context {
    Context::new(Limits::default())
}

#[test]
fn class_structure_is_decoded() {
    let c = parse_java_class(&java_class(), &ctx()).unwrap();
    assert_eq!((c.major, c.minor, c.java_version.as_str()), (52, 0, "Java 8"));
    assert_eq!(c.class_name, "Hello");
    assert_eq!(c.super_class.as_deref(), Some("java.lang.Object"));
    assert_eq!(c.access, vec!["public"]);
    assert_eq!(c.interfaces, vec!["java.lang.Runnable".to_string()]);
    assert_eq!(c.source_file.as_deref(), Some("Hello.java"));
    assert_eq!((c.fields[0].name.as_str(), c.fields[0].descriptor.as_str(), c.fields[0].access.clone()), ("field", "I", vec!["private"]));
    assert_eq!(c.methods[0].name, "main");
    assert_eq!(c.methods[0].descriptor, "([Ljava/lang/String;)V");
    assert_eq!(c.methods[0].access, vec!["public", "static"]);
    assert!(!c.truncated);
}

#[test]
fn member_limit_truncates() {
    let c = Context::new(Limits { max_symbols: 1, ..Limits::default() });
    let info = parse_java_class(&java_class(), &c).unwrap();
    assert!(info.truncated);
    assert_eq!(info.fields.len() + info.methods.len(), 1);
}

#[test]
fn class_files_are_not_native_executables_and_non_classes_are_rejected() {
    assert_eq!(parse(&java_class(), &ctx()).unwrap_err().code, ErrorCode::UnsupportedFormat);
    assert!(parse_java_class(&minimal_elf64(), &ctx()).is_err());
    assert!(parse_java_class(&[], &ctx()).is_err());
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_class_never_panics() {
    let sample = java_class();
    for len in 0..sample.len() {
        let _ = parse_java_class(&sample[..len], &ctx());
    }
    let mut m = sample.clone();
    for k in 0..m.len() {
        for flip in [0xffu8, 0x01, 0x80] {
            let old = m[k];
            m[k] ^= flip;
            let _ = parse_java_class(&m, &ctx());
            m[k] = old;
        }
    }
}

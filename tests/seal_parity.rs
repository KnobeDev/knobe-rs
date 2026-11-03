//! Sealer parity: for the same request, the Rust sealer must emit exactly the
//! bytes that upstream knobe-core.js createKnobe() emits, and lens.py must
//! verify the result.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use knobe::{CreateOptions, Value, create_knobe};

fn node_create(request: &str) -> String {
    let mut child = Command::new("node")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/create.mjs"))
        .env("KNOBE_PROTOCOL_DIR", common::protocol_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node must be installed to run seal parity tests");
    child.stdin.take().unwrap().write_all(request.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "createKnobe failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

fn rust_create(request: &str) -> Result<String, knobe::SealError> {
    let req = knobe::json::parse(request).expect("test request is valid JSON");
    let opts = CreateOptions {
        fields: req.get("fields").cloned().unwrap_or(Value::Object(Vec::new())),
        body: req.get("body").and_then(Value::as_str).unwrap_or("").to_string(),
        author: req.get("author").and_then(Value::as_str).map(str::to_string),
        today: None,
    };
    create_knobe(&opts).map(|c| c.text)
}

const CASES: &[(&str, &str)] = &[
    ("minimal", r#"{"fields":{"title":"Hello","created_date":"2026-11-02"}}"#),
    ("defaults-for-null", r#"{"fields":{"title":null,"summary":null,"created_date":"2026-11-02"}}"#),
    ("author", r#"{"fields":{"title":"A","created_date":"2026-11-02"},"author":"Ada Lovelace"}"#),
    (
        "body-crlf-trailing",
        r##"{"fields":{"title":"B","created_date":"2026-11-02"},"body":"# Heading\r\n\r\nLine one   \r\nLine two\t\n\n\n"}"##,
    ),
    ("body-whitespace-only", r#"{"fields":{"title":"W","created_date":"2026-11-02"},"body":"  \n \t "}"#),
    ("body-x85-edge", "{\"fields\":{\"title\":\"X\",\"created_date\":\"2026-11-02\"},\"body\":\"text\u{85}\"}"),
    ("yaml-quoting", r#"{"fields":{"title":"He said \"hi\" \\ bye","created_date":"2026-11-02"}}"#),
    (
        "nfd-normalized",
        "{\"fields\":{\"title\":\"Cafe\u{301}\",\"cafe\u{301}-note\":\"e\u{301}\",\"created_date\":\"2026-11-02\"}}",
    ),
    (
        "astral-and-controls",
        "{\"fields\":{\"title\":\"\u{1F600} smile\",\"summary\":\"tab\\there\\u0001\",\"\u{1F600}\":\"k\",\"\u{FFFF}\":\"k2\",\"created_date\":\"2026-11-02\"}}",
    ),
    (
        "numbers-coerced",
        r#"{"fields":{"title":"N","created_date":"2026-11-02","n":{"int":3,"neg":-0,"half":1.5,"whole":2.0,"big":1e20,"tiny":1e-7,"exp":1E2,"edge":9007199254740991,"pi":3.141592653589793}}}"#,
    ),
    (
        "extensions-and-parents",
        r#"{"fields":{"title":"E","created_date":"2026-11-02","license":"CC0-1.0","privacy_level":"internal","quarantine_status":"trusted","identity_status":"declared","content_type":"ext-notes","parents":[{"title":"P","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"inscribe:flags":{"ok":true,"none":null,"list":["a",{"b":"c"}]}},"body":"Body text.\n"}"#,
    ),
    (
        "custom-attribution",
        r#"{"fields":{"title":"C","created_date":"2026-11-02","attribution":{"sources":[{"author":"X","contribution":"editor"},{"author":"Y","contribution":"ai-assist"}]}}}"#,
    ),
    (
        "stale-hashes-dropped",
        r#"{"fields":{"title":"S","created_date":"2026-11-02","payload_hash":"zz","body_hash":"zz"}}"#,
    ),
    (
        "long-payload-wraps",
        r#"{"fields":{"title":"L","created_date":"2026-11-02","summary":"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"}}"#,
    ),
];

#[test]
fn rust_sealer_output_is_byte_identical_to_create_knobe() {
    let mut diffs = Vec::new();
    for (name, req) in CASES {
        let js = node_create(req);
        match rust_create(req) {
            Ok(rs) if rs == js => {}
            Ok(rs) => diffs.push(format!("{name}\n--- js ---\n{js}\n--- rust ---\n{rs}")),
            Err(e) => diffs.push(format!("{name}: rust refused: {e}")),
        }
    }
    assert!(diffs.is_empty(), "{} of {} cases differ:\n{}", diffs.len(), CASES.len(), diffs.join("\n"));
}

#[test]
fn sealed_files_verify_under_lens_py() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sealed");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, req) in CASES {
        let text = rust_create(req).unwrap();
        let path = dir.join(format!("{name}.knobe.md"));
        std::fs::write(&path, &text).unwrap();
        let py = common::lens(&path).expect("lens.py output");
        assert_eq!(py.exit_code, 0, "{name}: lens.py rejected our seal: {py:?}");
        assert_eq!(py.state, Value::Str("verified".into()), "{name}");
    }
}

// --- deliberate refusals (see README "Sealer refusals") ---

#[test]
fn refuses_integers_beyond_2_pow_53_instead_of_losing_digits() {
    let e = rust_create(r#"{"fields":{"title":"T","created_date":"2026-11-02","n":12345678901234567890}}"#);
    assert!(e.is_err(), "JS would round this to 12345678901234567000; we refuse");
}

#[test]
fn refuses_keys_that_collide_under_nfc() {
    let e = rust_create("{\"fields\":{\"title\":\"T\",\"caf\u{e9}\":\"1\",\"cafe\u{301}\":\"2\"}}");
    assert!(e.is_err());
}

#[test]
fn refuses_duplicate_keys() {
    assert!(knobe::json::parse(r#"{"a":"1","a":"2"}"#).is_err());
}

#[test]
fn refuses_to_emit_a_file_whose_body_would_not_verify() {
    // JS \s strips a trailing U+FEFF from the written body, Python strip()
    // keeps it in body_hash: createKnobe emits a verified-body-modified file.
    let e = rust_create("{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\"},\"body\":\"text\u{feff}\"}");
    assert!(e.is_err());
}

#[test]
fn refuses_title_newline_that_would_break_frontmatter() {
    let e = rust_create(r#"{"fields":{"title":"a\n---\nb","created_date":"2026-11-02"},"body":"x"}"#);
    assert!(e.is_err());
}

#[test]
fn refuses_line_breaks_in_frontmatter_fields() {
    for field in ["content_type", "license"] {
        let req = format!(r#"{{"fields":{{"title":"T","created_date":"2026-11-02","{field}":"x\ny"}}}}"#);
        assert!(matches!(rust_create(&req), Err(knobe::SealError::LineBreakInFrontmatter(f)) if f == field), "{field}");
    }
}

#[test]
fn default_created_date_is_utc_today() {
    let out = Command::new("date").args(["-u", "+%F"]).output().unwrap();
    let today = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let text = rust_create(r#"{"fields":{"title":"T"}}"#).unwrap();
    assert!(text.contains(&format!("created_date: \"{today}\"")), "{text}");
}

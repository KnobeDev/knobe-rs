//! Sealer parity: for the same request, the Rust sealer must emit exactly the
//! bytes that upstream knobe-core.js createKnobe() emits, and lens.py must
//! verify the result. Where createKnobe refuses a request for an unassigned
//! code point, the Rust sealer must refuse it for the same code point.

mod common;

use std::cmp::Ordering::{Equal, Greater, Less};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use knobe::{CreateOptions, Value, create_knobe};
use unicode_normalization::UnicodeNormalization;

/// Exit status of tests/support/create.mjs when createKnobe refuses a request.
const NODE_REFUSED: i32 = 3;

fn node(script: &str) -> Command {
    let mut cmd = Command::new("node");
    cmd.arg(format!("{}/tests/support/{script}", env!("CARGO_MANIFEST_DIR")))
        .env("KNOBE_PROTOCOL_DIR", common::protocol_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// The file createKnobe emits for `request`, or its message if it refuses.
fn node_create(request: &str) -> Result<String, String> {
    let mut child = node("create.mjs").spawn().expect("node must be installed to run seal parity tests");
    child.stdin.take().unwrap().write_all(request.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    match out.status.code() {
        Some(0) => Ok(String::from_utf8(out.stdout).unwrap()),
        Some(NODE_REFUSED) => Err(stderr),
        _ => panic!("create.mjs failed: {stderr}"),
    }
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
        "{\"fields\":{\"title\":\"\u{1F600} smile\",\"summary\":\"tab\\there\\u0001\",\"\u{1F600}\":\"k\",\"\u{FF21}\":\"k2\",\"created_date\":\"2026-11-02\"}}",
    ),
    // Private-use code points are assigned (Co, not Cn): createKnobe seals them.
    (
        "private-use",
        "{\"fields\":{\"title\":\"\u{E000}\u{F8FF}\",\"\u{F0000}\":\"\u{10FFFD}\",\"created_date\":\"2026-11-02\"}}",
    ),
    // createKnobe checks the payload only. The body is hashed without NFC, so
    // an unassigned code point there cannot split verifiers.
    (
        "unassigned-in-body",
        "{\"fields\":{\"title\":\"U\",\"created_date\":\"2026-11-02\"},\"body\":\"a\u{0378}b\u{FFFF}c\"}",
    ),
    // payload_hash and body_hash from the request are dropped before the check.
    (
        "unassigned-in-stale-hashes",
        "{\"fields\":{\"title\":\"H\",\"created_date\":\"2026-11-02\",\"payload_hash\":\"\u{FFFF}\",\"body_hash\":\"\u{FDD0}\"}}",
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
        match (node_create(req), rust_create(req)) {
            (Ok(js), Ok(rs)) if rs == js => {}
            (Ok(js), Ok(rs)) => diffs.push(format!("{name}\n--- js ---\n{js}\n--- rust ---\n{rs}")),
            (Ok(_), Err(e)) => diffs.push(format!("{name}: rust refused: {e}")),
            (Err(e), _) => diffs.push(format!("{name}: createKnobe refused: {e}")),
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

// --- refusals shared with createKnobe: unassigned code points ---
//
// Upstream PR #34 (issue #33): NFC of a code point the engine's Unicode
// tables do not know can change in a later Unicode version, so the reference
// sealer refuses it in any payload key or string.

/// Requests createKnobe refuses, and the code point its message names. All
/// but the last are noncharacters, which no Unicode version will assign.
const REFUSED_UNASSIGNED: &[(&str, &str, char)] = &[
    ("key", "{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\",\"\u{FFFF}\":\"k\"}}", '\u{FFFF}'),
    ("title", "{\"fields\":{\"title\":\"\u{FDD0}\",\"created_date\":\"2026-11-02\"}}", '\u{FDD0}'),
    (
        "after-assigned-text",
        "{\"fields\":{\"title\":\"T\",\"summary\":\"caf\u{E9} \u{1F600} \u{1FFFE} end\",\"created_date\":\"2026-11-02\"}}",
        '\u{1FFFE}',
    ),
    ("author", "{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\"},\"author\":\"A\u{FFFE}\"}", '\u{FFFE}'),
    (
        "nested-array-value",
        "{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\",\"x\":{\"list\":[\"a\",[\"\u{10FFFF}\"]]}}}",
        '\u{10FFFF}',
    ),
    (
        "nested-object-key",
        "{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\",\"x\":[{\"\u{EFFFF}\":true}]}}",
        '\u{EFFFF}',
    ),
    // createKnobe normalizes an entry's value before its key.
    (
        "value-before-its-key",
        "{\"fields\":{\"title\":\"T\",\"created_date\":\"2026-11-02\",\"\u{FDD1}\":\"\u{FDD2}\"}}",
        '\u{FDD2}',
    ),
    // A reserved code point, the one upstream's selftest uses.
    ("reserved", "{\"fields\":{\"title\":\"a\u{0378}b\",\"created_date\":\"2026-11-02\"}}", '\u{0378}'),
];

/// The code point in "the text contains U+FFFF, a character ...".
fn named_code_point(message: &str) -> Option<char> {
    let hex = message.split_once("contains U+")?.1;
    let end = hex.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(hex.len());
    char::from_u32(u32::from_str_radix(&hex[..end], 16).ok()?)
}

#[test]
fn refuses_the_unassigned_code_point_create_knobe_refuses() {
    let mut diffs = Vec::new();
    for (name, req, want) in REFUSED_UNASSIGNED {
        let js = node_create(req);
        let rs = rust_create(req);
        let js_named = js.as_ref().err().and_then(|message| named_code_point(message));
        let rs_named = match &rs {
            Err(knobe::SealError::UnassignedCodePoint(c)) => Some(*c),
            _ => None,
        };
        if js_named != Some(*want) || rs_named != Some(*want) {
            let rs = rs.map(|_| "sealed").map_err(|e| e.to_string());
            let js = js.map(|_| "sealed");
            diffs.push(format!("{name}: want a refusal naming U+{:04X}\n  js: {js:?}\n  rust: {rs:?}", *want as u32));
        }
    }
    assert!(diffs.is_empty(), "{} of {} cases differ:\n{}", diffs.len(), REFUSED_UNASSIGNED.len(), diffs.join("\n"));
}

#[test]
fn the_refusal_message_names_the_code_point_as_create_knobe_does() {
    let e = rust_create("{\"fields\":{\"title\":\"\u{FFFF}\"}}").unwrap_err();
    assert_eq!(named_code_point(&e.to_string()), Some('\u{FFFF}'), "{e}");
    let e = rust_create("{\"fields\":{\"title\":\"\u{10FFFF}\"}}").unwrap_err();
    assert_eq!(named_code_point(&e.to_string()), Some('\u{10FFFF}'), "{e}");
}

/// A set of Unicode scalar values, indexed by code point.
struct CodePoints(Vec<bool>);

impl CodePoints {
    fn of(contains: impl Fn(char) -> bool) -> Self {
        CodePoints((0..=0x10FFFF).map(|cp| char::from_u32(cp).is_some_and(&contains)).collect())
    }

    /// From inclusive hex ranges, one "START-END" per line.
    fn from_ranges<'a>(lines: impl Iterator<Item = &'a str>) -> Self {
        let mut set = vec![false; 0x11_0000];
        for line in lines {
            let (start, end) = line.split_once('-').unwrap_or_else(|| panic!("not a START-END range: {line:?}"));
            let bound = |hex: &str| usize::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("{line:?}: {e}"));
            set[bound(start)..=bound(end)].fill(true);
        }
        CodePoints(set)
    }

    fn chars(&self) -> impl Iterator<Item = char> + '_ {
        (0..=0x10FFFF).filter(|&cp| self.0[cp as usize]).filter_map(char::from_u32)
    }

    fn minus(&self, other: &CodePoints) -> CodePoints {
        CodePoints(self.0.iter().zip(&other.0).map(|(mine, theirs)| *mine && !theirs).collect())
    }

    fn len(&self) -> usize {
        self.chars().count()
    }

    /// "0378-0379 038B ...", for a failure message.
    fn show(&self) -> String {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for cp in self.chars().map(u32::from) {
            match ranges.last_mut() {
                Some((_, end)) if *end + 1 == cp => *end = cp,
                _ => ranges.push((cp, cp)),
            }
        }
        let show = |&(start, end): &(u32, u32)| {
            if start == end { format!("{start:04X}") } else { format!("{start:04X}-{end:04X}") }
        };
        ranges.iter().map(show).collect::<Vec<_>>().join(" ")
    }
}

/// Unicode's 66 noncharacters are unassigned in every version.
fn is_noncharacter(c: char) -> bool {
    matches!(c, '\u{FDD0}'..='\u{FDEF}') || (c as u32) & 0xFFFE == 0xFFFE
}

/// `node tests/support/verify.mjs FILE`: upstream knobe-core.js verify().
fn node_verify(file: &Path) -> common::Gate {
    let out = node("verify.mjs").arg(file).output().expect("node must be installed to run seal parity tests");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty(), "verify.mjs failed: {}", String::from_utf8_lossy(&out.stderr));
    common::gate_from_json(&stdout, out.status.code().unwrap_or(-1))
}

/// Seals a file whose payload holds every code point in `newer`, alone, in
/// its canonical decomposition, and among combining marks that NFC reorders
/// or composes, then requires lens.py and knobe-core.js to verify it. Their
/// tables do not know these code points. An older normalizer leaves a code
/// point it does not know alone, so text that is NFC by newer tables should
/// read as NFC to it (upstream issue #33, point 2).
fn assert_reference_verifiers_accept(newer: &CodePoints) {
    let strings: Vec<Value> = newer
        .chars()
        .flat_map(|c| {
            let decomposed: String = c.nfd().collect();
            [format!("{c}"), decomposed, format!("a{c}\u{301}\u{323}"), format!("a\u{301}\u{323}{c}{c}\u{301}")]
        })
        .map(Value::Str)
        .collect();
    let fields = Value::Object(vec![
        ("title".into(), Value::Str("Code points newer than the reference engines' tables".into())),
        ("created_date".into(), Value::Str("2026-11-02".into())),
        ("x-newer".into(), Value::Array(strings)),
    ]);
    let created =
        create_knobe(&CreateOptions { fields, ..CreateOptions::default() }).expect("knobe seals assigned text");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sealed");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("newer-code-points.knobe.md");
    std::fs::write(&path, &created.text).unwrap();

    let verified = Value::Str("verified".into());
    let py = common::lens(&path).expect("lens.py output");
    assert!(py.exit_code == 0 && py.state == verified, "lens.py rejected {}: {py:?}", path.display());
    let js = node_verify(&path);
    assert!(js.exit_code == 0 && js.state == verified, "knobe-core.js rejected {}: {js:?}", path.display());
    assert_eq!(py.computed, Value::Str(created.payload_hash.clone()), "lens.py computed another payload hash");
    assert_eq!(js.computed, Value::Str(created.payload_hash), "knobe-core.js computed another payload hash");
}

/// A Unicode version, major and minor.
type UnicodeVersion = (u8, u8);

/// Characters added between two Unicode versions (older, newer), from the
/// release pages: https://www.unicode.org/versions/Unicode18.0.0/ says
/// "Unicode 18.0 adds 13,007 characters".
const CHARACTERS_ADDED: &[(UnicodeVersion, UnicodeVersion, usize)] = &[((17, 0), (18, 0), 13_007)];

/// What upstream seal() refuses depends on the Unicode version of the
/// JavaScript engine running it, and what this crate refuses on the version
/// of its normalization tables (`knobe::UNICODE_VERSION`). With the same
/// version the two must refuse exactly the same code points. With different
/// versions, the newer one may accept more and nothing else may differ, and
/// how many more must be the number of characters the Unicode releases in
/// between added, where `CHARACTERS_ADDED` has it. Where this crate is the
/// newer one, a file sealed with every code point it alone accepts must still
/// verify in lens.py and knobe-core.js.
#[test]
fn seal_refuses_the_code_points_upstream_seal_refuses() {
    let out = node("unassigned.mjs").output().expect("node must be installed to run seal parity tests");
    assert!(out.status.success(), "unassigned.mjs failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = stdout.lines();
    let js_unicode =
        lines.next().and_then(|l| l.strip_prefix("unicode ")).expect("unassigned.mjs prints its Unicode version");
    let mut numbers = js_unicode.split('.').map(|n| n.parse::<u8>().expect("a numeric Unicode version"));
    let js_version = (numbers.next().unwrap(), numbers.next().unwrap_or(0));
    let js = CodePoints::from_ranges(lines);

    let rust = CodePoints::of(|c| {
        let payload = Value::Object(vec![("v".into(), Value::Str(c.to_string()))]);
        match knobe::seal(&payload) {
            Ok(_) => false,
            Err(knobe::SealError::UnassignedCodePoint(named)) if named == c => true,
            Err(e) => panic!("seal refused U+{:04X} for another reason: {e}", c as u32),
        }
    });
    let (major, minor, _) = knobe::UNICODE_VERSION;
    let rust_unicode = format!("{major}.{minor}");

    let noncharacters = CodePoints::of(is_noncharacter);
    assert_eq!(noncharacters.len(), 66);
    assert_eq!(noncharacters.minus(&js).show(), "", "upstream seal() accepts a noncharacter");
    assert_eq!(noncharacters.minus(&rust).show(), "", "knobe::seal accepts a noncharacter");

    let only_js = js.minus(&rust);
    let only_rust = rust.minus(&js);
    let rust_version = (major, minor);
    let (older, newer, newly_assigned, only_newer_refuses) = match rust_version.cmp(&js_version) {
        Equal => {
            assert!(
                only_js.len() + only_rust.len() == 0,
                "both engines have Unicode {js_unicode} tables but refuse different code points\n  \
                 only upstream seal() refuses: {}\n  only knobe::seal refuses: {}",
                only_js.show(),
                only_rust.show()
            );
            return;
        }
        Greater => (js_version, rust_version, &only_js, &only_rust),
        Less => (rust_version, js_version, &only_rust, &only_js),
    };
    let engines =
        format!("knobe::seal has Unicode {rust_unicode} tables and upstream seal() on this Node has {js_unicode}");
    assert_eq!(only_newer_refuses.show(), "", "{engines}: the newer one refuses code points the older one accepts");
    match CHARACTERS_ADDED.iter().find(|(from, to, _)| (*from, *to) == (older, newer)) {
        Some((_, _, published)) => assert_eq!(
            newly_assigned.len(),
            *published,
            "{engines}: the newer one accepts {} more code points, but Unicode published {published} new \
             characters between the two: {}",
            newly_assigned.len(),
            newly_assigned.show()
        ),
        None => eprintln!(
            "note: {engines}. The newer one accepts {} more code points. That count is not checked: add the \
             number of characters Unicode published between the two versions to CHARACTERS_ADDED. They are: {}",
            newly_assigned.len(),
            newly_assigned.show()
        ),
    }
    if rust_version > js_version {
        assert_reference_verifiers_accept(&only_js);
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

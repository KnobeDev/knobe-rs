//! The verifier: a port of lens.py `verify()`. It reports two independent
//! dimensions, `state` (integrity) and `conformance` (schema/spec), plus
//! `body_verified` for the optional body hash.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;

use crate::canon::{body_hash, nfc, payload_hash};
use crate::conformance;
use crate::json::{self, ParseError, Parsed, Scan, Value, to_pretty};
use crate::pyfmt::{
    Undecoded, display_py, is_py_space, py_str, py_strip, repr_py, repr_str, safe_str, truthy, type_name,
};
use crate::{SUPPORTED_SPEC_VERSIONS, b64};

pub const BEGIN_MARKER: &str = "-----BEGIN KNOBE B64-----";
pub const END_MARKER: &str = "-----END KNOBE B64-----";

const REQUIRED: &[&str] = &[
    "spec_version",
    "title",
    "summary",
    "content_type",
    "created_date",
    "license",
    "privacy_level",
    "quarantine_status",
    "attribution",
    "payload_hash",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Verified,
    VerifiedBodyModified,
    Failed,
    Unreadable,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Verified => "verified",
            State::VerifiedBodyModified => "verified-body-modified",
            State::Failed => "failed",
            State::Unreadable => "unreadable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conformance {
    Valid,
    Warnings,
    Invalid,
}

impl Conformance {
    pub fn as_str(self) -> &'static str {
        match self {
            Conformance::Valid => "valid",
            Conformance::Warnings => "warnings",
            Conformance::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyVerified {
    Yes,
    Modified,
    Omitted,
}

impl BodyVerified {
    pub fn as_str(self) -> &'static str {
        match self {
            BodyVerified::Yes => "yes",
            BodyVerified::Modified => "modified",
            BodyVerified::Omitted => "omitted",
        }
    }
}

/// A verification report with lens.py's keys and semantics.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub state: State,
    /// Recomputed payload hash; None when unreadable.
    pub computed: Option<String>,
    /// The stored `payload_hash` value as found (any JSON type; "" if absent); None when unreadable.
    pub stored: Option<Value>,
    pub payload: Option<Value>,
    pub missing: Vec<String>,
    /// None when unreadable.
    pub body_verified: Option<BodyVerified>,
    pub conformance: Conformance,
    pub conformance_issues: Vec<String>,
    pub block_count: usize,
    /// Why the file is unreadable; None otherwise.
    pub reason: Option<String>,
}

impl Report {
    /// An `unreadable` report, as lens.py's `_unreadable` builds it.
    pub fn unreadable(reason: String, block_count: usize, payload: Option<Value>) -> Report {
        Report {
            state: State::Unreadable,
            computed: None,
            stored: None,
            payload,
            missing: Vec::new(),
            body_verified: None,
            conformance: Conformance::Invalid,
            conformance_issues: vec![reason.clone()],
            block_count,
            reason: Some(reason),
        }
    }

    pub fn multiple_blocks(&self) -> bool {
        self.block_count > 1
    }

    /// The block evaluated: always the last one (spec §3.3).
    pub fn block_used(&self) -> usize {
        self.block_count
    }

    /// 0 = integrity OK and conformance valid/warnings; 1 = failed or
    /// invalid; 2 = unreadable.
    pub fn exit_code(&self) -> i32 {
        match (self.state, self.conformance) {
            (State::Unreadable, _) => 2,
            (State::Verified | State::VerifiedBodyModified, Conformance::Valid | Conformance::Warnings) => 0,
            _ => 1,
        }
    }

    /// The `lens.py --json` document.
    pub fn to_json(&self) -> String {
        let s = |x: &str| Value::Str(x.to_string());
        let opt = |x: Option<&str>| x.map_or(Value::Null, s);
        let doc = Value::Object(vec![
            ("state".into(), s(self.state.as_str())),
            ("computed".into(), opt(self.computed.as_deref())),
            ("stored".into(), self.stored.clone().unwrap_or(Value::Null)),
            ("body_verified".into(), opt(self.body_verified.map(BodyVerified::as_str))),
            ("conformance".into(), s(self.conformance.as_str())),
            ("conformance_issues".into(), Value::Array(self.conformance_issues.iter().map(|i| s(i)).collect())),
            ("multiple_blocks".into(), Value::Bool(self.multiple_blocks())),
            ("block_count".into(), Value::Int(self.block_count.to_string())),
            ("block_used".into(), Value::Int(self.block_used().to_string())),
            ("reason".into(), opt(self.reason.as_deref())),
        ]);
        to_pretty(&doc)
    }
}

/// Frontmatter facts the conformance check needs.
#[derive(Debug, Clone, PartialEq)]
pub struct Frontmatter {
    pub ok: bool,
    pub spec: Option<String>,
    pub reason: &'static str,
}

pub fn verify_path(path: &Path) -> Report {
    match std::fs::read(path) {
        Ok(bytes) => verify_bytes(&bytes),
        Err(e) => Report::unreadable(read_error(path, &e), 0, None),
    }
}

/// lens.py's reason for a file it cannot read. Python holds the path as it
/// decodes a command-line argument, so bytes that are not UTF-8 show as
/// `\udcXX`, through safe() or, in an OSError's text, repr().
fn read_error(path: &Path, e: &std::io::Error) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let shown = || safe_str(&display_py(bytes, Undecoded::SurrogateEscape), usize::MAX);
    match (e.kind(), e.raw_os_error()) {
        (std::io::ErrorKind::NotFound, _) => format!("file not found: {}", shown()),
        (std::io::ErrorKind::IsADirectory, _) => format!("path is a directory, not a file: {}", shown()),
        // Python's str(OSError) is "[Errno N] <strerror>: <repr(path)>"; Rust's
        // text is the same strerror with " (os error N)" after it.
        (_, Some(code)) => {
            let text = e.to_string();
            let strerror = text.strip_suffix(&format!(" (os error {code})")).unwrap_or(&text);
            format!("could not read file: [Errno {code}] {strerror}: {}", repr_py(bytes, Undecoded::SurrogateEscape))
        }
        (_, None) => format!("could not read file: {e}"),
    }
}

pub fn verify_bytes(bytes: &[u8]) -> Report {
    match std::str::from_utf8(bytes) {
        Ok(raw) => verify_str(raw),
        Err(e) => Report::unreadable(format!("file is not valid UTF-8: {}", utf8_error_text(bytes, &e)), 0, None),
    }
}

/// CPython's `UnicodeDecodeError` text for the first invalid UTF-8 sequence,
/// which lens.py quotes, e.g. "'utf-8' codec can't decode byte 0xc3 in
/// position 39: invalid continuation byte". CPython's span is Rust's
/// `error_len`, or the rest of the input when a sequence is cut short.
fn utf8_error_text(bytes: &[u8], e: &std::str::Utf8Error) -> String {
    let start = e.valid_up_to();
    let (len, why) = match e.error_len() {
        None => (bytes.len() - start, "unexpected end of data"),
        // A lead byte, followed by a byte that cannot continue it.
        Some(n) if (0xc2..=0xf4).contains(&bytes[start]) => (n, "invalid continuation byte"),
        Some(n) => (n, "invalid start byte"),
    };
    if len == 1 {
        format!("'utf-8' codec can't decode byte 0x{:02x} in position {start}: {why}", bytes[start])
    } else {
        format!("'utf-8' codec can't decode bytes in position {start}-{}: {why}", start + len - 1)
    }
}

pub fn verify_str(raw: &str) -> Report {
    let blocks = find_blocks(raw);
    let n = blocks.len();
    let Some(last) = blocks.last() else {
        return Report::unreadable("no payload block found".into(), 0, None);
    };
    let payload = match decode_payload(last).and_then(admit) {
        Ok(p) => p,
        Err(Rejection { reason, payload, issue, no_blocks }) => {
            let mut r = Report::unreadable(reason, if no_blocks { 0 } else { n }, payload);
            if let Some(issue) = issue {
                r.conformance_issues = vec![issue];
            }
            return r;
        }
    };

    // Canonical hash (spec §5). The parser already rejects a float that
    // overflows to inf (anywhere, payload_hash included), so this cannot fail
    // for parsed input; a value with no canonical form is never hashed.
    let Ok(computed) = payload_hash(&payload) else {
        let reason = "payload contains a number that cannot be canonicalized (overflows to infinity); rejected";
        return Report::unreadable(reason.into(), n, Some(payload));
    };
    let stored = payload.get("payload_hash").cloned().unwrap_or(Value::Str(String::new()));
    let missing = missing_fields(&payload);
    let mut state = if stored.as_str() == Some(computed.as_str()) { State::Verified } else { State::Failed };
    let fm = parse_frontmatter(raw);

    // body_verified is omitted for multiple blocks (ambiguous extraction), no
    // body_hash, or a payload that did not verify (untrusted).
    let mut body_verified = BodyVerified::Omitted;
    if state == State::Verified && payload.contains_key("body_hash") && n == 1 {
        let Some(matches) = body_matches(raw, &payload) else {
            let reason = "body_hash present but YAML frontmatter delimiters not found";
            return Report::unreadable(reason.into(), n, Some(payload));
        };
        if matches {
            body_verified = BodyVerified::Yes;
        } else {
            body_verified = BodyVerified::Modified;
            state = State::VerifiedBodyModified;
        }
    }

    let (conformance, conformance_issues) = conformance::check(&payload, &missing, &fm, n);
    Report {
        state,
        computed: Some(computed),
        stored: Some(stored),
        payload: Some(payload),
        missing,
        body_verified: Some(body_verified),
        conformance,
        conformance_issues,
        block_count: n,
        reason: None,
    }
}

/// Why a payload makes the file unreadable.
struct Rejection {
    reason: String,
    /// Payload to keep on the report (lens.py keeps it for some rejections).
    payload: Option<Value>,
    /// Replacement conformance issue, when it differs from the reason.
    issue: Option<String>,
    /// Report a block count of 0, as lens.py does when `verify()` raises and
    /// its command line builds the report without the blocks.
    no_blocks: bool,
}

impl Rejection {
    fn new(reason: String) -> Self {
        Rejection { reason, payload: None, issue: None, no_blocks: false }
    }
}

const LONE_SURROGATE: &str =
    "payload contains characters that cannot be UTF-8 encoded (e.g. an unpaired surrogate); rejected";

/// Decode and parse the last block, rejecting ambiguous or illegal JSON.
fn decode_payload(block: &str) -> Result<Parsed, Rejection> {
    let Some(text) = b64::decode_block(block).and_then(|bytes| String::from_utf8(bytes).ok()) else {
        return Err(Rejection::new("payload could not be decoded or parsed".into()));
    };
    json::parse_payload(&text).map_err(|e| {
        Rejection::new(match e {
            ParseError::DuplicateKey(k) => {
                format!("payload contains duplicate JSON key: {} (ambiguous; rejected)", safe_str(&k, 300))
            }
            ParseError::NonJsonConstant => {
                "payload contains a non-JSON numeric constant (NaN/Infinity); rejected".into()
            }
            ParseError::LoneSurrogate => LONE_SURROGATE.into(),
            ParseError::Syntax { .. } => "payload could not be decoded or parsed".into(),
        })
    })
}

/// The structural gates before hashing, in lens.py's order: a JSON object,
/// no unpaired surrogate (within the nesting lens.py can walk), no NFC key
/// collisions, and a spec_version this verifier implements.
fn admit(Parsed { value: payload, scan }: Parsed) -> Result<Value, Rejection> {
    if !matches!(payload, Value::Object(_)) {
        return Err(Rejection::new(format!("payload is not a JSON object (got {})", type_name(&payload))));
    }
    match scan {
        Scan::Clean => {}
        Scan::LoneSurrogate => return Err(Rejection::new(LONE_SURROGATE.into())),
        // lens.py's walk raises RecursionError, which its command line reports.
        Scan::TooDeep => {
            let reason = "verifier error (RecursionError); rejected".into();
            return Err(Rejection { no_blocks: true, ..Rejection::new(reason) });
        }
    }
    let collisions = nfc_collisions(&payload, "");
    if !collisions.is_empty() {
        let shown: Vec<_> = collisions.into_iter().take(5).collect();
        return Err(Rejection::new(format!("payload keys collide under NFC normalization: {}", shown.join("; "))));
    }
    // An unsupported spec_version cannot be honestly verified.
    if let Some(sv) = payload.get("spec_version").filter(|v| **v != Value::Null) {
        if !sv.as_str().is_some_and(|s| SUPPORTED_SPEC_VERSIONS.contains(&s)) {
            let shown = safe_str(&py_str(sv), 300); // lens.py: safe(str(sv))
            return Err(Rejection {
                issue: Some(format!("unsupported spec_version: {shown} (this verifier supports ['1.0'])")),
                payload: Some(payload),
                ..Rejection::new(format!("unsupported spec_version: {shown}"))
            });
        }
    }
    Ok(payload)
}

/// Required fields that are absent, plus `attribution.sources` when
/// attribution is present without a truthy sources value.
fn missing_fields(payload: &Value) -> Vec<String> {
    let mut missing: Vec<String> =
        REQUIRED.iter().filter(|f| !payload.contains_key(f)).map(|f| (*f).to_string()).collect();
    if let Some(att) = payload.get("attribution") {
        if !(matches!(att, Value::Object(_)) && att.get("sources").is_some_and(truthy)) {
            missing.push("attribution.sources".into());
        }
    }
    missing
}

/// Whether the body between the frontmatter and the (single) BEGIN marker
/// matches `body_hash`. None if no frontmatter delimiters can be found.
fn body_matches(raw: &str, payload: &Value) -> Option<bool> {
    let marker = format!("\n{BEGIN_MARKER}\n");
    let pre = raw.rfind(&marker).map_or("", |pos| &raw[..pos]);
    let start = find_body_start(pre)?;
    Some(payload.get("body_hash").and_then(Value::as_str) == Some(body_hash(&pre[start..]).as_str()))
}

/// All payload blocks, as lens.py's
/// `re.findall(r'(?:^|\n)-----BEGIN KNOBE B64-----\n(.*?)\n-----END KNOBE B64-----', raw, re.DOTALL)`.
fn find_blocks(raw: &str) -> Vec<&str> {
    let begin = format!("{BEGIN_MARKER}\n");
    let begin_after_newline = format!("\n{begin}");
    let end = format!("\n{END_MARKER}");
    let mut out = Vec::new();
    let mut pos = 0;
    while pos <= raw.len() {
        // Next candidate: BEGIN at the very start of the text, or after a "\n".
        let content_start = if pos == 0 && raw.starts_with(&begin) {
            begin.len()
        } else {
            let Some(nl) = raw[pos..].find(&begin_after_newline) else { break };
            pos + nl + 1 + begin.len()
        };
        // Lazy `(.*?)`: the first END after the content start.
        let Some(rel) = raw[content_start..].find(&end) else { break };
        out.push(&raw[content_start..content_start + rel]);
        pos = content_start + rel + end.len();
    }
    out
}

/// lens.py `parse_frontmatter`: first line exactly '---' (trailing CRs
/// ignored) and a later line exactly '---'; captures the first
/// `spec_version:` value seen before the closing line.
fn parse_frontmatter(raw: &str) -> Frontmatter {
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let mut lines = raw.split('\n').map(|l| l.trim_end_matches('\r'));
    if lines.next() != Some("---") {
        return Frontmatter { ok: false, spec: None, reason: "missing opening '---' frontmatter delimiter" };
    }
    let mut spec = None;
    for line in lines {
        if line == "---" {
            return Frontmatter { ok: true, spec, reason: "" };
        }
        if spec.is_none() {
            spec = spec_version_line(line);
        }
    }
    Frontmatter { ok: false, spec, reason: "missing closing '---' frontmatter delimiter" }
}

/// `re.match(r'\s*spec_version\s*:\s*(.+?)\s*$', line)` then
/// `.strip().strip('"\'')`, with Python's Unicode `\s`.
fn spec_version_line(line: &str) -> Option<String> {
    let rest = line.trim_start_matches(is_py_space).strip_prefix("spec_version")?;
    let rest = rest.trim_start_matches(is_py_space).strip_prefix(':')?;
    if rest.is_empty() {
        return None; // `.+?` needs at least one character
    }
    // An all-whitespace value still matches (the regex backtracks one
    // whitespace char into the group), which strips to "".
    let group = rest.trim_matches(is_py_space);
    Some(py_strip(group).trim_matches(['"', '\'']).to_string())
}

/// Spec §6: the body is "the text immediately following the second line
/// containing exactly --- (the closing delimiter of the YAML frontmatter)",
/// and a verifier that cannot find it before the BEGIN marker MUST report
/// unreadable. The first of those lines is line 1, the opening delimiter
/// (§3.1: the file MUST begin with the frontmatter). If line 1 is anything
/// else there is no frontmatter, so no closing delimiter to find, and a
/// body's `---` horizontal rules are never taken for one. This is the
/// direction the steward agreed for proposed ERRATA E14
/// (KnobeOne/knobe-protocol#22), and lens.py's `_find_body_start`: line 1 is
/// exactly `---` ending in LF or CRLF, with no BOM skipped, and the closing
/// line is the next one that is `---` once trailing CRs are removed.
fn find_body_start(pre: &str) -> Option<usize> {
    let open = ["---\n", "---\r\n"].into_iter().find(|open| pre.starts_with(open))?;
    let mut idx = open.len(); // start of line 2
    loop {
        let nl = pre[idx..].find('\n').map(|r| idx + r);
        let line = &pre[idx..nl.unwrap_or(pre.len())];
        if line.trim_end_matches('\r') == "---" {
            return Some(nl.map_or(pre.len(), |n| n + 1));
        }
        idx = nl? + 1;
    }
}

/// Keys that collapse to the same key under NFC make canonicalization ambiguous.
fn nfc_collisions(v: &Value, path: &str) -> Vec<String> {
    let join = |k: &str| if path.is_empty() { k.to_string() } else { format!("{path}.{k}") };
    let mut out = Vec::new();
    match v {
        Value::Object(o) => {
            // NFC form -> first original key; O(1) lookups keep hostile objects linear.
            let mut seen: HashMap<String, &str> = HashMap::new();
            for (k, _) in o {
                match seen.entry(nfc(k)) {
                    Entry::Occupied(first) => {
                        out.push(format!("{} collides with {} under NFC", repr_str(&join(k)), repr_str(first.get())))
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(k);
                    }
                }
            }
            for (k, item) in o {
                out.extend(nfc_collisions(item, &join(k)));
            }
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                out.extend(nfc_collisions(item, &format!("{path}[{i}]")));
            }
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_blocks_matches_python_findall() {
        let b = |s: &str| find_blocks(s).into_iter().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(b("-----BEGIN KNOBE B64-----\nAA\n-----END KNOBE B64-----"), vec!["AA"]);
        assert_eq!(b("x-----BEGIN KNOBE B64-----\nAA\n-----END KNOBE B64-----"), Vec::<String>::new());
        assert_eq!(
            b(
                "\n-----BEGIN KNOBE B64-----\nA\n-----END KNOBE B64-----\n-----BEGIN KNOBE B64-----\nB\n-----END KNOBE B64-----"
            ),
            vec!["A", "B"]
        );
        assert_eq!(b("\n-----BEGIN KNOBE B64-----\n\n-----END KNOBE B64-----"), vec![""]);
        assert_eq!(b("\n-----BEGIN KNOBE B64-----\nA\n"), Vec::<String>::new());
    }

    #[test]
    fn spec_version_line_follows_the_python_regex() {
        assert_eq!(spec_version_line("spec_version: \"1.0\""), Some("1.0".into()));
        assert_eq!(spec_version_line("  spec_version :'1.0'  "), Some("1.0".into()));
        assert_eq!(spec_version_line("spec_version:   "), Some(String::new()));
        assert_eq!(spec_version_line("spec_version:"), None);
        assert_eq!(spec_version_line("spec_versionx: 1"), None);
    }

    /// A payload whose only defect is `payload_hash` set to `ph` (a JSON lexeme).
    fn with_payload_hash(ph: &str) -> String {
        let payload = format!(
            r#"{{"spec_version":"1.0","title":"T","summary":"S","content_type":"original","created_date":"2026-01-02","license":"CC0-1.0","privacy_level":"public","quarantine_status":"quarantine","attribution":{{"sources":[{{"author":"A"}}]}},"payload_hash":{ph}}}"#
        );
        format!(
            "---\nspec_version: \"1.0\"\n---\n\n{BEGIN_MARKER}\n{}\n{END_MARKER}\n",
            b64::encode(payload.as_bytes())
        )
    }

    #[test]
    fn overflowing_payload_hash_is_unreadable_and_json_stays_valid() {
        // payload_hash is excluded from the canonical form, so an overflow
        // there used to slip past hashing and print `"stored": Infinity`.
        for ph in ["1e400", "-1e400", "1.5E+999", "[1e400]", r#"{"a":1e400}"#] {
            let r = verify_str(&with_payload_hash(ph));
            assert_eq!(r.state, State::Unreadable, "{ph}");
            assert_eq!(r.exit_code(), 2, "{ph}");
            assert_eq!(
                r.reason.as_deref(),
                Some("payload contains a non-JSON numeric constant (NaN/Infinity); rejected"),
                "{ph}"
            );
            let doc = json::parse(&r.to_json()).unwrap_or_else(|e| panic!("{ph}: --json is not JSON ({e})"));
            assert_eq!(doc.get("stored"), Some(&Value::Null), "{ph}");
        }
        // Control: the same file with a finite number is merely failed.
        let r = verify_str(&with_payload_hash("5"));
        assert_eq!((r.state, r.exit_code()), (State::Failed, 1));
    }

    #[test]
    fn utf8_errors_read_as_cpython_reports_them() {
        // Expected texts produced by CPython 3.13 bytes.decode("utf-8").
        let text = |b: &[u8]| verify_bytes(b).reason.unwrap();
        let cases: &[(&[u8], &str)] = &[
            (b"ab\xc3(", "byte 0xc3 in position 2: invalid continuation byte"),
            (b"\xff", "byte 0xff in position 0: invalid start byte"),
            (b"\x80x", "byte 0x80 in position 0: invalid start byte"),
            (b"\xc0\xaf", "byte 0xc0 in position 0: invalid start byte"),
            (b"\xed\xa0\x80", "byte 0xed in position 0: invalid continuation byte"),
            (b"\xe0\x80\x80", "byte 0xe0 in position 0: invalid continuation byte"),
            (b"\xe2\x82(", "bytes in position 0-1: invalid continuation byte"),
            (b"x\xf0\x9f\x98(", "bytes in position 1-3: invalid continuation byte"),
            (b"\xc3", "byte 0xc3 in position 0: unexpected end of data"),
            (b"\xf0\x9f\x98", "bytes in position 0-2: unexpected end of data"),
        ];
        for (bytes, want) in cases {
            assert_eq!(text(bytes), format!("file is not valid UTF-8: 'utf-8' codec can't decode {want}"));
        }
    }

    /// A file with `payload` as its block, sealed or not.
    fn with_payload(payload: &str) -> String {
        format!(
            "---\nspec_version: \"1.0\"\n---\n\n{BEGIN_MARKER}\n{}\n{END_MARKER}\n",
            b64::encode(payload.as_bytes())
        )
    }

    #[test]
    fn checks_payloads_in_lens_py_order() {
        let reason = |payload: &str| verify_str(&with_payload(payload)).reason.unwrap_or_default();
        const SURROGATE: &str = LONE_SURROGATE;
        // Object check, then surrogates, then NFC collisions, then spec_version.
        assert_eq!(reason(r#""\ud800""#), "payload is not a JSON object (got str)");
        assert_eq!(reason(r#"{"spec_version":"2.0","a":"\ud800"}"#), SURROGATE);
        assert_eq!(reason("{\"caf\u{e9}\":1,\"cafe\u{301}\":2,\"a\":\"\\udc00\"}"), SURROGATE);
        // A parse error anywhere comes before both.
        assert_eq!(reason(r#"{"a":"\ud800","a":1}"#), "payload contains duplicate JSON key: a (ambiguous; rejected)");
        assert_eq!(reason(r#"{"a":"\ud800",}"#), "payload could not be decoded or parsed");
    }

    #[test]
    fn a_non_string_spec_version_is_shown_as_python_str() {
        let reason = |sv: &str| verify_str(&with_payload(&format!(r#"{{"spec_version":{sv}}}"#))).reason.unwrap();
        assert_eq!(reason(r#"["1.0"]"#), "unsupported spec_version: ['1.0']");
        assert_eq!(reason("true"), "unsupported spec_version: True");
        assert_eq!(reason(r#"{"v":1.0}"#), "unsupported spec_version: {'v': 1.0}");
        let long = reason(&format!("[{}]", vec!["\"xxxxxxxx\""; 40].join(",")));
        assert_eq!(long.chars().count(), "unsupported spec_version: ".len() + 300 + 1);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn a_duplicate_key_with_an_unpaired_surrogate_is_reported() {
        // The surrogate shows as \udXXX, as the patched lens.py's safe() shows
        // it (unpatched lens.py crashes printing the key).
        let r = verify_str(&with_payload(r#"{"\ud800":"1","x\u001b\udfff\u202e":"2","\ud800":"3"}"#));
        assert_eq!(r.reason.as_deref(), Some(r"payload contains duplicate JSON key: \ud800 (ambiguous; rejected)"));
        let r = verify_str(&with_payload(r#"{"x\u001b\udfff\u202e":"1","x\u001b\udfff\u202e":"2"}"#));
        assert_eq!(
            r.reason.as_deref(),
            Some(r"payload contains duplicate JSON key: x\x1b\udfff\u202e (ambiguous; rejected)")
        );
        assert!(json::parse(&r.to_json()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn read_errors_show_the_path_as_lens_py_does() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("knobe-read-errors-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &[u8]| dir.join(std::ffi::OsStr::from_bytes(name));
        let reason = |p: &Path| verify_path(p).reason.unwrap();
        let d = dir.display();
        assert_eq!(
            reason(&path(b"missing-\xff\x1b\xe2\x80\xae.md")),
            format!(r"file not found: {d}/missing-\udcff\x1b\u202e.md")
        );
        std::fs::create_dir_all(path(b"dir-\xed\xa0\x80")).unwrap();
        assert_eq!(
            reason(&path(b"dir-\xed\xa0\x80")),
            format!(r"path is a directory, not a file: {d}/dir-\udced\udca0\udc80")
        );
        std::fs::write(path(b"file"), "x").unwrap();
        assert_eq!(
            reason(&path(b"file/it's-\xff")),
            format!(r#"could not read file: [Errno 20] Not a directory: "{d}/file/it's-\udcff""#)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn find_body_start_is_line_exact() {
        assert_eq!(find_body_start("---\na: '---x'\n---\nbody"), Some(18));
        assert_eq!(find_body_start("---\nno close"), None);
        assert_eq!(find_body_start("---"), None);
        assert_eq!(find_body_start("---\n---"), Some(7));
        assert_eq!(find_body_start("---\r\nt: x\r\n---\r\nbody"), Some(16));
        // The closing line may end in any number of CRs, as in lens.py.
        assert_eq!(find_body_start("---\nt: x\n---\r\r\nbody"), Some(15));
        // The body starts at the first closing line; later rules are body.
        assert_eq!(find_body_start("---\nt: x\n---\nrule\n---\nmore"), Some(13));
    }

    #[test]
    fn find_body_start_needs_the_opening_delimiter_on_line_1() {
        // Proposed ERRATA E14: with anything else on line 1 there is no
        // frontmatter, so a body's horizontal rules are never delimiters.
        assert_eq!(find_body_start("\n---\nt: x\n---\nbody"), None);
        assert_eq!(find_body_start("Preamble.\n---\nt: x\n---\nbody"), None);
        assert_eq!(find_body_start("intro\n---\nmiddle\n---\nend"), None);
        // lens.py skips no BOM here, and line 1 ends in LF or CRLF only.
        assert_eq!(find_body_start("\u{feff}---\nt: x\n---\nbody"), None);
        assert_eq!(find_body_start("---\r\r\nt: x\n---\nbody"), None);
        assert_eq!(find_body_start(" ---\nt: x\n---\nbody"), None);
    }
}

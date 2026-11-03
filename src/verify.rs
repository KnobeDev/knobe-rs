//! The verifier: a port of lens.py `verify()`. It reports two independent
//! dimensions, `state` (integrity) and `conformance` (schema/spec), plus
//! `body_verified` for the optional body hash.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::path::Path;

use crate::canon::{body_hash, nfc, payload_hash};
use crate::conformance;
use crate::json::{self, ParseError, Value, to_pretty};
use crate::pyfmt::{is_py_space, py_strip, repr_str, safe, safe_str, truthy, type_name};
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
    fn unreadable(reason: String, block_count: usize, payload: Option<Value>) -> Report {
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
        Err(e) => {
            let p = path.display();
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => format!("file not found: {p}"),
                std::io::ErrorKind::IsADirectory => format!("path is a directory, not a file: {p}"),
                _ => format!("could not read file: {e}"),
            };
            Report::unreadable(reason, 0, None)
        }
    }
}

pub fn verify_bytes(bytes: &[u8]) -> Report {
    match std::str::from_utf8(bytes) {
        Ok(raw) => verify_str(raw),
        Err(e) => Report::unreadable(format!("file is not valid UTF-8: {e}"), 0, None),
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
        Err(Rejection { reason, payload, issue }) => {
            let mut r = Report::unreadable(reason, n, payload);
            if let Some(issue) = issue {
                r.conformance_issues = vec![issue];
            }
            return r;
        }
    };

    // Canonical hash (spec §5). A float that overflowed to inf has no
    // canonical form, so the file is unreadable.
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
}

impl Rejection {
    fn new(reason: String) -> Self {
        Rejection { reason, payload: None, issue: None }
    }
}

/// Decode and parse the last block, rejecting ambiguous or illegal JSON.
fn decode_payload(block: &str) -> Result<Value, Rejection> {
    let Some(text) = b64::decode_block(block).and_then(|bytes| String::from_utf8(bytes).ok()) else {
        return Err(Rejection::new("payload could not be decoded or parsed".into()));
    };
    json::parse(&text).map_err(|e| {
        Rejection::new(match e {
            ParseError::DuplicateKey(k) => {
                format!("payload contains duplicate JSON key: {} (ambiguous; rejected)", safe_str(&k, 300))
            }
            ParseError::NonJsonConstant => {
                "payload contains a non-JSON numeric constant (NaN/Infinity); rejected".into()
            }
            ParseError::LoneSurrogate => {
                "payload contains characters that cannot be UTF-8 encoded (e.g. an unpaired surrogate); rejected".into()
            }
            ParseError::Syntax { .. } => "payload could not be decoded or parsed".into(),
        })
    })
}

/// The structural gates before hashing: a JSON object, no NFC key
/// collisions, and a spec_version this verifier implements.
fn admit(payload: Value) -> Result<Value, Rejection> {
    if !matches!(payload, Value::Object(_)) {
        return Err(Rejection::new(format!("payload is not a JSON object (got {})", type_name(&payload))));
    }
    let collisions = nfc_collisions(&payload, "");
    if !collisions.is_empty() {
        let shown: Vec<_> = collisions.into_iter().take(5).collect();
        return Err(Rejection::new(format!("payload keys collide under NFC normalization: {}", shown.join("; "))));
    }
    // An unsupported spec_version cannot be honestly verified.
    if let Some(sv) = payload.get("spec_version").filter(|v| **v != Value::Null) {
        if !sv.as_str().is_some_and(|s| SUPPORTED_SPEC_VERSIONS.contains(&s)) {
            let shown = match sv {
                Value::Str(s) => safe_str(s, 300),
                other => safe(other),
            };
            return Err(Rejection {
                reason: format!("unsupported spec_version: {shown}"),
                issue: Some(format!("unsupported spec_version: {shown} (this verifier supports ['1.0'])")),
                payload: Some(payload),
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
/// containing exactly ---", and a verifier that cannot find two such lines
/// before the BEGIN marker MUST report unreadable. Lines are counted from the
/// start of the file; lens.py instead requires the very first line to be one
/// of them (docs/INTERPRETATIONS.md, I-4). Trailing CRs are line-ending
/// residue, as in lens.py. A line with a BOM or other prefix does not count.
fn find_body_start(pre: &str) -> Option<usize> {
    let mut seen = 0;
    let mut idx = 0;
    loop {
        let nl = pre[idx..].find('\n').map(|r| idx + r);
        let line = &pre[idx..nl.unwrap_or(pre.len())];
        if line.trim_end_matches('\r') == "---" {
            seen += 1;
            if seen == 2 {
                return Some(nl.map_or(pre.len(), |n| n + 1));
            }
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

    #[test]
    fn find_body_start_is_line_exact() {
        assert_eq!(find_body_start("---\na: '---x'\n---\nbody"), Some(18));
        assert_eq!(find_body_start("\u{feff}---\n---\n"), None);
        assert_eq!(find_body_start("---\nno close"), None);
        // §6 counts '---' lines from the start; the first need not be line 1.
        assert_eq!(find_body_start("\n---\nt: x\n---\nbody"), Some(14));
        assert_eq!(find_body_start("---\r\nt: x\r\n---\r\nbody"), Some(16));
    }
}

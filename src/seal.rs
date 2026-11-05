//! The sealer: a port of knobe-core.js `seal()` / `createKnobe()`. For any
//! input createKnobe accepts and emits a self-consistent file from, the output
//! here is byte-identical. Rather than emit a file that would lose
//! information or not fully verify, this refuses:
//!
//! * integers beyond ±(2^53−1), which a JavaScript number cannot hold exactly,
//! * object keys that collide under NFC,
//! * a line break in any field written to the YAML frontmatter (title,
//!   spec_version, content_type, license, created_date),
//! * any result that is not `verified` with `body_verified: yes` whenever a
//!   body was given.

use std::collections::HashSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::b64;
use crate::canon::{NonFinite, body_hash, canonical, nfc, sha256_hex};
use crate::json::Value;
use crate::pyfmt::{float_repr, int_repr, is_js_space};
use crate::verify::{BEGIN_MARKER, BodyVerified, Conformance, END_MARKER, Report, State, verify_str};

#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Payload fields (a JSON object). Defaults fill anything missing or null.
    pub fields: Value,
    /// Markdown body; when non-empty, `body_hash` is sealed in.
    pub body: String,
    /// Author for the default attribution; "Anonymous" if None.
    pub author: Option<String>,
    /// Default `created_date` (YYYY-MM-DD); today's UTC date if None.
    pub today: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Created {
    pub text: String,
    pub payload: Value,
    pub payload_hash: String,
    /// Self-verification of `text`.
    pub report: Report,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SealError {
    FieldsNotObject,
    UnsafeInteger(String),
    NonFiniteNumber,
    NfcKeyCollision(String),
    NotAString(&'static str),
    LineBreakInFrontmatter(&'static str),
    SelfCheckFailed { state: &'static str, body: Option<&'static str>, conformance: &'static str, issues: Vec<String> },
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::FieldsNotObject => write!(f, "fields must be a JSON object"),
            SealError::UnsafeInteger(n) => write!(
                f,
                "integer {n} is beyond ±(2^53−1) and would lose digits; write it as a string (spec §5 wants strings anyway)"
            ),
            SealError::NonFiniteNumber => write!(f, "a number overflows to infinity and cannot be sealed"),
            SealError::NfcKeyCollision(k) => {
                write!(f, "two keys collapse to {k:?} under NFC normalization; rename one")
            }
            SealError::NotAString(field) => write!(f, "{field} must be a string"),
            SealError::LineBreakInFrontmatter(field) => {
                write!(f, "{field} is written to the YAML frontmatter and must not contain a line break")
            }
            SealError::SelfCheckFailed { state, body, conformance, issues } => write!(
                f,
                "self-check failed: {state}/{}/{conformance}{}{}",
                body.unwrap_or("-"),
                if issues.is_empty() { "" } else { " — " },
                issues.join("; ")
            ),
        }
    }
}

impl std::error::Error for SealError {}

impl From<NonFinite> for SealError {
    fn from(_: NonFinite) -> Self {
        SealError::NonFiniteNumber
    }
}

const MAX_SAFE_INTEGER: i128 = (1 << 53) - 1;

/// JS `pyNumberRepr(Number(x))` for a value that came through JSON.parse:
/// integral and |x| < 1e16 prints as an integer, otherwise Python float repr.
fn js_number_string(v: &Value) -> Result<String, SealError> {
    match v {
        Value::Int(l) => match l.parse::<i128>() {
            Ok(n) if n.abs() <= MAX_SAFE_INTEGER => Ok(int_repr(l).to_string()),
            _ => Err(SealError::UnsafeInteger(l.clone())),
        },
        Value::Float(x) if x.fract() == 0.0 && x.abs() < 1e16 => Ok(format!("{}", *x as i64)),
        Value::Float(x) => float_repr(*x).ok_or(SealError::NonFiniteNumber),
        _ => unreachable!("only called on numbers"),
    }
}

/// knobe-core.js `normalizePayloadForAuthoring`: NFC keys and strings,
/// numbers to strings (spec §5).
fn normalize_for_authoring(v: &Value) -> Result<Value, SealError> {
    Ok(match v {
        Value::Str(s) => Value::Str(nfc(s)),
        Value::Int(_) | Value::Float(_) => Value::Str(js_number_string(v)?),
        Value::Array(a) => Value::Array(a.iter().map(normalize_for_authoring).collect::<Result<_, _>>()?),
        Value::Object(o) => {
            let mut out: Vec<(String, Value)> = Vec::with_capacity(o.len());
            let mut seen: HashSet<String> = HashSet::with_capacity(o.len());
            for (k, item) in o {
                let nk = nfc(k);
                if !seen.insert(nk.clone()) {
                    return Err(SealError::NfcKeyCollision(nk));
                }
                out.push((nk, normalize_for_authoring(item)?));
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

/// Seal a payload: normalize for authoring, drop any stale payload_hash,
/// compute the §5 hash, and return the payload carrying it plus the hash.
pub fn seal(payload: &Value) -> Result<(Value, String), SealError> {
    let Value::Object(mut obj) = normalize_for_authoring(payload)? else {
        return Err(SealError::FieldsNotObject);
    };
    obj.retain(|(k, _)| k != "payload_hash");
    let hash = sha256_hex(canonical(&Value::Object(obj.clone()))?.as_bytes());
    obj.push(("payload_hash".into(), Value::Str(hash.clone())));
    Ok((Value::Object(obj), hash))
}

/// Fields createKnobe sets itself; copied from `fields` only via the defaults.
const MANAGED: &[&str] = &[
    "title",
    "summary",
    "content_type",
    "created_date",
    "license",
    "privacy_level",
    "quarantine_status",
    "identity_status",
    "attribution",
    "payload_hash",
    "body_hash",
];

/// Create a complete `.knobe.md` file (knobe-core.js `createKnobe`).
pub fn create_knobe(opts: &CreateOptions) -> Result<Created, SealError> {
    let Value::Object(fields) = &opts.fields else { return Err(SealError::FieldsNotObject) };
    let given = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v).filter(|v| **v != Value::Null);
    let or = |k: &str, default: &str| given(k).cloned().unwrap_or_else(|| Value::Str(default.into()));
    let today = opts.today.clone().unwrap_or_else(utc_today);
    let default_attribution = Value::Object(vec![(
        "sources".into(),
        Value::Array(vec![Value::Object(vec![
            ("author".into(), Value::Str(opts.author.clone().unwrap_or_else(|| "Anonymous".into()))),
            ("contribution".into(), Value::Str("author".into())),
        ])]),
    )]);

    let mut payload: Vec<(String, Value)> = vec![
        ("spec_version".into(), Value::Str("1.0".into())),
        ("title".into(), or("title", "Untitled KNOBE")),
        ("summary".into(), or("summary", "")),
        ("content_type".into(), or("content_type", "original")),
        ("created_date".into(), or("created_date", &today)),
        ("license".into(), or("license", "CC BY 4.0")),
        ("privacy_level".into(), or("privacy_level", "public")),
        ("quarantine_status".into(), or("quarantine_status", "quarantine")),
        ("identity_status".into(), or("identity_status", "declared")),
        ("attribution".into(), given("attribution").cloned().unwrap_or(default_attribution)),
    ];
    // Remaining fields are spread over the defaults, as in JS. Field keys are
    // unique (the parser rejects duplicates) and none is MANAGED, so only
    // spec_version can replace an existing entry.
    for (k, v) in fields.iter().filter(|(k, _)| !MANAGED.contains(&k.as_str())) {
        if k == "spec_version" {
            payload[0].1 = v.clone();
        } else {
            payload.push((k.clone(), v.clone()));
        }
    }
    if !opts.body.is_empty() {
        payload.push(("body_hash".into(), Value::Str(body_hash(&opts.body))));
    }

    let (sealed, payload_hash) = seal(&Value::Object(payload))?;
    let field = |k: &'static str| match sealed.get(k).and_then(Value::as_str) {
        None => Err(SealError::NotAString(k)),
        Some(s) if s.contains(['\n', '\r']) => Err(SealError::LineBreakInFrontmatter(k)),
        Some(s) => Ok(s),
    };
    let frontmatter = [
        "---".to_string(),
        format!("title: {}", yaml_quote(field("title")?)),
        format!("spec_version: {}", yaml_quote(field("spec_version")?)),
        format!("content_type: {}", field("content_type")?),
        format!("license: {}", field("license")?),
        format!("created_date: {}", yaml_quote(field("created_date")?)),
        "---".to_string(),
    ]
    .join("\n");
    let body_section =
        if opts.body.is_empty() { String::new() } else { format!("\n{}\n", opts.body.trim_end_matches(is_js_space)) };
    let text = format!(
        "{frontmatter}\n{body_section}\n{BEGIN_MARKER}\n{}\n{END_MARKER}\n",
        b64::encode_wrapped(canonical(&sealed)?.as_bytes(), 76)
    );

    let report = verify_str(&text);
    let body_ok = opts.body.is_empty() || report.body_verified == Some(BodyVerified::Yes);
    if report.state != State::Verified || report.conformance == Conformance::Invalid || !body_ok {
        return Err(SealError::SelfCheckFailed {
            state: report.state.as_str(),
            body: report.body_verified.map(BodyVerified::as_str),
            conformance: report.conformance.as_str(),
            issues: report.conformance_issues,
        });
    }
    Ok(Created { text, payload: sealed, payload_hash, report })
}

/// knobe-core.js `yamlQuote`: double quotes, escaping only `\` and `"`.
fn yaml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Today's date in UTC as YYYY-MM-DD (JavaScript `toISOString().slice(0, 10)`).
pub fn utc_today() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_759), (2026, 11, 2));
    }

    #[test]
    fn numbers_become_js_strings() {
        let n = |s: &str| js_number_string(&crate::json::parse(s).unwrap());
        assert_eq!(n("3"), Ok("3".into()));
        assert_eq!(n("-0"), Ok("0".into()));
        assert_eq!(n("2.0"), Ok("2".into()));
        assert_eq!(n("-0.0"), Ok("0".into()));
        assert_eq!(n("1e20"), Ok("1e+20".into()));
        assert_eq!(n("1e-7"), Ok("1e-07".into()));
        assert_eq!(n("9007199254740991"), Ok("9007199254740991".into()));
        assert!(n("9007199254740992").is_err());
        // The parser rejects 1e400, but a hand-built Value can still hold inf.
        assert_eq!(js_number_string(&Value::Float(f64::INFINITY)), Err(SealError::NonFiniteNumber));
    }
}

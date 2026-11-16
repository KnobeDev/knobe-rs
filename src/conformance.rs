//! Schema/spec conformance: a port of lens.py `check_conformance`. Errors make
//! a file `invalid`; soft deviations make it `warnings`.

use crate::json::Value;
use crate::pyfmt::{py_strip, repr, repr_str, type_name};
use crate::verify::{Conformance, Frontmatter};

/// Required fields that MUST be JSON strings (spec §4).
const STRING_FIELDS: &[&str] = &[
    "spec_version",
    "title",
    "summary",
    "content_type",
    "created_date",
    "license",
    "privacy_level",
    "quarantine_status",
];

/// Canonical vocabularies (spec §8). Custom values without a namespace warn.
const CANONICAL_VOCAB: &[(&str, &[&str])] = &[
    (
        "content_type",
        &["original", "synthesis", "adaptation", "compression", "annotation", "seed", "collection", "translation"],
    ),
    ("quarantine_status", &["quarantine", "trusted", "rejected"]),
    ("privacy_level", &["public", "internal", "sensitive", "restricted"]),
    ("identity_status", &["declared", "signed"]),
];

/// Spec §4.1/§4.3: "exactly 64 lowercase hexadecimal characters", with
/// nothing following (ERRATA E12; lens.py and knobe-core.js agree).
fn hex64(v: &Value) -> bool {
    let Value::Str(s) = v else { return false };
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `datetime.date.fromisoformat` on a string that already looks like a date:
/// ASCII YYYY-MM-DD, year 1..=9999, a real calendar day.
fn is_real_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = &b[r];
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(part).ok()?.parse().ok()
    };
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else { return false };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y >= 1 && (1..=days).contains(&d)
}

/// Spec §4.1 "ISO 8601 date (YYYY-MM-DD)": ten ASCII characters in that shape.
/// Every shape failure and every impossible date is an error either way; the
/// shape only decides which of the two messages is used.
fn iso_date_shape(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10 && b.iter().enumerate().all(|(i, c)| if i == 4 || i == 7 { *c == b'-' } else { c.is_ascii_digit() })
}

/// Paths of bare numeric values (spec §5 violations), in payload order.
fn numeric_paths(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Int(_) | Value::Float(_) => out.push(path.to_string()),
        Value::Object(o) => {
            for (k, item) in o {
                numeric_paths(item, &if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out);
            }
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                numeric_paths(item, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Run every lens.py conformance rule, in lens.py's order. Errors make the
/// file `invalid`; warnings alone make it `warnings`.
pub fn check(payload: &Value, missing: &[String], fm: &Frontmatter, block_count: usize) -> (Conformance, Vec<String>) {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    check_frontmatter(payload, fm, &mut errors, &mut warnings);
    errors.extend(missing.iter().map(|m| format!("required field missing: {m}")));
    check_types(payload, &mut errors);
    check_formats(payload, &mut errors);
    check_numerics(payload, &mut errors);
    check_parents(payload, &mut errors);
    if block_count > 1 {
        warnings
            .push(format!("multiple payload blocks present ({block_count}); evaluated the last block per spec §3.3"));
    }
    check_vocabulary(payload, &mut warnings);

    if !errors.is_empty() {
        errors.extend(warnings);
        (Conformance::Invalid, errors)
    } else if !warnings.is_empty() {
        (Conformance::Warnings, warnings)
    } else {
        (Conformance::Valid, Vec::new())
    }
}

/// Frontmatter must exist and declare spec_version (§3.1 "At minimum,
/// spec_version MUST appear in the frontmatter"; §10). lens.py checks only
/// that it exists (docs/INTERPRETATIONS.md, I-1); proposed ERRATA E13
/// (KnobeOne/knobe-protocol#22) adds this check to the reference engines.
/// A value that is empty or Python whitespace once its quotes are stripped
/// (`spec_version: "  "`) is not a declaration: it gets this one issue, with
/// no E5 warning on top, as in knobe-go. A declared value that disagrees with
/// the payload is a warning (ERRATA E5).
fn check_frontmatter(payload: &Value, fm: &Frontmatter, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
    if !fm.ok {
        errors.push(format!("YAML frontmatter missing or malformed: {}", fm.reason));
        return;
    }
    match (fm.spec.as_deref().filter(|s| !py_strip(s).is_empty()), payload.get("spec_version")) {
        (None, _) => errors.push("YAML frontmatter does not declare spec_version (spec §3.1)".into()),
        (Some(fs), Some(Value::Str(ps))) if fs != ps => {
            warnings.push(format!(
                "frontmatter spec_version {} does not match sealed payload spec_version {}",
                repr_str(fs),
                repr_str(ps)
            ));
        }
        _ => {}
    }
}

/// Required string fields are strings; attribution is an object whose
/// `sources`, if present, is a non-empty array.
fn check_types(payload: &Value, errors: &mut Vec<String>) {
    for field in STRING_FIELDS {
        if let Some(v) = payload.get(field).filter(|v| !matches!(v, Value::Str(_))) {
            errors.push(format!("required field {field} must be a string, got {}", type_name(v)));
        }
    }
    match payload.get("attribution") {
        None | Some(Value::Null) => {}
        Some(att @ Value::Object(_)) => match att.get("sources") {
            None | Some(Value::Null) => {}
            Some(Value::Array(a)) if a.is_empty() => {
                errors.push("attribution.sources must be a non-empty array".into())
            }
            Some(Value::Array(_)) => {}
            Some(other) => errors.push(format!("attribution.sources must be an array, got {}", type_name(other))),
        },
        Some(other) => errors.push(format!("attribution must be an object, got {}", type_name(other))),
    }
}

/// Hash formats (JSON null counts as absent, as in lens.py) and created_date.
fn check_formats(payload: &Value, errors: &mut Vec<String>) {
    for field in ["payload_hash", "body_hash"] {
        if payload.get(field).is_some_and(|v| *v != Value::Null && !hex64(v)) {
            errors.push(format!("{field} format invalid (must be 64 lowercase hex)"));
        }
    }
    match payload.get("created_date") {
        None | Some(Value::Null) => {}
        Some(Value::Str(s)) if iso_date_shape(s) => {
            if !is_real_iso_date(s) {
                errors.push(format!("created_date is not a real calendar date: {}", repr_str(s)));
            }
        }
        Some(v) => errors.push(format!("created_date is not in YYYY-MM-DD form: {}", repr(v))),
    }
}

/// Bare numerics anywhere except payload_hash itself (spec §5).
fn check_numerics(payload: &Value, errors: &mut Vec<String>) {
    let mut paths = Vec::new();
    if let Value::Object(o) = payload {
        for (k, v) in o.iter().filter(|(k, _)| k != "payload_hash") {
            numeric_paths(v, k, &mut paths);
        }
    }
    if !paths.is_empty() {
        if paths.len() > 5 {
            paths.truncate(5);
            paths.push("...".into());
        }
        errors.push(format!("bare numeric value(s) in payload (spec §5 requires strings): {}", paths.join(", ")));
    }
}

/// parents[i].payload_hash format, when parents is a list.
fn check_parents(payload: &Value, errors: &mut Vec<String>) {
    if let Some(Value::Array(parents)) = payload.get("parents") {
        for (i, p) in parents.iter().enumerate() {
            if p.get("payload_hash").is_some_and(|h| !hex64(h)) {
                errors.push(format!("parents[{i}].payload_hash format invalid (must be 64 lowercase hex)"));
            }
        }
    }
}

/// Custom vocabulary values need an `ext-` or `domain:` prefix (spec §8).
fn check_vocabulary(payload: &Value, warnings: &mut Vec<String>) {
    for (field, canon) in CANONICAL_VOCAB {
        if let Some(Value::Str(v)) = payload.get(field) {
            if !canon.contains(&v.as_str()) && !v.contains(':') && !v.starts_with("ext-") {
                warnings.push(format!(
                    "{field}: {} is a custom vocabulary value without namespace prefix (recommend 'ext-' or 'domain:' per §8)",
                    repr_str(v)
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex64_is_exactly_64_lowercase_hex() {
        let h = "a".repeat(64);
        assert!(hex64(&Value::Str(h.clone())));
        assert!(!hex64(&Value::Str(format!("{h}\n"))));
        assert!(!hex64(&Value::Str("A".repeat(64))));
        assert!(!hex64(&Value::Str("a".repeat(63))));
    }

    #[test]
    fn dates_are_ascii_and_real() {
        assert!(is_real_iso_date("2024-02-29"));
        assert!(!is_real_iso_date("2026-02-29"));
        assert!(!is_real_iso_date("0000-01-01"));
        assert!(!is_real_iso_date("2026-13-01"));
        assert!(iso_date_shape("2026-02-30")); // right shape, impossible date
        assert!(!iso_date_shape("٢٠٢٦-01-01"));
        assert!(!iso_date_shape("2026-01-01\n"));
        assert!(!iso_date_shape("2026-1-01"));
    }
}

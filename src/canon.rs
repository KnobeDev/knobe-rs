//! Spec §5 canonical form and hashes — FROZEN for v1.
//!
//! payload_hash = SHA-256 of: the payload minus `payload_hash`, every object
//! key and string value NFC-normalized, serialized with keys recursively
//! sorted by code point, no whitespace, arrays in order, literal UTF-8
//! (`\uXXXX` only for C0 controls), numbers as Python repr.
//!
//! body_hash = SHA-256 of the body after: Python strip() of the whole body,
//! CRLF and lone CR to LF, only U+0020/U+0009 stripped from each line end, no
//! Unicode normalization.

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::json::{Value, number_repr, write_str};
use crate::pyfmt::py_strip;

pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Recursively NFC-normalize keys and string values.
pub fn nfc_value(v: &Value) -> Value {
    match v {
        Value::Str(s) => Value::Str(nfc(s)),
        Value::Array(a) => Value::Array(a.iter().map(nfc_value).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (nfc(k), nfc_value(v))).collect()),
        other => other.clone(),
    }
}

/// A value that cannot be canonicalized (a float that overflowed to inf).
#[derive(Debug, Clone, PartialEq)]
pub struct NonFinite;

/// Canonical serialization of an already NFC-normalized value. Keys are
/// sorted by UTF-8 bytes, which is code-point order (Python's str order).
pub fn canonical(v: &Value) -> Result<String, NonFinite> {
    let mut out = String::new();
    write_canonical(&mut out, v)?;
    Ok(out)
}

fn write_canonical(out: &mut String, v: &Value) -> Result<(), NonFinite> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(_) | Value::Float(_) => out.push_str(&number_repr(v).ok_or(NonFinite)?),
        Value::Str(s) => write_str(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut entries: Vec<&(String, Value)> = o.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (k, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, k);
                out.push(':');
                write_canonical(out, item)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The §5 payload hash of a payload object (its own payload_hash ignored).
pub fn payload_hash(payload: &Value) -> Result<String, NonFinite> {
    let without = match payload {
        Value::Object(o) => Value::Object(o.iter().filter(|(k, _)| k != "payload_hash").cloned().collect()),
        other => other.clone(),
    };
    Ok(sha256_hex(canonical(&nfc_value(&without))?.as_bytes()))
}

/// Body normalization for body_hash.
pub fn normalize_body(text: &str) -> String {
    let t = py_strip(text).replace("\r\n", "\n").replace('\r', "\n");
    t.split('\n').map(|line| line.trim_end_matches([' ', '\t'])).collect::<Vec<_>>().join("\n")
}

pub fn body_hash(text: &str) -> String {
    sha256_hex(normalize_body(text).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn canonical_sorts_by_code_point_not_utf16() {
        // U+FFFF sorts before U+10000 by code point (UTF-16 order would differ).
        let v = parse("{\"\u{10000}\":\"a\",\"\u{FFFF}\":\"b\",\"b\":\"c\",\"a\":[1.0,-0,true,null]}").unwrap();
        assert_eq!(
            canonical(&v).unwrap(),
            "{\"a\":[1.0,0,true,null],\"b\":\"c\",\"\u{FFFF}\":\"b\",\"\u{10000}\":\"a\"}"
        );
    }

    #[test]
    fn payload_hash_excludes_itself_and_normalizes_nfc() {
        let a = parse("{\"t\":\"Cafe\u{301}\",\"payload_hash\":\"x\"}").unwrap();
        let b = parse("{\"t\":\"Caf\u{e9}\"}").unwrap();
        assert_eq!(payload_hash(&a), payload_hash(&b));
    }

    #[test]
    fn body_normalization_rules() {
        assert_eq!(normalize_body("\u{85} a \t\r\nb\rc  \n"), "a\nb\nc");
        assert_eq!(normalize_body("x\u{a0}\ny"), "x\u{a0}\ny");
    }
}

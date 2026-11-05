//! Strict JSON (RFC 8259) with the protocol's ambiguity rules, applied at any
//! depth: duplicate keys are rejected; NaN/Infinity are rejected, and so is a
//! float that overflows to infinity (e.g. `1e400`, as lens.py since PR #11);
//! lone UTF-16 surrogate escapes are rejected (they cannot be UTF-8
//! canonicalized). Integers keep every digit like Python's int, and objects
//! keep insertion order. A parsed value therefore always has a canonical form.

use std::collections::HashSet;
use std::fmt;

use crate::pyfmt::{float_repr, int_repr};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Integer lexeme exactly as written (arbitrary precision).
    Int(String),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// Insertion-ordered; keys are unique (enforced by the parser).
    Object(Vec<(String, Value)>),
}

/// An empty object.
impl Default for Value {
    fn default() -> Self {
        Value::Object(Vec::new())
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    DuplicateKey(String),
    NonJsonConstant,
    LoneSurrogate,
    Syntax { msg: &'static str, offset: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::DuplicateKey(k) => write!(f, "duplicate JSON key: {k}"),
            ParseError::NonJsonConstant => {
                write!(f, "non-JSON numeric constant (NaN, Infinity, or a number that overflows to infinity)")
            }
            ParseError::LoneSurrogate => write!(f, "unpaired UTF-16 surrogate escape"),
            ParseError::Syntax { msg, offset } => write!(f, "{msg} at byte {offset}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse one JSON document; only JSON whitespace (space, \t, \n, \r) may surround it.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("trailing content"));
    }
    Ok(v)
}

/// Deeply nested input must fail cleanly, not overflow the stack.
const MAX_DEPTH: usize = 512;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError::Syntax { msg, offset: self.i }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn rest(&self) -> &[u8] {
        &self.s[self.i..]
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        let hit = self.rest().starts_with(lit.as_bytes());
        if hit {
            self.i += lit.len();
        }
        hit
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.ws();
        let constant = ["NaN", "Infinity", "-Infinity"].iter().any(|c| self.rest().starts_with(c.as_bytes()));
        if constant {
            return Err(ParseError::NonJsonConstant);
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Str),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) if self.eat("true") => Ok(Value::Bool(true)),
            Some(_) if self.eat("false") => Ok(Value::Bool(false)),
            Some(_) if self.eat("null") => Ok(Value::Null),
            Some(_) => Err(self.err("unexpected token")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut out: Vec<(String, Value)> = Vec::new();
        // O(1) duplicate detection; a linear scan is quadratic on hostile input.
        let mut seen: HashSet<String> = HashSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected string key"));
            }
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(ParseError::DuplicateKey(key));
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            let v = self.value(depth + 1)?;
            out.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self.s.get(self.i..self.i + 4).ok_or_else(|| self.err("invalid \\u escape"))?;
        if !h.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.err("invalid \\u escape"));
        }
        let h = std::str::from_utf8(h).expect("ascii hex");
        self.i += 4;
        Ok(u32::from_str_radix(h, 16).expect("validated hex"))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            // Copy a run of plain characters. We stop only on ASCII bytes, so
            // the slice of the original &str stays valid UTF-8.
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).expect("utf-8 boundary"));
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = self.peek().ok_or_else(|| self.err("unterminated string"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                Some(_) => return Err(self.err("control character in string")),
            }
        }
    }

    /// After `\u`: one BMP scalar, or a high+low surrogate pair. A lone
    /// surrogate is rejected: it cannot be UTF-8 encoded, so it has no canonical form.
    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let hi = self.hex4()?;
        if (0xDC00..0xE000).contains(&hi) {
            return Err(ParseError::LoneSurrogate);
        }
        if !(0xD800..0xDC00).contains(&hi) {
            return Ok(char::from_u32(hi).expect("non-surrogate BMP"));
        }
        if !self.rest().starts_with(b"\\u") {
            return Err(ParseError::LoneSurrogate);
        }
        self.i += 2;
        let lo = self.hex4()?;
        if !(0xDC00..0xE000).contains(&lo) {
            return Err(ParseError::LoneSurrogate);
        }
        Ok(char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)).expect("valid pair"))
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err("invalid number")),
        }
        let mut is_int = true;
        if self.peek() == Some(b'.') {
            is_int = false;
            self.i += 1;
            if self.digits() == 0 {
                return Err(self.err("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_int = false;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return Err(self.err("invalid number"));
            }
        }
        let lexeme = std::str::from_utf8(&self.s[start..self.i]).expect("ascii");
        if is_int {
            Ok(Value::Int(lexeme.to_string()))
        } else {
            // Correctly rounded, like Python float(). An overflow to inf has no
            // canonical form, so it is rejected like Infinity (lens.py
            // `_finite_float`). Underflow to 0.0 is fine.
            let x: f64 = lexeme.parse().expect("validated float lexeme");
            if x.is_infinite() {
                return Err(ParseError::NonJsonConstant);
            }
            Ok(Value::Float(x))
        }
    }
}

/// JSON string literal exactly as Python `json.dumps(..., ensure_ascii=False)`
/// writes it: `"` `\` and C0 controls escaped (short forms for \b\t\n\f\r,
/// lowercase `\u00xx` otherwise); everything else literal UTF-8.
pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A JSON number as Python json.dumps writes it. None for NaN/inf.
pub fn number_repr(v: &Value) -> Option<String> {
    match v {
        Value::Int(l) => Some(int_repr(l).to_string()),
        Value::Float(f) => float_repr(*f),
        _ => None,
    }
}

/// Python `json.dumps(v, indent=2, ensure_ascii=False)`, for --json output.
/// The output is always valid JSON: a non-finite float (which [`parse`] never
/// produces, but a hand-built `Value` can hold) is written as `null`, not as
/// Python's bare `Infinity`/`NaN`.
pub fn to_pretty(v: &Value) -> String {
    let mut out = String::new();
    pretty(&mut out, v, 0);
    out
}

fn pretty(out: &mut String, v: &Value, level: usize) {
    let pad = |n: usize| "  ".repeat(n);
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(_) | Value::Float(_) => out.push_str(&number_repr(v).unwrap_or_else(|| "null".into())),
        Value::Str(s) => write_str(out, s),
        Value::Array(a) if a.is_empty() => out.push_str("[]"),
        Value::Object(o) if o.is_empty() => out.push_str("{}"),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                out.push_str(if i == 0 { "\n" } else { ",\n" });
                out.push_str(&pad(level + 1));
                pretty(out, item, level + 1);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, item)) in o.iter().enumerate() {
                out.push_str(if i == 0 { "\n" } else { ",\n" });
                out.push_str(&pad(level + 1));
                write_str(out, k);
                out.push_str(": ");
                pretty(out, item, level + 1);
            }
            out.push('\n');
            out.push_str(&pad(level));
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_and_illegal_json() {
        assert_eq!(parse(r#"{"a":1,"b":{"c":1,"c":2}}"#), Err(ParseError::DuplicateKey("c".into())));
        assert_eq!(parse("[NaN]"), Err(ParseError::NonJsonConstant));
        assert_eq!(parse("-Infinity"), Err(ParseError::NonJsonConstant));
        assert_eq!(parse(r#""\ud800""#), Err(ParseError::LoneSurrogate));
        assert_eq!(parse(r#""\udc00\ud800""#), Err(ParseError::LoneSurrogate));
        // A float that overflows to inf is rejected like Infinity, at any depth.
        for overflow in ["1e400", "-1e400", "1.5E+999", "[1e400]", r#"{"a":{"b":-1e309}}"#] {
            assert_eq!(parse(overflow), Err(ParseError::NonJsonConstant), "{overflow}");
        }
        assert!(parse("[1,]").is_err());
        assert!(parse("01").is_err());
        assert!(parse("\u{feff}{}").is_err());
        assert!(parse("\"a\u{1}\"").is_err());
        assert!(parse(&"[".repeat(10_000)).is_err());
    }

    #[test]
    fn keeps_big_ints_and_combines_surrogate_pairs() {
        assert_eq!(
            parse("123456789012345678901234567890").unwrap(),
            Value::Int("123456789012345678901234567890".into())
        );
        assert_eq!(parse(r#""😀""#).unwrap(), Value::Str("\u{1F600}".into()));
        // The float range edges stay readable: f64::MAX, and underflow to zero.
        assert_eq!(parse("1.7976931348623157e308").unwrap(), Value::Float(f64::MAX));
        assert_eq!(parse("1e-400").unwrap(), Value::Float(0.0));
        // An overflowing integer lexeme is an Int, not a float, so it stays readable.
        let big = format!("1{}", "0".repeat(400));
        assert_eq!(parse(&big).unwrap(), Value::Int(big));
    }

    #[test]
    fn to_pretty_never_writes_bare_infinity() {
        let v = Value::Object(vec![
            ("a".into(), Value::Float(f64::INFINITY)),
            ("b".into(), Value::Float(f64::NEG_INFINITY)),
            ("c".into(), Value::Float(f64::NAN)),
            ("d".into(), Value::Float(1.5)),
        ]);
        let out = to_pretty(&v);
        assert_eq!(out, "{\n  \"a\": null,\n  \"b\": null,\n  \"c\": null,\n  \"d\": 1.5\n}");
        assert!(parse(&out).is_ok());
    }

    #[test]
    fn write_str_matches_python_escaping() {
        let mut s = String::new();
        write_str(&mut s, "\"\\\u{0}\u{1f}\u{8}\u{c}\n\r\t\u{7f}\u{2028}é😀");
        assert_eq!(s, "\"\\\"\\\\\\u0000\\u001f\\b\\f\\n\\r\\t\u{7f}\u{2028}é😀\"");
    }
}

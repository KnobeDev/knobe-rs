//! Strict JSON (RFC 8259) as lens.py reads a payload: Python's `json.loads`
//! with lens.py's hooks. Duplicate keys at any depth are rejected (when their
//! object closes, as `object_pairs_hook` sees them), and so are NaN/Infinity
//! and a float that overflows to infinity (e.g. `1e400`, as lens.py since
//! PR #11). Integers keep every digit like Python's int, up to its 4300-digit
//! limit, and objects keep insertion order.
//!
//! An unpaired UTF-16 surrogate escape parses, as in Python, but has no UTF-8
//! form. [`parse_payload`] reports it, and nesting too deep for lens.py to
//! walk, in the order lens.py's lone-surrogate walk meets them ([`Scan`]).
//! [`parse`] rejects it, and nesting deeper than 512 levels, as 0.1.1 did.

use std::collections::HashSet;
use std::fmt;

use crate::pyfmt::{Piece, Undecoded, decode_py, display_py, float_repr, int_repr};

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

/// How deep an array may nest below the top-level value (level 0), as in
/// CPython 3.13's `json.loads`: one level deeper exhausts its C recursion
/// limit, which lens.py reports as "payload could not be decoded or parsed".
/// The parser keeps its own stack, so this costs heap, not call stack.
pub const MAX_DEPTH: usize = 9997;

/// How deep a node may be when `json.loads` must call one of lens.py's Python
/// hooks for it: an object (`object_pairs_hook`), a float (`parse_float`) or
/// NaN/Infinity (`parse_constant`). The call takes two more levels of the C
/// recursion limit, so such a node deeper than this cannot be parsed either.
/// Integers, strings and literals need no hook. An object's hook runs a level
/// deeper than the others, inside the object, so when it raises (a duplicate
/// key) it fails at this level already: such an object must sit above it.
pub const MAX_HOOK_LEVEL: usize = 9995;

/// The deepest level (the payload is level 0) at which lens.py's
/// `_has_lone_surrogate` can reach a value or key. It recurses through a
/// generator, two CPython frames per level, so a value or key one level
/// deeper exhausts Python's default recursion limit of 1000.
pub const MAX_SCAN_LEVEL: usize = 498;

/// How deep [`parse`] lets a document nest, as in 0.1.1.
const PARSE_MAX_DEPTH: usize = 512;

/// CPython's default `int` max_str_digits: `json.loads` refuses an integer
/// literal with more digits (the sign does not count).
const MAX_INT_DIGITS: usize = 4300;

/// What lens.py's `_has_lone_surrogate` walk meets first, depth first in
/// document order with each key before its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// Neither of the others: the walk completes.
    Clean,
    /// A key or string holding an unpaired surrogate.
    LoneSurrogate,
    /// A value or key nested deeper than [`MAX_SCAN_LEVEL`], where the walk
    /// raises RecursionError.
    TooDeep,
}

/// A parsed document, with what lens.py's lone-surrogate walk finds in it.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    /// Complete only when `scan` is [`Scan::Clean`]. Otherwise each unpaired
    /// surrogate reads as U+FFFD, and nothing nested deeper than
    /// [`MAX_SCAN_LEVEL`] is kept.
    pub value: Value,
    pub scan: Scan,
}

/// Parse one JSON document as lens.py's `json.loads` does, errors in the
/// order Python raises them; only JSON whitespace (space, \t, \n, \r) may
/// surround it. Unpaired surrogates and nesting deeper than lens.py can walk
/// are not errors here but are reported in [`Parsed::scan`], because lens.py
/// checks them only once the payload has parsed and proved to be an object.
pub fn parse_payload(text: &str) -> Result<Parsed, ParseError> {
    let (value, scan) = parse_document(text, Mode::Payload)?;
    Ok(Parsed { value, scan: scan.unwrap_or(Scan::Clean) })
}

/// Parse one JSON document whole, rejecting an unpaired surrogate (it has no
/// UTF-8 form) and nesting deeper than 512 levels, as 0.1.1 did. lens.py
/// verifies only payloads up to [`MAX_SCAN_LEVEL`] deep; [`parse_payload`]
/// reports deeper ones.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    parse_document(text, Mode::Strict).map(|(value, _)| value)
}

/// The value, and what the lone-surrogate walk stops at first.
fn parse_document(text: &str, mode: Mode) -> Result<(Value, Option<Scan>), ParseError> {
    let mut p = Parser { s: text.as_bytes(), i: 0, mode, scan: None };
    let value = p.document()?;
    p.ws();
    if p.i != p.s.len() {
        return Err(p.err("trailing content"));
    }
    Ok((value, p.scan))
}

/// What a parse is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A payload, as lens.py's `json.loads` reads it: unpaired surrogates and
    /// nesting beyond [`MAX_SCAN_LEVEL`] are left to the scan, and nothing
    /// deeper than the scan reaches is kept.
    Payload,
    /// A whole document for [`parse`]: nesting up to [`PARSE_MAX_DEPTH`], and
    /// an unpaired surrogate is an error where it occurs.
    Strict,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    mode: Mode,
    /// The first thing lens.py's lone-surrogate walk stops at.
    scan: Option<Scan>,
}

/// A container whose closing bracket is still to come.
enum Open {
    Array(Vec<Value>),
    Object {
        members: Vec<(String, Value)>,
        /// Keys so far, as WTF-8, so unpaired surrogates compare as Python
        /// compares them. A set keeps hostile objects linear.
        seen: HashSet<Vec<u8>>,
        /// The first repeated key. Python's `object_pairs_hook` sees the object
        /// only once it is complete, so an error later in it is raised first.
        dup: Option<Vec<u8>>,
        /// The key whose value is being parsed.
        key: String,
    },
}

impl Parser<'_> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError::Syntax { msg, offset: self.i }
    }

    /// Record what the lone-surrogate walk meets here, unless it stopped earlier.
    fn note(&mut self, scan: Scan) {
        self.scan.get_or_insert(scan);
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

    /// The top-level value. Containers are tracked on an explicit stack, so
    /// hostile nesting cannot overflow the call stack. A value's level is the
    /// number of containers open around it.
    fn document(&mut self) -> Result<Value, ParseError> {
        let mut stack: Vec<Open> = Vec::new();
        loop {
            let Some(v) = self.start_value(&mut stack)? else { continue };
            if let Some(done) = self.finish_value(&mut stack, v)? {
                return Ok(done);
            }
        }
    }

    /// The start of the next value, at level `stack.len()`. A scalar or an
    /// empty container is complete at once; a container with members is
    /// pushed (None), and its first member is parsed next.
    fn start_value(&mut self, stack: &mut Vec<Open>) -> Result<Option<Value>, ParseError> {
        let level = stack.len();
        self.ws();
        if self.mode == Mode::Strict && level > PARSE_MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        if level > MAX_SCAN_LEVEL {
            self.note(Scan::TooDeep);
        }
        match self.peek() {
            Some(b'[') if level > MAX_DEPTH => Err(self.err("nesting too deep")),
            Some(b'{') if level > MAX_HOOK_LEVEL => Err(self.err("nesting too deep")),
            Some(b'{') => {
                self.i += 1;
                self.ws();
                if self.eat("}") {
                    return Ok(Some(Value::Object(Vec::new())));
                }
                let raw = self.key(level + 1)?;
                let key = self.text(raw.clone())?;
                stack.push(Open::Object { members: Vec::new(), seen: HashSet::from([raw]), dup: None, key });
                Ok(None)
            }
            Some(b'[') => {
                self.i += 1;
                self.ws();
                if self.eat("]") {
                    return Ok(Some(Value::Array(Vec::new())));
                }
                stack.push(Open::Array(Vec::new()));
                Ok(None)
            }
            _ => self.scalar(level).map(Some),
        }
    }

    /// Add the complete value `v` to its container. If that container closes
    /// here, it is the next value to add, and so on outwards. Returns the
    /// top-level value once it is complete, or None when another member
    /// follows.
    fn finish_value(&mut self, stack: &mut Vec<Open>, mut v: Value) -> Result<Option<Value>, ParseError> {
        loop {
            let level = stack.len();
            let Some(open) = stack.last_mut() else { return Ok(Some(v)) };
            // Nothing lens.py cannot walk is kept: the scan already rejects
            // it, and a shallow value is cheap to drop.
            let keep = self.mode == Mode::Strict || level <= MAX_SCAN_LEVEL;
            self.ws();
            let more = match open {
                Open::Array(items) => {
                    if keep {
                        items.push(v);
                    }
                    self.separator(b']')?
                }
                Open::Object { members, seen, dup, key } => {
                    let k = std::mem::take(key);
                    if keep {
                        members.push((k, v));
                    }
                    let more = self.separator(b'}')?;
                    if more {
                        let raw = self.key(level)?;
                        *key = self.text(raw.clone())?;
                        if !seen.insert(raw.clone()) && dup.is_none() {
                            *dup = Some(raw);
                        }
                    }
                    more
                }
            };
            if more {
                return Ok(None);
            }
            v = match stack.pop() {
                Some(Open::Array(items)) => Value::Array(items),
                Some(Open::Object { dup: Some(_), .. }) if level > MAX_HOOK_LEVEL => {
                    return Err(self.err("nesting too deep"));
                }
                Some(Open::Object { dup: Some(k), .. }) => {
                    return Err(ParseError::DuplicateKey(display_py(&k, Undecoded::Wtf8)));
                }
                Some(Open::Object { members, .. }) => Value::Object(members),
                None => unreachable!("a container was open"),
            };
        }
    }

    /// After a member: true, past the ',', if another follows; false, past
    /// `close`, if the container ends here.
    fn separator(&mut self, close: u8) -> Result<bool, ParseError> {
        match self.peek() {
            Some(b',') => {
                self.i += 1;
                Ok(true)
            }
            Some(c) if c == close => {
                self.i += 1;
                Ok(false)
            }
            _ => Err(self.err(if close == b']' { "expected ',' or ']'" } else { "expected ',' or '}'" })),
        }
    }

    /// An object key at `level`, as WTF-8, and the ':' after it.
    fn key(&mut self, level: usize) -> Result<Vec<u8>, ParseError> {
        self.ws();
        if self.peek() != Some(b'"') {
            return Err(self.err("expected string key"));
        }
        if level > MAX_SCAN_LEVEL {
            self.note(Scan::TooDeep);
        }
        let key = self.string()?;
        self.ws();
        if !self.eat(":") {
            return Err(self.err("expected ':'"));
        }
        Ok(key)
    }

    /// Any value that is not a container, at `level`.
    fn scalar(&mut self, level: usize) -> Result<Value, ParseError> {
        let constant = ["NaN", "Infinity", "-Infinity"].iter().any(|c| self.rest().starts_with(c.as_bytes()));
        match self.peek() {
            _ if constant && level > MAX_HOOK_LEVEL => Err(self.err("nesting too deep")),
            _ if constant => Err(ParseError::NonJsonConstant),
            None => Err(self.err("unexpected end of input")),
            Some(b'"') => {
                let raw = self.string()?;
                Ok(Value::Str(self.text(raw)?))
            }
            Some(b'-' | b'0'..=b'9') => self.number(level),
            Some(_) if self.eat("true") => Ok(Value::Bool(true)),
            Some(_) if self.eat("false") => Ok(Value::Bool(false)),
            Some(_) if self.eat("null") => Ok(Value::Null),
            Some(_) => Err(self.err("unexpected token")),
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

    /// Text from a parsed string. An unpaired surrogate is noted for the
    /// scan (and read as U+FFFD), or in [`Mode::Strict`] is an error.
    fn text(&mut self, wtf8: Vec<u8>) -> Result<String, ParseError> {
        match String::from_utf8(wtf8) {
            Ok(text) => Ok(text),
            Err(_) if self.mode == Mode::Strict => Err(ParseError::LoneSurrogate),
            Err(e) => {
                self.note(Scan::LoneSurrogate);
                Ok(wtf8_lossy(e.as_bytes()))
            }
        }
    }

    /// A JSON string as Python holds it, in WTF-8: UTF-8 in which an unpaired
    /// surrogate is encoded like any other code point. Equal strings have
    /// equal bytes, and only an unpaired surrogate makes them invalid UTF-8.
    fn string(&mut self) -> Result<Vec<u8>, ParseError> {
        self.i += 1; // opening quote
        let mut out = Vec::new();
        loop {
            let start = self.i;
            // Copy a run of plain characters. We stop only on ASCII bytes, so
            // the run is whole UTF-8 characters.
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.extend_from_slice(&self.s[start..self.i]);
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
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => push_wtf8(&mut out, self.unicode_escape()?),
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                Some(_) => return Err(self.err("control character in string")),
            }
        }
    }

    /// After `\u`: one code point, from a BMP escape or a surrogate pair. As
    /// in Python, a high surrogate followed by an escape that is not a low
    /// surrogate stands alone, and that escape is read on its own.
    fn unicode_escape(&mut self) -> Result<u32, ParseError> {
        let hi = self.hex4()?;
        if (0xD800..0xDC00).contains(&hi) && self.rest().starts_with(b"\\u") {
            let after_hi = self.i;
            self.i += 2;
            let lo = self.hex4()?;
            if (0xDC00..0xE000).contains(&lo) {
                return Ok(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00));
            }
            self.i = after_hi;
        }
        Ok(hi)
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number(&mut self, level: usize) -> Result<Value, ParseError> {
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
            if lexeme.trim_start_matches('-').len() > MAX_INT_DIGITS {
                return Err(self.err("integer has more digits than Python allows"));
            }
            Ok(Value::Int(lexeme.to_string()))
        } else if level > MAX_HOOK_LEVEL {
            Err(self.err("nesting too deep"))
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

/// Push a code point (a character or an unpaired surrogate) as WTF-8.
fn push_wtf8(out: &mut Vec<u8>, cp: u32) {
    match char::from_u32(cp) {
        Some(c) => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        // A surrogate, in the three-byte form of the code points around it.
        None => {
            out.extend_from_slice(&[0xE0 | (cp >> 12) as u8, 0x80 | (cp >> 6 & 0x3F) as u8, 0x80 | (cp & 0x3F) as u8])
        }
    }
}

/// WTF-8 as text, each unpaired surrogate read as U+FFFD.
fn wtf8_lossy(wtf8: &[u8]) -> String {
    let mut out = String::with_capacity(wtf8.len());
    decode_py(wtf8, Undecoded::Wtf8, |piece| match piece {
        Piece::Text(t) => out.push_str(t),
        Piece::Surrogate(_) => out.push(char::REPLACEMENT_CHARACTER),
    });
    out
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
        for bad in ["[1,]", "01", "1.", ".5", "-", "\u{feff}{}", "\"a\u{1}\"", r#""\x""#, r#""\u12""#, "{} x"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        for bad in [r#"{"a" 1}"#, "tru", "1e", r#""unterminated"#, r#"{"a":1"#, "[", r#"{"a":"\ud800\uZZZZ"}"#] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&"[".repeat(10_000)).is_err());
    }

    #[test]
    fn reports_a_duplicate_key_when_its_object_closes() {
        // Python's object_pairs_hook sees an object only once it is complete,
        // so any error later in that object is raised first.
        let syntax = |r: Result<Value, ParseError>| matches!(r, Err(ParseError::Syntax { .. }));
        let dup = |k: &str| Err::<Value, _>(ParseError::DuplicateKey(k.into()));
        assert_eq!(parse(r#"{"a":1,"a":1e400}"#), Err(ParseError::NonJsonConstant));
        assert_eq!(parse(r#"{"a":1,"a":NaN}"#), Err(ParseError::NonJsonConstant));
        assert!(syntax(parse(r#"{"a":1,"a":2,}"#)));
        assert!(syntax(parse(r#"{"a":1,"a":2"#)));
        assert_eq!(parse(r#"{"a":{"b":1,"b":2},"a":3}"#), dup("b"));
        assert_eq!(parse(r#"{"a":1,"a":2,"b":3,"b":4}"#), dup("a"));
        assert_eq!(parse(r#"{"a":1,"b":2,"b":3,"a":4}"#), dup("b"));
        assert_eq!(parse(r#"[{"a":1,"a":2},{"b":1,"b"}]"#), dup("a"));
        // Keys compare as Python's str: distinct unpaired surrogates, or one and
        // a real U+FFFD, are different keys; the same one twice is a duplicate,
        // and the error shows the surrogate as lens.py does.
        for distinct in [r#"{"\ud800":1,"\udc00":2}"#, r#"{"\ud800":1,"\ufffd":2}"#, r#"{"\ud800":1,"\ud801":2}"#] {
            assert_eq!(parse_payload(distinct).map(|p| p.scan), Ok(Scan::LoneSurrogate), "{distinct}");
        }
        assert_eq!(parse_payload(r#"{"\ud800":1,"\ud800":2}"#), Err(ParseError::DuplicateKey(r"\ud800".into())));
        assert_eq!(
            parse_payload(r#"{"a":{"x\udc00y":1,"x\udc00y":2}}"#),
            Err(ParseError::DuplicateKey(r"x\udc00y".into()))
        );
    }

    #[test]
    fn integers_follow_pythons_digit_limit() {
        let digits = |n: usize| "9".repeat(n);
        assert_eq!(parse(&digits(4300)), Ok(Value::Int(digits(4300))));
        assert_eq!(parse(&format!("-{}", digits(4300))), Ok(Value::Int(format!("-{}", digits(4300)))));
        assert!(matches!(parse(&digits(4301)), Err(ParseError::Syntax { .. })));
        assert!(matches!(parse(&format!("[-{}]", digits(4301))), Err(ParseError::Syntax { .. })));
        // Python's float() has no digit limit; a long float lexeme is just a float.
        assert_eq!(parse(&format!("0.{}", digits(5000))), Ok(Value::Float(1.0)));
    }

    #[test]
    fn scan_follows_the_lens_py_walk() {
        let deep = |n: usize, inner: &str| format!(r#"{{"x":{}{inner}{}}}"#, "[".repeat(n), "]".repeat(n));
        let scan = |text: &str| parse_payload(text).map(|p| p.scan);
        let cases = [
            (deep(498, ""), Scan::Clean),
            (deep(499, ""), Scan::TooDeep),
            (deep(497, "0"), Scan::Clean),
            (deep(498, "0"), Scan::TooDeep),
            (deep(498, r#""s""#), Scan::TooDeep),
            (deep(497, "{}"), Scan::Clean),
            (deep(496, r#"{"k":null}"#), Scan::Clean),
            (deep(497, r#"{"k":null}"#), Scan::TooDeep),
            (r#"{"a":"\ud800","x":[]}"#.into(), Scan::LoneSurrogate),
            (deep(499, "").replace(r#"{"x":"#, r#"{"a":"\ud800","x":"#), Scan::LoneSurrogate),
            (deep(499, "").replace('}', r#","a":"\ud800"}"#), Scan::TooDeep),
            (r#"{"\udc00":"v"}"#.into(), Scan::LoneSurrogate),
            (r#"{"x":[1,{"y":"ok"},"😀"]}"#.into(), Scan::Clean),
            (deep(499, "").replace(r#"{"x":"#, r#"{"a":["ok",{"y":["\ud800"]}],"x":"#), Scan::LoneSurrogate),
            // Unpaired at a level the walk reaches, then too deep, in one string's object.
            (format!(r#"{{"x":{}"\ud800"{}}}"#, "[".repeat(498), "]".repeat(498)), Scan::TooDeep),
            (format!(r#"{{"x":{}"\ud800"{}}}"#, "[".repeat(497), "]".repeat(497)), Scan::LoneSurrogate),
        ];
        for (text, want) in &cases {
            assert_eq!(scan(text), Ok(*want), "{:.70}", text);
        }
        // parse() keeps 0.1.1's limit of 512 levels, deeper than the scan.
        assert!(matches!(parse(&deep(512, "")), Ok(Value::Object(_))));
        assert!(matches!(parse(&deep(513, "")), Err(ParseError::Syntax { msg: "nesting too deep", .. })));
        assert_eq!(parse(&deep(499, r#""\ud800""#)), Err(ParseError::LoneSurrogate));
    }

    #[test]
    fn unpaired_surrogates_read_as_replacement_characters() {
        let read = |text: &str| parse_payload(text).unwrap();
        // A high surrogate followed by an escape that is not a low surrogate
        // stands alone; the escape after it is read on its own, as in Python.
        let p = read(r#""\ud800😀\ud800A""#);
        assert_eq!((p.value, p.scan), (Value::Str("\u{fffd}😀\u{fffd}A".into()), Scan::LoneSurrogate));
        assert_eq!(read(r#""😀""#), Parsed { value: Value::Str("😀".into()), scan: Scan::Clean });
        // Not an object, so lens.py reports the type, not the surrogate.
        assert_eq!(read(r#""\udfff""#).value, Value::Str("\u{fffd}".into()));
    }

    #[test]
    fn nesting_follows_cpython_and_never_uses_the_call_stack() {
        let nest = |n: usize, inner: &str| format!(r#"{{"x":{}{inner}{}}}"#, "[".repeat(n), "]".repeat(n));
        let run = |text: String| {
            // A thread with a small stack: any recursion per level would overflow
            // it. The result is dropped here, as dropping a deep Value recurses.
            let parsed = std::thread::Builder::new().stack_size(64 * 1024).spawn(move || parse_payload(&text));
            parsed.unwrap().join().unwrap().map(|p| p.scan)
        };
        // CPython 3.13's json.loads accepts arrays 9997 levels below the
        // top-level value, and integers, strings and literals in them.
        assert_eq!(run(nest(9997, "")), Ok(Scan::TooDeep));
        assert_eq!(run(nest(9997, "1")), Ok(Scan::TooDeep));
        assert!(matches!(run(nest(9998, "")), Err(ParseError::Syntax { msg: "nesting too deep", .. })));
        // A node that needs one of lens.py's hooks stops two levels earlier.
        let at = |level: usize, node: &str| format!("{}{node}{}", "[".repeat(level), "]".repeat(level));
        let too_deep =
            |r: Result<Scan, ParseError>| matches!(r, Err(ParseError::Syntax { msg: "nesting too deep", .. }));
        for node in [r#"{"a":1}"#, "{}", "1.5", "1e400", "NaN", "-Infinity"] {
            assert!(too_deep(run(at(9996, node))), "{node} at 9996");
        }
        for node in [r#"{"a":1}"#, "1.5", "true", r#""s""#, "1"] {
            assert_eq!(run(at(9995, node)), Ok(Scan::TooDeep), "{node} at 9995");
        }
        for node in ["1", r#""s""#, "null"] {
            assert_eq!(run(at(9998, node)), Ok(Scan::TooDeep), "{node} at 9998");
        }
        assert_eq!(run(at(9995, "NaN")), Err(ParseError::NonJsonConstant));
        assert!(too_deep(run(at(9996, r#"{"a":1,"a":2}"#))), "the duplicate is never seen");
        // Raising from the object's hook takes one level more.
        assert!(too_deep(run(at(9995, r#"{"a":1,"a":2}"#))), "the duplicate cannot be raised");
        assert_eq!(run(at(9994, r#"{"a":1,"a":2}"#)), Err(ParseError::DuplicateKey("a".into())));
        assert!(matches!(run(format!("[{}", "{\"a\":".repeat(100_000))), Err(ParseError::Syntax { .. })));
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

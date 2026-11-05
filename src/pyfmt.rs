//! Python-compatible text behaviour that the reference verifier (lens.py)
//! depends on: str.isspace()/strip(), float repr(), repr() of values,
//! truthiness, and the safe() terminal-escaping helper. Also the JavaScript
//! `\s` set, which createKnobe uses when writing a body.

use crate::json::Value;

/// Python `str.isspace()`: bidi WS/B/S or category Zs. This is the set that
/// `str.split()`, `str.strip()` and regex `\s` use in lens.py.
pub fn is_py_space(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | '\u{1c}'..='\u{1f}' | ' ' | '\u{85}' | '\u{a0}'
        | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}'
        | '\u{3000}')
}

/// Python `s.strip()` with no arguments.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// JavaScript regex `\s` (WhiteSpace + LineTerminator). Differs from Python:
/// includes U+FEFF; excludes U+001C..U+001F and U+0085.
pub fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// Python `repr(float)` (what `json.dumps` emits for a float): shortest
/// round-trip digits; fixed notation for 1e-4 <= |x| < 1e16 with at least one
/// fractional digit; otherwise `d[.ddd]e±XX`. `None` for NaN/inf, which
/// `json.dumps(allow_nan=False)` refuses.
pub fn float_repr(x: f64) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    if x == 0.0 {
        return Some(if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_string());
    }
    // Rust's `{:e}` is the shortest round-trip form, e.g. "1.5e22", "-5e-324".
    let e = format!("{x:e}");
    let (mant, exp) = e.split_once('e').expect("LowerExp always has an exponent");
    let exp: i32 = exp.parse().expect("integer exponent");
    let (sign, mant) = mant.strip_prefix('-').map_or(("", mant), |m| ("-", m));
    let digits: String = mant.chars().filter(|c| *c != '.').collect();

    if !(-4..16).contains(&exp) {
        let m = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits };
        let esign = if exp < 0 { '-' } else { '+' };
        return Some(format!("{sign}{m}e{esign}{:02}", exp.unsigned_abs()));
    }
    let out = if exp >= 0 {
        let int_len = exp as usize + 1;
        if int_len >= digits.len() {
            format!("{digits:0<int_len$}.0")
        } else {
            format!("{}.{}", &digits[..int_len], &digits[int_len..])
        }
    } else {
        format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
    };
    Some(format!("{sign}{out}"))
}

/// Python `str(int)` for a JSON integer lexeme: identical except "-0" -> "0".
pub fn int_repr(lexeme: &str) -> &str {
    if lexeme.strip_prefix('-').is_some_and(|d| d.bytes().all(|b| b == b'0')) { "0" } else { lexeme }
}

/// Python type name of a parsed JSON value, for messages.
pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python truthiness.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Int(l) => int_repr(l) != "0",
        Value::Float(f) => *f != 0.0,
        Value::Str(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `str.isprintable()` for one character, from CPython 3.13's tables
/// (Unicode 15.1). It decides what repr() escapes; messages only, never
/// hashed or gated.
fn py_printable(c: char) -> bool {
    let c = c as u32;
    crate::pyprintable::NOT_PRINTABLE
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_err()
}

/// Python `repr(str)`.
pub fn repr_str(s: &str) -> String {
    repr_py(s.as_bytes(), Undecoded::Wtf8)
}

/// What bytes that are not valid UTF-8 stand for: code points that Python
/// holds as surrogates, which a Rust string cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Undecoded {
    /// Text from the JSON parser (WTF-8): a three-byte encoded surrogate is
    /// that surrogate.
    Wtf8,
    /// A path's bytes, as Python decodes a command-line argument
    /// (surrogateescape): each byte that is not UTF-8 is U+DC80-U+DCFF.
    SurrogateEscape,
}

/// A piece of Python's string: a run of valid UTF-8, or a code point Python
/// holds where the bytes are not UTF-8 (a surrogate).
pub(crate) enum Piece<'a> {
    Text(&'a str),
    Surrogate(u32),
}

/// Walk `bytes` as Python's string, piece by piece.
pub(crate) fn decode_py<'a>(mut bytes: &'a [u8], how: Undecoded, mut each: impl FnMut(Piece<'a>)) {
    while !bytes.is_empty() {
        let valid = std::str::from_utf8(bytes).map_or_else(|e| e.valid_up_to(), str::len);
        let (run, rest) = bytes.split_at(valid);
        if !run.is_empty() {
            each(Piece::Text(std::str::from_utf8(run).expect("valid up to here")));
        }
        bytes = match (how, rest) {
            (_, []) => rest,
            (Undecoded::Wtf8, &[0xed, b1 @ 0xa0..=0xbf, b2 @ 0x80..=0xbf, ..]) => {
                each(Piece::Surrogate(0xd000 | (u32::from(b1) & 0x3f) << 6 | u32::from(b2) & 0x3f));
                &rest[3..]
            }
            (_, &[b, ..]) => {
                each(Piece::Surrogate(0xdc00 | u32::from(b)));
                &rest[1..]
            }
        };
    }
}

/// Python's string as text to show: each surrogate written `\udXXX`, which
/// is how lens.py's safe() and repr() show it.
pub(crate) fn display_py(bytes: &[u8], how: Undecoded) -> String {
    let mut out = String::with_capacity(bytes.len());
    decode_py(bytes, how, |piece| match piece {
        Piece::Text(t) => out.push_str(t),
        Piece::Surrogate(cp) => out.push_str(&format!("\\u{cp:04x}")),
    });
    out
}

/// Python `repr()` of the string `bytes` stand for (see [`Undecoded`]).
pub(crate) fn repr_py(bytes: &[u8], how: Undecoded) -> String {
    let mut chars = Vec::new();
    decode_py(bytes, how, |piece| match piece {
        Piece::Text(t) => chars.extend(t.chars().map(Ok)),
        Piece::Surrogate(cp) => chars.push(Err(cp)),
    });
    let has = |q: char| chars.contains(&Ok(q));
    let quote = if has('\'') && !has('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push(quote);
    for c in chars {
        match c {
            Ok('\\') => out.push_str("\\\\"),
            Ok('\t') => out.push_str("\\t"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok(c) if c == quote => {
                out.push('\\');
                out.push(c);
            }
            Ok(c) if py_printable(c) => out.push(c),
            Ok(c) if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            Ok(c) if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            Ok(c) => out.push_str(&format!("\\U{:08x}", c as u32)),
            Err(surrogate) => out.push_str(&format!("\\u{surrogate:04x}")),
        }
    }
    out.push(quote);
    out
}

/// Python `repr()` of a parsed JSON value (None/True/False, lists, dicts).
pub fn repr(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Int(l) => int_repr(l).into(),
        Value::Float(f) => float_repr(*f).unwrap_or_else(|| if *f > 0.0 { "inf" } else { "-inf" }.into()),
        Value::Str(s) => repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, v)| format!("{}: {}", repr_str(k), repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Python `str()` of a parsed JSON value: a string as is, anything else as
/// its repr().
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => repr(other),
    }
}

/// lens.py `safe()`: escape C0/C1 controls and DEL as `\xNN`, so a crafted
/// string cannot spoof the report or inject terminal escapes, and bidi
/// overrides and isolates and line/paragraph separators (U+202A-202E,
/// U+2066-2069, U+2028/2029) as `\uNNNN`, so it cannot reorder what a reader
/// sees; then truncate at `limit` characters (`usize::MAX`: never). A Rust
/// string holds no unpaired surrogate; where Python would hold one, the
/// caller has already written it as `\udXXX` ([`display_py`]), which is
/// what safe() shows.
pub fn safe_str(s: &str, limit: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let o = c as u32;
        if o < 0x20 || o == 0x7f || (0x80..=0x9f).contains(&o) {
            out.push_str(&format!("\\x{o:02x}"));
        } else if (0x202a..=0x202e).contains(&o) || (0x2066..=0x2069).contains(&o) || o == 0x2028 || o == 0x2029 {
            out.push_str(&format!("\\u{o:04x}"));
        } else {
            out.push(c);
        }
    }
    if out.chars().count() > limit {
        out = out.chars().take(limit).collect::<String>() + "…";
    }
    out
}

/// lens.py `safe()` for any value: strings escaped, everything else repr().
pub fn safe(v: &Value) -> String {
    match v {
        Value::Str(s) => safe_str(s, 300),
        other => repr(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python_json_dumps() {
        // Expected values produced by CPython 3.13 json.dumps.
        let cases: &[(f64, &str)] = &[
            (1.0, "1.0"),
            (1.5, "1.5"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (100.0, "100.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (2.5e-7, "2.5e-07"),
            (123456789.125, "123456789.125"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (0.1, "0.1"),
            (-1.5e22, "-1.5e+22"),
            (9999999999999998.0, "9999999999999998.0"),
            (1.2345678901234567e19, "1.2345678901234567e+19"),
            (std::f64::consts::PI, "3.141592653589793"),
        ];
        for (x, want) in cases {
            assert_eq!(float_repr(*x).as_deref(), Some(*want), "repr({x:e})");
        }
        assert_eq!(float_repr(f64::INFINITY), None);
        assert_eq!(float_repr(f64::NAN), None);
    }

    #[test]
    fn py_strip_differs_from_rust_trim_where_python_does() {
        assert_eq!(py_strip("\u{1c}\u{85} x \u{a0}"), "x");
        assert_eq!(py_strip("\u{feff}x\u{feff}"), "\u{feff}x\u{feff}");
    }

    #[test]
    fn safe_str_escapes_controls_and_reordering_characters() {
        // Expected values produced by the patched lens.py safe().
        assert_eq!(safe_str("a\u{1b}[31m\u{7f}\u{85}\u{9f}", 300), "a\\x1b[31m\\x7f\\x85\\x9f");
        assert_eq!(
            safe_str("\u{202a}\u{202e}\u{2066}\u{2069}\u{2028}\u{2029}", 300),
            "\\u202a\\u202e\\u2066\\u2069\\u2028\\u2029"
        );
        // Neighbours of the escaped ranges, and joiners, stay as they are.
        let kept = "\u{2027}\u{202f}\u{2065}\u{206a}\u{200d}\u{200e}\u{feff}\u{ad}\u{a0}é😀\\";
        assert_eq!(safe_str(kept, 300), kept);
        // The limit counts characters after escaping.
        assert_eq!(safe_str(&"é".repeat(301), 300), format!("{}…", "é".repeat(300)));
        assert_eq!(safe_str(&"\u{1b}".repeat(100), 300), format!("{}…", "\\x1b".repeat(75)));
        assert_eq!(safe_str(&"x".repeat(1000), usize::MAX), "x".repeat(1000));
    }

    #[test]
    fn surrogates_are_written_as_python_shows_them() {
        use Undecoded::{SurrogateEscape, Wtf8};
        // From the parser, an encoded surrogate is one code point; in a path,
        // Python's surrogateescape takes every undecodable byte on its own.
        assert_eq!(repr_py(b"a\xed\xa0\x80b", Wtf8), r"'a\ud800b'");
        assert_eq!(repr_py(b"a\xed\xa0\x80b", SurrogateEscape), r"'a\udced\udca0\udc80b'");
        assert_eq!(repr_py(b"/tmp/x\xff\xc3.md", SurrogateEscape), r"'/tmp/x\udcff\udcc3.md'");
        assert_eq!(repr_py(b"/x\xe2\x82(\xf0\x9f\x98\x80", SurrogateEscape), "'/x\\udce2\\udc82(😀'");
        assert_eq!(repr_py("it's\\\u{1b}".as_bytes(), Wtf8), r#""it's\\\x1b""#);
        assert_eq!(display_py(b"x\xed\xbf\xbfy\xed\xa0", Wtf8), r"x\udfffy\udced\udca0");
        assert_eq!(display_py(b"\xff\x1b", SurrogateEscape), "\\udcff\u{1b}");
    }

    #[test]
    fn repr_escapes_what_python_cannot_print() {
        // Expected values produced by CPython 3.13 repr().
        assert_eq!(repr_str("\u{2067}\u{61c}\u{200b}\u{a0}\u{378}"), r"'\u2067\u061c\u200b\xa0\u0378'");
        assert_eq!(repr_str("\u{e0001}\u{f0000}\u{1d173}é😀 "), r"'\U000e0001\U000f0000\U0001d173é😀 '");
        assert_eq!(repr_str("\u{7f}\u{85}\u{ad}\u{2028}\u{3000}"), r"'\x7f\x85\xad\u2028\u3000'");
    }

    #[test]
    fn repr_str_picks_quotes_like_python() {
        assert_eq!(repr_str("a'b"), "\"a'b\"");
        assert_eq!(repr_str("a'b\""), "'a\\'b\"'");
        assert_eq!(repr_str("x\u{1}\n"), "'x\\x01\\n'");
    }

    #[test]
    fn int_repr_normalizes_negative_zero_only() {
        assert_eq!(int_repr("-0"), "0");
        assert_eq!(int_repr("-10"), "-10");
        assert_eq!(int_repr("123456789012345678901234567890"), "123456789012345678901234567890");
    }
}

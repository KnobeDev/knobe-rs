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

/// Approximates Python `str.isprintable()` for repr(); messages only, never
/// hashed or gated.
fn py_printable(c: char) -> bool {
    !matches!(c,
        '\0'..='\u{1f}' | '\u{7f}'..='\u{a0}' | '\u{ad}' | '\u{1680}' | '\u{2000}'..='\u{200f}'
        | '\u{2028}'..='\u{202f}' | '\u{205f}'..='\u{2064}' | '\u{3000}' | '\u{feff}')
}

/// Python `repr(str)`.
pub fn repr_str(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if py_printable(c) => out.push(c),
            c if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push_str(&format!("\\u{:04x}", c as u32)),
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

/// lens.py `safe()`: escape C0/C1 controls and DEL so a crafted string cannot
/// spoof the report or inject terminal escapes; truncate at `limit` chars.
pub fn safe_str(s: &str, limit: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let o = c as u32;
        if o < 0x20 || o == 0x7f || (0x80..=0x9f).contains(&o) {
            out.push_str(&format!("\\x{o:02x}"));
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

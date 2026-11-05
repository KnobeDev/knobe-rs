//! Differential parity with the reference verifier: for every published file
//! and for a battery of crafted hostile files, the Rust verifier must report
//! exactly what `python3 lens.py --json` reports on the fields the upstream
//! parity gate compares (state, conformance, body_verified, computed, stored,
//! block_count, multiple_blocks, exit code).

mod common;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use knobe::Value;

#[test]
fn published_corpus_matches_lens_py() {
    let mut diffs = Vec::new();
    let files = common::corpus();
    for f in &files {
        let py = common::lens(f).unwrap_or_else(|| panic!("lens.py crashed on {}", f.display()));
        let rs = common::rust(f);
        if py != rs {
            diffs.push(format!("{}\n  lens: {py:?}\n  rust: {rs:?}", f.display()));
        }
    }
    assert!(diffs.is_empty(), "{} of {} files disagree:\n{}", diffs.len(), files.len(), diffs.join("\n"));
}

// ---------------------------------------------------------------------------
// Hostile-input battery
// ---------------------------------------------------------------------------

const FM: &str = "---\ntitle: \"T\"\nspec_version: \"1.0\"\n---\n";
const BASE: &str = r#""spec_version":"1.0","title":"T","summary":"S","content_type":"original","created_date":"2026-01-02","license":"CC0-1.0","privacy_level":"public","quarantine_status":"quarantine","attribution":{"sources":[{"author":"A"}]}"#;

fn oracle(mode: &str, input: &str) -> String {
    let mut child = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/pyhash.py"))
        .arg(mode)
        .env("KNOBE_PROTOCOL_DIR", common::protocol_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3");
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "pyhash oracle failed on: {input}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// Fill `__B__` with the oracle body hash of `body`, then `__H__` with the
/// oracle payload hash of the resulting payload text.
fn sealed_payload(payload: &str, body: &str) -> String {
    let p = payload.replace("__B__", &oracle("body", body));
    if p.contains("__H__") {
        let h = oracle("payload", &p.replace("\"__H__\"", "null"));
        p.replace("__H__", &h)
    } else {
        p
    }
}

fn block(payload_text: &str) -> String {
    format!("\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n", b64(payload_text.as_bytes()))
}

/// A complete file: frontmatter + body + one payload block.
fn knobe(fm: &str, body: &str, payload: &str) -> Vec<u8> {
    format!("{fm}{body}{}", block(&sealed_payload(payload, body))).into_bytes()
}

fn obj(extra: &str) -> String {
    if extra.is_empty() {
        format!("{{{BASE},\"payload_hash\":\"__H__\"}}")
    } else {
        format!("{{{BASE},{extra},\"payload_hash\":\"__H__\"}}")
    }
}

/// Payload with BASE fields minus `drop`, plus `extra`.
fn obj_without(drop: &str, extra: &str) -> String {
    let fields: Vec<&str> =
        split_top_level(BASE).into_iter().filter(|f| !f.starts_with(&format!("\"{drop}\""))).collect();
    let mut body = fields.join(",");
    if !extra.is_empty() {
        body = if body.is_empty() { extra.to_string() } else { format!("{body},{extra}") };
    }
    format!("{{{body},\"payload_hash\":\"__H__\"}}")
}

fn split_top_level(s: &str) -> Vec<&str> {
    let (mut out, mut depth, mut start, mut in_str, mut esc) = (Vec::new(), 0i32, 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if esc => esc = false,
            '\\' if in_str => esc = true,
            '"' => in_str = !in_str,
            '{' | '[' if !in_str => depth += 1,
            '}' | ']' if !in_str => depth -= 1,
            ',' if !in_str && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn hostile_cases() -> Vec<(&'static str, Vec<u8>)> {
    let hex = "a".repeat(64);
    let body = "\nHello body.\n";
    let bh = r#""body_hash":"__B__""#;
    let mut c: Vec<(&'static str, Vec<u8>)> = vec![
        ("baseline", knobe(FM, "", &obj(""))),
        ("baseline-with-body", knobe(FM, body, &obj(bh))),
        // --- hash format: exactly 64 lowercase hex, nothing following (ERRATA E12) ---
        (
            "payload-hash-trailing-newline",
            knobe(
                FM,
                "",
                &obj_without("payload_hash", &format!(r#""payload_hash":"{hex}\n""#))
                    .replace(",\"payload_hash\":\"__H__\"", ""),
            ),
        ),
        ("body-hash-trailing-newline", knobe(FM, body, &obj(&format!(r#""body_hash":"{hex}\n""#)))),
        (
            "parent-hash-trailing-newline",
            knobe(FM, "", &obj(&format!(r#""parents":[{{"title":"p","payload_hash":"{hex}\n"}}]"#))),
        ),
        (
            "parent-hash-uppercase",
            knobe(FM, "", &obj(&format!(r#""parents":[{{"title":"p","payload_hash":"{}"}}]"#, "A".repeat(64)))),
        ),
        ("parent-hash-missing-ok", knobe(FM, "", &obj(r#""parents":[{"title":"p"},"x",null]"#))),
        ("parents-not-a-list", knobe(FM, "", &obj(r#""parents":{"payload_hash":"zz"}"#))),
        (
            "payload-hash-missing",
            knobe(FM, "", &obj_without("payload_hash", "").replace(",\"payload_hash\":\"__H__\"", "")),
        ),
        ("payload-hash-null", knobe(FM, "", &obj("").replace("\"__H__\"", "null"))),
        ("payload-hash-number", knobe(FM, "", &obj("").replace("\"__H__\"", "5"))),
        ("body-hash-null", knobe(FM, body, &obj(r#""body_hash":null"#))),
        ("body-hash-number", knobe(FM, body, &obj(r#""body_hash":7"#))),
        // --- created_date ---
        ("date-feb-29-nonleap", knobe(FM, "", &obj_without("created_date", r#""created_date":"2026-02-29""#))),
        ("date-feb-29-leap", knobe(FM, "", &obj_without("created_date", r#""created_date":"2024-02-29""#))),
        ("date-year-zero", knobe(FM, "", &obj_without("created_date", r#""created_date":"0000-01-01""#))),
        ("date-arabic-indic-digits", knobe(FM, "", &obj_without("created_date", r#""created_date":"٢٠٢٦-01-01""#))),
        ("date-trailing-newline", knobe(FM, "", &obj_without("created_date", r#""created_date":"2026-01-01\n""#))),
        ("date-short-month", knobe(FM, "", &obj_without("created_date", r#""created_date":"2026-1-01""#))),
        ("date-number", knobe(FM, "", &obj_without("created_date", r#""created_date":20260101"#))),
        // --- attribution / sources truthiness ---
        ("sources-empty-list", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":[]}"#))),
        ("sources-empty-object", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":{}}"#))),
        ("sources-nonempty-object", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":{"a":1}}"#))),
        ("sources-string", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":"x"}"#))),
        ("sources-empty-string", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":""}"#))),
        ("sources-zero", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":0}"#))),
        ("sources-zero-float", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":0.0}"#))),
        ("sources-true", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":true}"#))),
        ("sources-null", knobe(FM, "", &obj_without("attribution", r#""attribution":{"sources":null}"#))),
        ("sources-absent", knobe(FM, "", &obj_without("attribution", r#""attribution":{}"#))),
        ("attribution-string", knobe(FM, "", &obj_without("attribution", r#""attribution":"me""#))),
        ("attribution-null", knobe(FM, "", &obj_without("attribution", r#""attribution":null"#))),
        ("attribution-list", knobe(FM, "", &obj_without("attribution", r#""attribution":[{"sources":[1]}]"#))),
        // --- string-typed required fields ---
        ("title-number", knobe(FM, "", &obj_without("title", r#""title":5"#))),
        ("title-bool", knobe(FM, "", &obj_without("title", r#""title":true"#))),
        ("title-null", knobe(FM, "", &obj_without("title", r#""title":null"#))),
        ("summary-list", knobe(FM, "", &obj_without("summary", r#""summary":[]"#))),
        ("license-object", knobe(FM, "", &obj_without("license", r#""license":{}"#))),
        ("summary-missing", knobe(FM, "", &obj_without("summary", ""))),
        // --- spec_version ---
        ("spec-version-float", knobe(FM, "", &obj_without("spec_version", r#""spec_version":1.0"#))),
        ("spec-version-2", knobe(FM, "", &obj_without("spec_version", r#""spec_version":"2.0""#))),
        ("spec-version-null", knobe(FM, "", &obj_without("spec_version", r#""spec_version":null"#))),
        ("spec-version-padded", knobe(FM, "", &obj_without("spec_version", r#""spec_version":"1.0 ""#))),
        ("spec-version-missing", knobe(FM, "", &obj_without("spec_version", ""))),
        // --- vocabulary ---
        ("vocab-custom-bare", knobe(FM, "", &obj_without("content_type", r#""content_type":"custom""#))),
        ("vocab-ext-prefix", knobe(FM, "", &obj_without("content_type", r#""content_type":"ext-custom""#))),
        ("vocab-namespaced", knobe(FM, "", &obj_without("privacy_level", r#""privacy_level":"acme:secret""#))),
        ("vocab-identity-status", knobe(FM, "", &obj(r#""identity_status":"vibes""#))),
        ("vocab-non-string", knobe(FM, "", &obj(r#""identity_status":["signed"]"#))),
        // --- numbers: hash must still match (ERRATA E1), conformance invalid ---
        ("numbers-ints", knobe(FM, "", &obj(r#""x":[0,-0,7,-12,123456789012345678901234567890]"#))),
        (
            "numbers-floats",
            knobe(
                FM,
                "",
                &obj(r#""x":[1.0,1.5,-0.0,1e16,1E2,1e-5,0.0001,2.5e-7,123456789.125,1.7976931348623157e308,5e-324]"#),
            ),
        ),
        ("numbers-bool-null-not-numeric", knobe(FM, "", &obj(r#""flag":true,"none":null,"deep":{"a":[false]}"#))),
        ("number-underflow-to-zero", knobe(FM, "", &obj(r#""x":1e-400"#))),
        ("number-int-beyond-float-range", knobe(FM, "", &obj(&format!(r#""x":1{}"#, "0".repeat(400))))),
        // --- a float that overflows to inf has no canonical form: unreadable (lens.py PR #11) ---
        ("number-overflow-in-field", knobe(FM, "", &obj(r#""x":1e400"#))),
        ("number-overflow-nested", knobe(FM, "", &obj(r#""ext":{"a":[-1e309]}"#))),
        // payload_hash is left out of the hash, so only the parser can catch these.
        ("payload-hash-overflow", knobe(FM, "", &obj("").replace("\"__H__\"", "1e400"))),
        ("payload-hash-overflow-negative", knobe(FM, "", &obj("").replace("\"__H__\"", "-1.5E+999"))),
        ("payload-hash-overflow-in-list", knobe(FM, "", &obj("").replace("\"__H__\"", "[1e400]"))),
        // --- JSON strictness ---
        ("dup-key-nested", knobe(FM, "", &obj(r#""ext":{"a":"1","a":"2"}"#))),
        ("nan-constant", knobe(FM, "", &obj(r#""x":NaN"#))),
        ("infinity-constant", knobe(FM, "", &obj(r#""x":-Infinity"#))),
        ("lone-surrogate-value", knobe(FM, "", &obj(r#""x":"\ud800""#))),
        ("surrogate-pair-escape", knobe(FM, "", &obj(r#""x":"😀""#))),
        ("escapes-mixed", knobe(FM, "", &obj(r#""x":"\u0000\u001f\b\f\n\r\t\/\\\"\u007f é""#))),
        ("nfd-key-no-collision", knobe(FM, "", &obj("\"cafe\u{301}\":\"v\",\"x\":\"e\u{301}\""))),
        ("nfc-collision-in-list", knobe(FM, "", &obj("\"x\":[{\"caf\u{e9}\":\"1\",\"cafe\u{301}\":\"2\"}]"))),
        ("astral-keys-sorting", knobe(FM, "", &obj("\"\u{1F600}\":\"a\",\"\u{FFFF}\":\"b\",\"\u{10000}\":\"c\""))),
        ("payload-top-level-string", knobe(FM, "", r#""hello""#)),
        ("payload-top-level-null", knobe(FM, "", "null")),
        ("payload-whitespace-around", knobe(FM, "", &format!(" \n\t{}\r\n ", obj("")))),
        ("payload-trailing-comma", knobe(FM, "", "{\"a\":\"1\",}")),
        ("payload-bom", knobe(FM, "", &format!("\u{feff}{}", obj("")))),
        ("payload-raw-control-char", knobe(FM, "", &obj("\"x\":\"a\u{1}b\""))),
        ("payload-raw-del-char", knobe(FM, "", &obj("\"x\":\"a\u{7f}b\""))),
        // --- frontmatter ---
        ("fm-missing", knobe("", "", &obj(""))),
        ("fm-crlf", knobe("---\r\ntitle: T\r\nspec_version: 1.0\r\n---\r\n", "", &obj(""))),
        ("fm-crlf-with-body", knobe("---\r\ntitle: T\r\n---\r\n", "Body\r\nline  \r\n", &obj(bh))),
        ("fm-double-cr", knobe("---\r\r\ntitle: T\r\n---\r\n", "", &obj(""))),
        ("fm-double-cr-with-body", knobe("---\r\r\ntitle: T\n---\n", body, &obj(bh))),
        ("fm-bom", knobe("\u{feff}---\ntitle: T\n---\n", "", &obj(""))),
        ("fm-bom-with-body", knobe("\u{feff}---\ntitle: T\n---\n", body, &obj(bh))),
        ("fm-unclosed", knobe("---\ntitle: T\nspec_version: 2.0\n", "", &obj(""))),
        ("fm-spec-quoted-mismatch", knobe("---\nspec_version: '1.1'\n---\n", "", &obj(""))),
        ("fm-spec-mixed-quotes", knobe("---\nspec_version: \"'1.0'\"\n---\n", "", &obj(""))),
        ("fm-spec-whitespace-only", knobe("---\nspec_version:    \n---\n", "", &obj(""))),
        ("fm-spec-empty", knobe("---\nspec_version:\n---\n", "", &obj(""))),
        (
            "fm-spec-indented-unicode-ws",
            knobe("---\n\u{3000}spec_version\u{a0}:\u{2003}1.1\u{205f}\n---\n", "", &obj("")),
        ),
        ("fm-spec-first-wins", knobe("---\nspec_version: 1.0\nspec_version: 9\n---\n", "", &obj(""))),
        ("fm-spec-after-close-ignored", knobe("---\ntitle: T\n---\nspec_version: 9\n", "", &obj(""))),
        ("fm-spec-not-prefix", knobe("---\nspec_versionx: 9\n---\n", "", &obj(""))),
        // --- body normalization edges (python whitespace vs line-end rules) ---
        ("body-tabs-and-spaces", knobe(FM, "\n  a \t\n\tb\t \n\n", &obj(bh))),
        ("body-lone-cr", knobe(FM, "\na\rb\r\n", &obj(bh))),
        ("body-unicode-edges", knobe(FM, "\u{1c}\u{85}\u{a0} body \u{3000}\u{2028}", &obj(bh))),
        ("body-feff-edge", knobe(FM, "\u{feff}body\u{feff}", &obj(bh))),
        ("body-nbsp-line-end", knobe(FM, "\nline\u{a0}\nnext \n", &obj(bh))),
        ("body-with-dashes-line", knobe(FM, "\nbefore\n---\nafter\n", &obj(bh))),
        ("body-empty-with-hash", knobe(FM, "", &obj(bh))),
        ("body-modified", {
            let mut f = knobe(FM, body, &obj(bh));
            let s = String::from_utf8(f.clone()).unwrap().replacen("Hello", "Jello", 1);
            f.clear();
            f.extend(s.into_bytes());
            f
        }),
    ];

    // --- block-level structure (built by hand) ---
    let good = sealed_payload(&obj(""), "");
    let good_b64 = b64(good.as_bytes());
    let with_bh = sealed_payload(&obj(bh), body);
    let wrap = |s: &str| {
        s.as_bytes().chunks(10).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect::<Vec<_>>().join("\n")
    };
    let raw = |s: String| s.into_bytes();
    // JSON allows trailing whitespace; pad until the Base64 needs '=' padding.
    let mut padded = good.clone();
    while padded.len() % 3 == 0 {
        padded.push(' ');
    }
    c.extend([
        (
            "block-wrapped-lines",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n", wrap(&good_b64))),
        ),
        (
            "block-internal-spaces-tabs",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n {} \t\n-----END KNOBE B64-----\n",
                good_b64.replacen('A', "A \t", 1)
            )),
        ),
        (
            "block-internal-unicode-space",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{}\u{a0}\u{1c}\n-----END KNOBE B64-----\n", good_b64)),
        ),
        (
            "block-internal-nel",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{}\u{85}\n-----END KNOBE B64-----\n", good_b64)),
        ),
        (
            "block-internal-vt-ff",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}\u{b}{}\u{c}\n-----END KNOBE B64-----\n",
                &good_b64[..8],
                &good_b64[8..]
            )),
        ),
        (
            "block-internal-zwsp",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{}\u{200b}\n-----END KNOBE B64-----\n", good_b64)),
        ),
        ("block-at-byte-zero", raw(format!("-----BEGIN KNOBE B64-----\n{good_b64}\n-----END KNOBE B64-----\n"))),
        (
            "block-at-byte-zero-with-body-hash",
            raw(format!("-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n", b64(with_bh.as_bytes()))),
        ),
        ("block-no-end", raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{good_b64}\n"))),
        ("block-empty", raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n\n-----END KNOBE B64-----\n"))),
        (
            "block-end-trailing-text",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{good_b64}\n-----END KNOBE B64----- trailing\n")),
        ),
        (
            "block-begin-trailing-space",
            raw(format!("{FM}\n-----BEGIN KNOBE B64----- \n{good_b64}\n-----END KNOBE B64-----\n")),
        ),
        (
            "block-crlf-markers",
            raw(format!("{FM}\r\n-----BEGIN KNOBE B64-----\r\n{good_b64}\r\n-----END KNOBE B64-----\r\n")),
        ),
        (
            "block-two-then-garbage-last",
            raw(format!("{FM}{}\n-----BEGIN KNOBE B64-----\n!!!!\n-----END KNOBE B64-----\n", block(&good))),
        ),
        ("block-two-with-body-hash", raw(format!("{FM}{body}{}{}", block(&with_bh), block(&with_bh)))),
        (
            "block-nested-begin",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n-----BEGIN KNOBE B64-----\n{good_b64}\n-----END KNOBE B64-----\n"
            )),
        ),
        (
            "b64-nonzero-trailing-bits",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n",
                flip_trailing_bits(&b64(padded.as_bytes()))
            )),
        ),
        (
            "b64-excess-after-padding",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{good_b64}QQ==\n-----END KNOBE B64-----\n")),
        ),
        (
            "b64-bad-alphabet",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}-_\n-----END KNOBE B64-----\n",
                &good_b64[..good_b64.len() - 2]
            )),
        ),
        ("b64-three-pad", raw(format!("{FM}\n-----BEGIN KNOBE B64-----\nQ===\n-----END KNOBE B64-----\n"))),
        (
            "b64-not-utf8-json",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n",
                b64(&[0xff, 0xfe, 0x7b, 0x7d])
            )),
        ),
    ]);
    c.push(("file-not-utf8", [FM.as_bytes(), &[0xc3, 0x28]].concat()));
    c.push(("file-empty", Vec::new()));
    c
}

/// Change the last data character before padding so unused low bits are set
/// (Python accepts these; a strict canonical decoder would not).
fn flip_trailing_bits(b: &str) -> String {
    let pad = b.chars().rev().take_while(|&c| c == '=').count();
    assert!(pad > 0, "need padded input to have spare bits");
    let mut chars: Vec<char> = b.chars().collect();
    let i = chars.len() - pad - 1;
    const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let v = A.find(chars[i]).unwrap();
    chars[i] = A.as_bytes()[v | 1] as char;
    chars.into_iter().collect()
}

/// Cases where knobe-rs follows explicit spec text and lens.py does not (see
/// docs/INTERPRETATIONS.md): (case, rule, state, body_verified, conformance).
/// Each must differ from lens.py; if lens.py starts agreeing (an upstream fix
/// landed), the test fails so the entry can be removed.
const SPEC_OVER_REFERENCE: &[(&str, &str, &str, Option<&str>, &str)] = &[
    ("fm-crlf-with-body", "I-1", "verified", Some("yes"), "invalid"),
    ("fm-double-cr", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-double-cr-with-body", "I-1, I-4", "verified", Some("yes"), "invalid"),
    ("fm-bom", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-whitespace-only", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-empty", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-after-close-ignored", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-not-prefix", "I-1", "verified", Some("omitted"), "invalid"),
];

#[test]
fn hostile_battery_matches_lens_py_except_documented_spec_cases() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("hostile");
    std::fs::create_dir_all(&dir).unwrap();
    let mut diffs = Vec::new();
    let cases = hostile_cases();
    for (name, bytes) in &cases {
        let path = dir.join(format!("{name}.knobe.md"));
        std::fs::write(&path, bytes).unwrap();
        let Some(py) = common::lens(&path) else {
            diffs.push(format!("{name}: lens.py produced no JSON report"));
            continue;
        };
        let rs = common::rust(&path);
        match SPEC_OVER_REFERENCE.iter().find(|c| c.0 == *name) {
            Some((_, rule, state, body, conformance)) => {
                let want = (Value::Str((*state).into()), body.map_or(Value::Null, |b| Value::Str(b.into())));
                let want_conf = Value::Str((*conformance).into());
                if (rs.state.clone(), rs.body_verified.clone()) != want || rs.conformance != want_conf {
                    diffs.push(format!("{name} ({rule}): rust {rs:?} is not the spec result"));
                } else if py == rs {
                    diffs.push(format!("{name} ({rule}): lens.py now agrees; remove it from SPEC_OVER_REFERENCE"));
                }
            }
            None if py != rs => diffs.push(format!("{name}\n  lens: {py:?}\n  rust: {rs:?}")),
            None => {}
        }
    }
    assert_eq!(cases.len(), 122, "update the README if the battery size changes");
    assert!(diffs.is_empty(), "{} of {} hostile cases disagree:\n{}", diffs.len(), cases.len(), diffs.join("\n"));
}

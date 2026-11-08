//! Differential parity with the reference verifier, on every published file
//! and on a battery of crafted hostile files. The Rust verifier must report
//! exactly what `python3 lens.py --json` reports on the fields the upstream
//! parity gate compares (state, conformance, body_verified, computed, stored,
//! block_count, multiple_blocks, exit code), and the `knobe` command must
//! print the same complete `--json` output, byte for byte.

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
    // A body with two `---` horizontal rules, which a verifier that counts
    // `---` lines from anywhere could take for the frontmatter's delimiters.
    let rules = "\nIntro.\n\n---\n\nMiddle.\n\n---\n\nEnd.\n";
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
        // A non-string spec_version is shown as Python str() shows it, cut at 300 characters.
        ("spec-version-list", knobe(FM, "", &obj_without("spec_version", r#""spec_version":["1.0"]"#))),
        ("spec-version-object", knobe(FM, "", &obj_without("spec_version", r#""spec_version":{"v":"1.0"}"#))),
        ("spec-version-bool", knobe(FM, "", &obj_without("spec_version", r#""spec_version":true"#))),
        (
            "spec-version-long-list",
            knobe(
                FM,
                "",
                &obj_without("spec_version", &format!(r#""spec_version":[{}"1.0"]"#, r#""xxxxxxxx","#.repeat(40))),
            ),
        ),
        // --- vocabulary ---
        ("vocab-custom-bare", knobe(FM, "", &obj_without("content_type", r#""content_type":"custom""#))),
        ("vocab-ext-prefix", knobe(FM, "", &obj_without("content_type", r#""content_type":"ext-custom""#))),
        ("vocab-namespaced", knobe(FM, "", &obj_without("privacy_level", r#""privacy_level":"acme:secret""#))),
        ("vocab-identity-status", knobe(FM, "", &obj(r#""identity_status":"vibes""#))),
        ("vocab-non-string", knobe(FM, "", &obj(r#""identity_status":["signed"]"#))),
        // --- display: what safe() escapes, and where lens.py applies it ---
        ("dup-key-ansi", knobe(FM, "", r#"{"\u001b[31mRED":"1","\u001b[31mRED":"2"}"#)),
        ("dup-key-c1", knobe(FM, "", r#"{"\u0085x":"1","\u0085x":"2"}"#)),
        ("dup-key-bidi", knobe(FM, "", r#"{"a\u202eb":"1","a\u202eb":"2"}"#)),
        ("dup-key-line-separator", knobe(FM, "", r#"{"a\u2028b\u2066":"1","a\u2028b\u2066":"2"}"#)),
        ("dup-key-joiners-kept", knobe(FM, "", r#"{"\u200d\u202f\ufeff\u00ad":"1","\u200d\u202f\ufeff\u00ad":"2"}"#)),
        ("dup-key-surrogate", knobe(FM, "", r#"{"\ud800":"1","\ud800":"2"}"#)),
        ("dup-key-surrogate-in-text", knobe(FM, "", r#"{"x\u001b\udfffy":"1","x\u001b\udfffy":"2"}"#)),
        ("dup-key-surrogate-nested", knobe(FM, "", r#"{"a":{"\udc00":1,"\udc00":2}}"#)),
        ("dup-key-long", knobe(FM, "", &format!(r#"{{"{k}\u202e":"1","{k}\u202e":"2"}}"#, k = "k".repeat(297)))),
        ("stored-ansi", knobe(FM, "", &obj("").replace("\"__H__\"", r#""\u001b[31mDEADBEEF\u001b[0m""#))),
        ("stored-c1", knobe(FM, "", &obj("").replace("\"__H__\"", r#""\u009b31m""#))),
        ("stored-bidi", knobe(FM, "", &obj("").replace("\"__H__\"", &format!(r#""\u202e{hex}""#)))),
        ("stored-long-string", knobe(FM, "", &obj("").replace("\"__H__\"", &format!(r#""{}""#, "b".repeat(400))))),
        ("stored-list", knobe(FM, "", &obj("").replace("\"__H__\"", r#"["a",1]"#))),
        (
            "stored-long-list",
            knobe(FM, "", &obj("").replace("\"__H__\"", &format!("[{}0]", r#""xxxxxxxx","#.repeat(40)))),
        ),
        ("stored-object", knobe(FM, "", &obj("").replace("\"__H__\"", r#"{"k":"\u001b"}"#))),
        ("title-bidi", knobe(FM, "", &obj_without("title", r#""title":"a\u202eb\u2029""#))),
        ("privacy-level-bidi", knobe(FM, "", &obj_without("privacy_level", r#""privacy_level":"a\u2067b""#))),
        ("spec-version-bidi", knobe(FM, "", &obj_without("spec_version", r#""spec_version":"1.0\u202e""#))),
        ("numeric-key-escape", knobe(FM, "", &obj(r#""\u001b[2J\u202e":5"#))),
        // The human report shows these fields as str(), cut at 300 characters.
        (
            "privacy-level-long-list",
            knobe(
                FM,
                "",
                &obj_without("privacy_level", &format!(r#""privacy_level":[{}"x"]"#, r#""yyyyyyyy","#.repeat(40))),
            ),
        ),
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
        // --- Python reports a duplicate key only when its object closes
        // (object_pairs_hook), so a later error in the same object wins ---
        ("dup-key-then-overflow", knobe(FM, "", &obj(r#""ext":{"a":"1","a":1e400}"#))),
        ("dup-key-then-nan", knobe(FM, "", &obj(r#""ext":{"a":"1","a":NaN}"#))),
        ("dup-key-then-syntax-error", knobe(FM, "", r#"{"a":"1","a":"2",}"#)),
        ("dup-key-inner-closes-first", knobe(FM, "", &obj(r#""a":{"b":"1","b":"2"},"a":"3""#))),
        // --- Python's int() refuses more than 4300 digits; the sign does not count ---
        ("int-4300-digits", knobe(FM, "", &obj(&format!(r#""x":-{}"#, "9".repeat(4300))))),
        ("int-4301-digits", knobe(FM, "", &obj(&format!(r#""x":{}"#, "9".repeat(4301))))),
        // --- JSON strictness ---
        ("dup-key-nested", knobe(FM, "", &obj(r#""ext":{"a":"1","a":"2"}"#))),
        ("nan-constant", knobe(FM, "", &obj(r#""x":NaN"#))),
        ("infinity-constant", knobe(FM, "", &obj(r#""x":-Infinity"#))),
        ("lone-surrogate-value", knobe(FM, "", &obj(r#""x":"\ud800""#))),
        // The lone-surrogate walk runs once the payload has parsed and proved
        // to be an object, before the NFC and spec_version checks.
        ("lone-surrogate-key", knobe(FM, "", &obj(r#""\udc00":"v""#))),
        ("lone-surrogate-in-payload-hash", knobe(FM, "", &obj("").replace("\"__H__\"", r#""\ud800""#))),
        (
            "lone-surrogate-and-bad-spec-version",
            knobe(FM, "", &obj_without("spec_version", r#""spec_version":"2.0","a":"\ud800""#)),
        ),
        (
            "lone-surrogate-and-nfc-collision",
            knobe(FM, "", &obj("\"caf\u{e9}\":\"1\",\"cafe\u{301}\":\"2\",\"a\":\"\\ud800\"")),
        ),
        ("lone-surrogate-then-dup-key", knobe(FM, "", &obj(r#""x":"\ud800","x":"2""#))),
        // Distinct unpaired surrogates, or one and a real U+FFFD, are distinct keys.
        ("lone-surrogate-keys-distinct", knobe(FM, "", &obj(r#""\ud800":"1","\udc00":"2""#))),
        ("lone-surrogate-key-and-replacement-char", knobe(FM, "", &obj(r#""\ud800":"1","\ufffd":"2""#))),
        ("lone-surrogate-then-syntax-error", knobe(FM, "", r#"{"x":"\ud800",}"#)),
        ("lone-high-surrogate-then-pair", knobe(FM, "", &obj(r#""x":"\ud800\ud83d\ude00""#))),
        ("payload-top-level-lone-surrogate", knobe(FM, "", r#""\ud800""#)),
        ("surrogate-pair-escaped", knobe(FM, "", &obj(r#""x":"\ud83d\ude00""#))),
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
        // Proposed ERRATA E13: a quoted key, or a value that is empty or
        // whitespace once its quotes are stripped, is not a declaration.
        ("fm-spec-quoted-key", knobe("---\n\"spec_version\": \"1.0\"\n---\n", "", &obj(""))),
        ("fm-spec-quoted-empty", knobe("---\nspec_version: \"\"\n---\n", "", &obj(""))),
        ("fm-spec-quoted-whitespace", knobe("---\nspec_version: \" \u{3000} \"\n---\n", "", &obj(""))),
        // --- where the body starts (proposed ERRATA E14): the opening delimiter is line 1 ---
        ("fm-preamble-with-body-rules", knobe(&format!("Preamble line.\n{FM}"), rules, &obj(bh))),
        ("fm-bom-with-body-rules", knobe(&format!("\u{feff}{FM}"), rules, &obj(bh))),
        ("fm-missing-with-body-rules", knobe("", rules, &obj(bh))),
        ("fm-blank-first-line-with-body", knobe(&format!("\n{FM}"), body, &obj(bh))),
        ("fm-closing-double-cr-with-body", knobe("---\nspec_version: 1.0\n---\r\r\n", body, &obj(bh))),
        // Positive control: rules in the body of a well-formed file are body.
        ("body-with-two-rules", knobe(FM, rules, &obj(bh))),
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
        (
            "block-internal-file-separators",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}\u{1c}\u{1d}\u{1e}\u{1f}{}\n-----END KNOBE B64-----\n",
                &good_b64[..8],
                &good_b64[8..]
            )),
        ),
        (
            "block-internal-line-separator",
            raw(format!("{FM}\n-----BEGIN KNOBE B64-----\n{good_b64}\u{2028}\n-----END KNOBE B64-----\n")),
        ),
        (
            "block-internal-crlf-wrapped",
            raw(format!(
                "{FM}\n-----BEGIN KNOBE B64-----\n{}\n-----END KNOBE B64-----\n",
                wrap(&good_b64).replace('\n', "\r\n")
            )),
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
    // Nesting limits. lens.py's lone-surrogate walk reaches 498 levels below
    // the payload: a value or key at 499 is a RecursionError, reported with no
    // blocks. CPython 3.13's json.loads accepts containers 9997 levels deep;
    // scalars do not count.
    let deep = |n: usize, inner: &str| format!(r#""x":{}"#, nest(n, inner));
    c.extend([
        ("deep-nesting-498", knobe(FM, "", &obj(&deep(498, "")))),
        ("deep-nesting-499", knobe(FM, "", &obj(&deep(499, "")))),
        ("deep-number-leaf-498", knobe(FM, "", &obj(&deep(497, "0")))),
        ("deep-number-leaf-499", knobe(FM, "", &obj(&deep(498, "0")))),
        ("deep-string-leaf-499", knobe(FM, "", &obj(&deep(498, r#""s""#)))),
        ("deep-empty-object-498", knobe(FM, "", &obj(&deep(497, "{}")))),
        ("deep-object-key-499", knobe(FM, "", &obj(&deep(497, r#"{"k":"v"}"#)))),
        ("deep-in-payload-hash", knobe(FM, "", &obj("").replace("\"__H__\"", &nest(499, "")))),
        ("lone-surrogate-before-deep", knobe(FM, "", &obj(&format!(r#""a":"\ud800",{}"#, deep(499, ""))))),
        ("deep-before-lone-surrogate", knobe(FM, "", &obj(&format!(r#"{},"a":"\ud800""#, deep(499, ""))))),
        ("deep-and-dup-key", knobe(FM, "", &obj(&format!(r#"{},"x":"1""#, deep(499, ""))))),
        ("top-level-list-deep", knobe(FM, "", &nest(600, ""))),
        ("deep-nesting-9997", knobe(FM, "", &obj(&deep(9997, "")))),
        ("deep-nesting-9997-scalar-leaf", knobe(FM, "", &obj(&deep(9997, "0")))),
        ("deep-nesting-9998", knobe(FM, "", &obj(&deep(9998, "")))),
        ("deep-nesting-9998-then-dup-key", knobe(FM, "", &obj(&format!(r#"{},"x":"1""#, deep(9998, ""))))),
        ("top-level-list-9998", knobe(FM, "", &nest(9998, ""))),
        ("top-level-list-9999", knobe(FM, "", &nest(9999, ""))),
        // A node that needs one of lens.py's Python hooks (an object, a float,
        // NaN/Infinity) stops two levels earlier. In a top-level list, a
        // parsed payload reads "not a JSON object", a failed one "could not
        // be decoded or parsed".
        ("deep-object-9995", knobe(FM, "", &nest(9995, "{}"))),
        ("deep-object-9996", knobe(FM, "", &nest(9996, "{}"))),
        ("deep-object-dup-key-9994", knobe(FM, "", &nest(9994, r#"{"a":1,"a":2}"#))),
        ("deep-object-dup-key-9995", knobe(FM, "", &nest(9995, r#"{"a":1,"a":2}"#))),
        ("deep-object-dup-key-9996", knobe(FM, "", &nest(9996, r#"{"a":1,"a":2}"#))),
        ("deep-float-9995", knobe(FM, "", &nest(9995, "1.5"))),
        ("deep-float-9996", knobe(FM, "", &nest(9996, "1.5"))),
        ("deep-nan-9995", knobe(FM, "", &nest(9995, "NaN"))),
        ("deep-nan-9996", knobe(FM, "", &nest(9996, "NaN"))),
        ("deep-int-9998", knobe(FM, "", &nest(9998, "1"))),
    ]);
    // lens.py reports CPython's UnicodeDecodeError text, position included.
    let not_utf8 = |tail: &[u8]| [FM.as_bytes(), tail].concat();
    c.extend([
        ("file-not-utf8", not_utf8(&[0xc3, 0x28])),
        ("file-invalid-start-byte", not_utf8(&[0xff, b'x'])),
        ("file-overlong", not_utf8(&[0xc0, 0xaf])),
        ("file-surrogate-bytes", not_utf8(&[0xed, 0xa0, 0x80])),
        ("file-bad-third-byte", not_utf8(&[0xe2, 0x82, 0x28])),
        ("file-bad-fourth-byte", not_utf8(&[0xf0, 0x9f, 0x98, 0x28])),
        ("file-truncated-sequence", not_utf8(&[0xe2, 0x82])),
        ("file-truncated-four-byte", not_utf8(&[0xf0, 0x9f, 0x98])),
    ]);
    c.push(("file-empty", Vec::new()));
    c
}

/// `inner` wrapped in `n` JSON arrays.
fn nest(n: usize, inner: &str) -> String {
    format!("{}{inner}{}", "[".repeat(n), "]".repeat(n))
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
    ("fm-bom", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-whitespace-only", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-empty", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-after-close-ignored", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-not-prefix", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-quoted-key", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-quoted-empty", "I-1", "verified", Some("omitted"), "invalid"),
    ("fm-spec-quoted-whitespace", "I-1", "verified", Some("omitted"), "invalid"),
];

/// Cases where knobe-rs prints what lens.py prints once it has the display
/// fixes proposed upstream (KnobeOne/knobe-protocol, patch series
/// 3-display-escaping). Without them, lens.py crashes on unpaired surrogates
/// and prints bidi controls, stored_hash and issues raw, so these differ:
/// in both reports (`true`), or in the human report only (`false`).
const PENDING_UPSTREAM: &[(&str, bool)] = &[
    ("dup-key-bidi", true),
    ("dup-key-line-separator", true),
    ("dup-key-surrogate", true),
    ("dup-key-surrogate-in-text", true),
    ("dup-key-surrogate-nested", true),
    ("dup-key-long", true),
    ("spec-version-bidi", true),
    ("payload-hash-trailing-newline", false),
    ("stored-ansi", false),
    ("stored-c1", false),
    ("stored-bidi", false),
    ("stored-long-string", false),
    ("stored-long-list", false),
    ("title-bidi", false),
    ("privacy-level-bidi", false),
    ("numeric-key-escape", false),
];

/// Whether `name` may differ from the lens.py under test: true for a
/// PENDING_UPSTREAM case that differs in this report (`json`: the --json one)
/// while lens.py lacks the display patch.
fn pending(name: &str, json: bool) -> bool {
    !common::lens_has_display_patch() && PENDING_UPSTREAM.iter().any(|&(n, both)| n == name && (both || !json))
}

/// Writes every hostile case this python3 can arbitrate into `dir`.
fn write_hostile_files(dir: &str) -> Vec<(&'static str, PathBuf)> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cases = hostile_cases();
    assert_eq!(cases.len(), 211, "update the README if the battery size changes");
    eprintln!("python3 is {}; lens.py display patch: {}", common::python_version(), common::lens_has_display_patch());
    cases
        .into_iter()
        .filter(|(name, _)| !common::skip_on_this_python(name))
        .map(|(name, bytes)| {
            let path = dir.join(format!("{name}.knobe.md"));
            std::fs::write(&path, bytes).unwrap();
            (name, path)
        })
        .collect()
}

#[test]
fn hostile_battery_matches_lens_py_except_documented_spec_cases() {
    let mut diffs = Vec::new();
    let files = write_hostile_files("hostile");
    for (name, path) in files.iter().filter(|(name, _)| !pending(name, true)) {
        let Some(py) = common::lens(path) else {
            diffs.push(format!("{name}: lens.py produced no JSON report"));
            continue;
        };
        let rs = common::rust(path);
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
    assert!(diffs.is_empty(), "{} of {} hostile cases disagree:\n{}", diffs.len(), files.len(), diffs.join("\n"));
}

// ---------------------------------------------------------------------------
// Complete output, byte for byte
// ---------------------------------------------------------------------------

/// Every published file, named by its path below the protocol checkout.
fn published_files() -> Vec<(String, PathBuf)> {
    let root = common::protocol_dir();
    common::corpus().into_iter().map(|f| (f.strip_prefix(&root).unwrap().display().to_string(), f)).collect()
}

/// The `--json` document without the conformance fields, which is all a
/// spec-over-reference case may differ in.
fn without_conformance(stdout: &[u8]) -> Value {
    let text = String::from_utf8_lossy(stdout);
    let doc = knobe::json::parse(&text).unwrap_or_else(|e| panic!("--json is not JSON ({e}): {text}"));
    let Value::Object(members) = doc else { panic!("--json is not an object: {text}") };
    Value::Object(members.into_iter().filter(|(k, _)| !k.starts_with("conformance")).collect())
}

/// The gate fields above are what upstream's harness compares. This goes
/// further: the complete `knobe verify --json` output (every conformance
/// issue and the unreadable reason included) and the exit code must be
/// byte-identical to `lens.py --json`'s, so a change to upstream wording or
/// check order fails here too. The spec-over-reference cases must differ:
/// I-1 cases only in conformance and its issues (and so in the exit code).
/// So must the pending ones while lens.py lacks the display patch.
#[test]
fn full_json_output_is_byte_identical_to_lens_py() {
    let mut files: Vec<(String, PathBuf)> =
        write_hostile_files("hostile-json").into_iter().map(|(n, p)| (n.to_string(), p)).collect();
    files.extend(published_files());
    let mut diffs = Vec::new();
    for (name, path) in &files {
        let (py, py_code) = common::lens_cli(&["--json"], path);
        let (rs, rs_code) = common::knobe_cli(&["--json"], path);
        let same = py == rs && py_code == rs_code;
        if pending(name, true) {
            if same {
                diffs.push(format!("{name}: pending upstream, yet lens.py agrees; update PENDING_UPSTREAM"));
            }
            continue;
        }
        match SPEC_OVER_REFERENCE.iter().find(|c| c.0 == name.as_str()) {
            Some((_, rule, ..)) if same => diffs.push(format!("{name} ({rule}): lens.py now agrees")),
            // I-1 changes only conformance; the gate battery pins the result.
            Some((_, rule, ..)) if *rule == "I-1" && without_conformance(&py) != without_conformance(&rs) => {
                diffs.push(format!("{name} ({rule}): differs beyond conformance"))
            }
            None if !same => diffs.push(format!(
                "{name}: exit {py_code} vs {rs_code}\n--- lens.py\n{}--- knobe\n{}",
                String::from_utf8_lossy(&py),
                String::from_utf8_lossy(&rs)
            )),
            _ => {}
        }
    }
    eprintln!("compared {} files", files.len());
    assert!(diffs.is_empty(), "{} of {} files differ:\n{}", diffs.len(), files.len(), diffs.join("\n"));
}

/// The human report (`knobe verify FILE`) and exit code are byte-identical to
/// `python3 lens.py FILE`'s too, on every published and hostile file except
/// the spec-over-reference and pending ones, which must differ.
#[test]
fn human_output_is_byte_identical_to_lens_py() {
    let mut files: Vec<(String, PathBuf)> =
        write_hostile_files("hostile-human").into_iter().map(|(n, p)| (n.to_string(), p)).collect();
    files.extend(published_files());
    let mut diffs = Vec::new();
    for (name, path) in &files {
        let (py, py_code) = common::lens_cli(&[], path);
        let (rs, rs_code) = common::knobe_cli(&[], path);
        let same = py == rs && py_code == rs_code;
        let spec = SPEC_OVER_REFERENCE.iter().find(|c| c.0 == name.as_str()).map(|c| c.1);
        match spec.or_else(|| pending(name, false).then_some("pending upstream")) {
            Some(why) if same => diffs.push(format!("{name} ({why}): lens.py now agrees")),
            None if !same => diffs.push(format!(
                "{name}: exit {py_code} vs {rs_code}\n--- lens.py\n{}--- knobe\n{}",
                String::from_utf8_lossy(&py),
                String::from_utf8_lossy(&rs)
            )),
            _ => {}
        }
    }
    assert!(diffs.is_empty(), "{} of {} files differ:\n{}", diffs.len(), files.len(), diffs.join("\n"));
}

/// File names lens.py can hold only as surrogates (bytes that are not UTF-8)
/// or that carry control and bidi characters: the reasons quote the path.
/// Unpatched lens.py crashes on some of these and prints others raw.
#[cfg(unix)]
#[test]
fn file_name_reasons_are_byte_identical_to_lens_py() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("paths");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = |name: &[u8]| dir.join(std::ffi::OsStr::from_bytes(name));
    let baseline = knobe(FM, "", &obj(""));
    std::fs::write(path(b"exists-\xff.knobe.md"), &baseline).unwrap();
    std::fs::write(path(b"plain"), "x").unwrap();
    std::fs::create_dir_all(path(b"dir-\xff\xed\xa0\x80")).unwrap();
    std::fs::write(path(b"noperm-\xff"), &baseline).unwrap();
    std::fs::set_permissions(path(b"noperm-\xff"), std::fs::Permissions::from_mode(0o000)).unwrap();
    // As root the mode-000 file is readable: nothing to compare then.
    let root = std::fs::read(path(b"noperm-\xff")).is_ok();
    // (name, the case's file name, pending: unpatched lens.py differs)
    let cases: &[(&str, &[u8], bool)] = &[
        ("missing-not-utf8", b"missing-\xff\xc3.knobe.md", true),
        ("missing-ansi", b"missing-\x1b[31m.knobe.md", true),
        ("missing-bidi", "missing-\u{202e}\u{2028}.knobe.md".as_bytes(), true),
        ("directory-not-utf8", b"dir-\xff\xed\xa0\x80", true),
        ("exists-not-utf8", b"exists-\xff.knobe.md", false),
        ("not-a-directory", b"plain/it's-\xff", false),
        ("no-permission", b"noperm-\xff", false),
    ];
    let mut diffs = Vec::new();
    for &(name, file, is_pending) in cases {
        if name == "no-permission" && root {
            eprintln!("{name}: skipped, running as root");
            continue;
        }
        for args in [&["--json"][..], &[][..]] {
            let (py, py_code) = common::lens_cli(args, &path(file));
            let (rs, rs_code) = common::knobe_cli(args, &path(file));
            let same = py == rs && py_code == rs_code;
            if is_pending && !common::lens_has_display_patch() {
                if same {
                    diffs.push(format!("{name} {args:?}: pending upstream, yet lens.py agrees"));
                }
            } else if !same {
                diffs.push(format!(
                    "{name} {args:?}: exit {py_code} vs {rs_code}\n--- lens.py\n{}--- knobe\n{}",
                    String::from_utf8_lossy(&py),
                    String::from_utf8_lossy(&rs)
                ));
            }
        }
    }
    std::fs::set_permissions(path(b"noperm-\xff"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(diffs.is_empty(), "{} differ:\n{}", diffs.len(), diffs.join("\n"));
}

/// repr() escapes what CPython's str.isprintable() rejects; knobe carries
/// that table (src/pyprintable.rs), generated from CPython 3.13.
#[test]
fn printable_table_matches_cpython() {
    if common::python_version() != "3.13" {
        eprintln!("skipped: the table is CPython 3.13's and python3 is {}", common::python_version());
        return;
    }
    let out = Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/gen_pyprintable.py"))
        .output()
        .expect("python3");
    assert!(out.status.success());
    let ours = include_str!("../src/pyprintable.rs");
    assert!(out.stdout == ours.as_bytes(), "src/pyprintable.rs is stale: rerun tests/support/gen_pyprintable.py");
}

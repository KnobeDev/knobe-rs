//! The published test vectors and their expected results, read from the
//! tables in test-vectors/README.md, adversarial/README.md and
//! interpretation/README.md of the protocol checkout. Reading the tables,
//! rather than a copy, means a vector published upstream is checked against
//! its published result on the next run. Reproducing the core nine is the bar
//! for "canonically compatible with KNOBE v1".

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use knobe::verify_path;

/// The conformance bar; the README tables must list all nine.
const CORE_NINE: &[&str] = &[
    "minimal-valid.knobe.md",
    "full-valid.knobe.md",
    "body-modified.knobe.md",
    "payload-modified.knobe.md",
    "unreadable.knobe.md",
    "unicode-valid.knobe.md",
    "numeric-violation.knobe.md",
    "omitted-body-hash.knobe.md",
    "multi-block.knobe.md",
];

/// One row of a published expected-results table. `file` is relative to
/// test-vectors/, with forward slashes. `body` is None where the table has no
/// body_verified column (the core nine), and Some("—") for the omitted that
/// unreadable files report.
struct Expectation {
    file: String,
    status: String,
    body: Option<String>,
    conformance: String,
}

fn published_expected(vectors: &Path) -> Vec<Expectation> {
    let mut out = Vec::new();
    for (dir, has_body) in [("", false), ("adversarial", true), ("interpretation", true)] {
        let readme = vectors.join(dir).join("README.md");
        let text = std::fs::read_to_string(&readme).unwrap_or_else(|e| panic!("{}: {e}", readme.display()));
        for line in text.lines() {
            let Some((file, rest)) = line.strip_prefix("| `").and_then(|r| r.split_once('`')) else {
                continue;
            };
            if !file.ends_with(".knobe.md") {
                continue;
            }
            // "verified (last block)" and "valid (where readable)" keep the first word.
            let cells: Vec<&str> = rest.split('|').skip(1).map(|c| c.split_whitespace().next().unwrap_or("")).collect();
            let file = if dir.is_empty() { file.to_string() } else { format!("{dir}/{file}") };
            let row = match (has_body, cells.as_slice()) {
                (true, [status, body, conformance, ..]) => Expectation {
                    file,
                    status: status.to_string(),
                    body: Some(body.to_string()),
                    conformance: conformance.to_string(),
                },
                (false, [status, conformance, ..]) => {
                    Expectation { file, status: status.to_string(), body: None, conformance: conformance.to_string() }
                }
                _ => panic!("{}: cannot read the expected-results row {line:?}", readme.display()),
            };
            let blank_body = row.body.as_deref().is_some_and(str::is_empty);
            assert!(
                !row.status.is_empty() && !row.conformance.is_empty() && !blank_body,
                "{}: blank cell in the expected-results row {line:?}",
                readme.display()
            );
            out.push(row);
        }
    }
    out
}

/// Every .knobe.md under `dir`. A directory that cannot be listed fails the
/// test, so no vector drops out of the completeness check unseen.
fn vector_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
    for entry in entries {
        let p = entry.unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display())).path();
        if p.is_dir() {
            out.extend(vector_files(&p));
        } else if p.to_string_lossy().ends_with(".knobe.md") {
            out.push(p);
        }
    }
    out
}

#[test]
fn every_published_vector_matches_its_expected_result() {
    let dir = common::protocol_dir().join("test-vectors");
    let rows = published_expected(&dir);
    let listed: BTreeSet<&str> = rows.iter().map(|r| r.file.as_str()).collect();
    let mut failures = Vec::new();
    for want in &rows {
        let path = dir.join(&want.file);
        if !path.is_file() {
            failures.push(format!("{}: listed in the README but missing", want.file));
            continue;
        }
        let r = verify_path(&path);
        let got_body = r.body_verified.map(|b| b.as_str());
        let body_ok = match want.body.as_deref() {
            None => true,
            Some("—") => got_body.is_none(),
            Some(b) => got_body == Some(b),
        };
        if r.state.as_str() != want.status || r.conformance.as_str() != want.conformance || !body_ok {
            failures.push(format!(
                "{}: want {}/{:?}/{}, got {}/{got_body:?}/{} ({:?})",
                want.file,
                want.status,
                want.body,
                want.conformance,
                r.state.as_str(),
                r.conformance.as_str(),
                r.conformance_issues
            ));
        }
    }
    for core in CORE_NINE {
        if !listed.contains(core) {
            failures.push(format!("the README tables do not list the core vector {core}"));
        }
    }
    // Every published vector must have a published expected result.
    for p in vector_files(&dir) {
        let rel = p.strip_prefix(&dir).unwrap().to_string_lossy().replace('\\', "/");
        if !listed.contains(rel.as_str()) {
            failures.push(format!("{rel} has no expected result in the test-vectors READMEs"));
        }
    }
    assert!(failures.is_empty(), "vector mismatches:\n{}", failures.join("\n"));
}

#[test]
fn unreadable_vectors_exit_2_and_verified_valid_exit_0() {
    let dir = common::protocol_dir().join("test-vectors");
    assert_eq!(verify_path(&dir.join("unreadable.knobe.md")).exit_code(), 2);
    assert_eq!(verify_path(&dir.join("minimal-valid.knobe.md")).exit_code(), 0);
    assert_eq!(verify_path(&dir.join("numeric-violation.knobe.md")).exit_code(), 1);
    assert_eq!(verify_path(&dir.join("payload-modified.knobe.md")).exit_code(), 1);
}

#[test]
fn missing_file_is_unreadable_not_a_panic() {
    let r = verify_path(std::path::Path::new("/definitely/not/here.knobe.md"));
    assert_eq!(r.state.as_str(), "unreadable");
    assert_eq!(r.exit_code(), 2);
}

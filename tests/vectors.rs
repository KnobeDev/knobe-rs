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
/// test-vectors/, with forward slashes. `body` is "—" for the omitted that
/// unreadable files report.
struct Expectation {
    file: String,
    status: String,
    body: String,
    conformance: String,
}

/// The cells of a Markdown table row, split on unescaped pipes, or None for
/// a line that is not a table row.
fn table_cells(line: &str) -> Option<Vec<&str>> {
    let row = line.trim().strip_prefix('|')?;
    let mut cells = Vec::new();
    let (mut start, mut escaped) = (0, false);
    for (i, c) in row.char_indices() {
        match c {
            // The character after a backslash is literal, `\|` included.
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '|' => {
                cells.push(row[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = row[start..].trim();
    if !last.is_empty() {
        cells.push(last); // a row without a closing pipe
    }
    Some(cells)
}

/// The index of the header cell `name` or `expected <name>` (case-insensitive).
fn column(header: &[&str], name: &str) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.to_ascii_lowercase();
        h == name || h.strip_prefix("expected ") == Some(name)
    })
}

/// Every row that names a `.knobe.md` file, from each table in the three
/// READMEs. The status, body_verified and conformance columns are found by
/// their header, which every table has had since knobe-protocol PR #30
/// (8d664d3). A table starts at its header row (a first cell of `file`, or
/// the first row after a non-table line) and ends at the next non-table line
/// or header row.
fn published_expected(vectors: &Path) -> Vec<Expectation> {
    let mut out = Vec::new();
    for dir in ["", "adversarial", "interpretation"] {
        let readme = vectors.join(dir).join("README.md");
        let text = std::fs::read_to_string(&readme).unwrap_or_else(|e| panic!("{}: {e}", readme.display()));
        let mut header: Option<Vec<&str>> = None;
        for line in text.lines() {
            let Some(cells) = table_cells(line) else {
                header = None;
                continue;
            };
            let is_header = cells.first().is_some_and(|c| c.eq_ignore_ascii_case("file"));
            let head = match &header {
                Some(head) if !is_header => head,
                _ => {
                    header = Some(cells);
                    continue;
                }
            };
            let Some(file) =
                cells.first().and_then(|c| c.strip_prefix('`')?.strip_suffix('`')).filter(|f| f.ends_with(".knobe.md"))
            else {
                continue; // the separator row, or a row that names no vector
            };
            assert!(
                cells.len() == head.len(),
                "{}: row has {} cells, header {}: {line:?}",
                readme.display(),
                cells.len(),
                head.len()
            );
            let at = |name: &str| {
                let i = column(head, name).unwrap_or_else(|| {
                    panic!(
                        "{}: the table listing {file} has no {name} column (upstream added body_verified \
                         to every table in PR #30; use a checkout at 8d664d3 or later)",
                        readme.display()
                    )
                });
                // "verified (last block)" and "valid (where readable)" keep the first word.
                let cell = cells[i].split_whitespace().next().unwrap_or("");
                assert!(!cell.is_empty(), "{}: blank {name} cell in the row {line:?}", readme.display());
                cell.to_string()
            };
            out.push(Expectation {
                file: if dir.is_empty() { file.to_string() } else { format!("{dir}/{file}") },
                status: at("status"),
                body: at("body_verified"),
                conformance: at("conformance"),
            });
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
        let body_ok = match want.body.as_str() {
            "—" => got_body.is_none(),
            b => got_body == Some(b),
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

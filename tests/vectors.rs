//! The published test vectors and their expected results, transcribed from
//! test-vectors/README.md, adversarial/README.md and interpretation/README.md.
//! Reproducing these is the bar for "canonically compatible with KNOBE v1".

mod common;

use knobe::verify_path;

/// (file, status, body_verified or None when the README leaves it open, conformance)
const EXPECTED: &[(&str, &str, Option<&str>, &str)] = &[
    // Core six + additional three
    ("minimal-valid.knobe.md", "verified", None, "valid"),
    ("full-valid.knobe.md", "verified", None, "valid"),
    ("body-modified.knobe.md", "verified-body-modified", Some("modified"), "valid"),
    ("payload-modified.knobe.md", "failed", None, "valid"),
    ("unreadable.knobe.md", "unreadable", None, "invalid"),
    ("unicode-valid.knobe.md", "verified", None, "valid"),
    ("numeric-violation.knobe.md", "verified", None, "invalid"),
    ("omitted-body-hash.knobe.md", "verified", Some("omitted"), "valid"),
    ("multi-block.knobe.md", "verified", Some("omitted"), "warnings"),
    // Adversarial hardening set
    ("adversarial/bad-attribution-sources-type.knobe.md", "verified", Some("omitted"), "invalid"),
    ("adversarial/bad-body-hash-format.knobe.md", "verified-body-modified", Some("modified"), "invalid"),
    ("adversarial/bad-created-date.knobe.md", "verified", Some("omitted"), "invalid"),
    ("adversarial/control-character-title.knobe.md", "verified", Some("omitted"), "valid"),
    ("adversarial/duplicate-key.knobe.md", "unreadable", None, "invalid"),
    ("adversarial/multi-block-warning.knobe.md", "verified", Some("omitted"), "warnings"),
    ("adversarial/nfc-key-collision.knobe.md", "unreadable", None, "invalid"),
    ("adversarial/no-frontmatter-valid-payload.knobe.md", "verified", Some("omitted"), "invalid"),
    ("adversarial/payload-array.knobe.md", "unreadable", None, "invalid"),
    ("adversarial/unsupported-spec-version.knobe.md", "unreadable", None, "invalid"),
    // Interpretation set (ERRATA rulings)
    ("interpretation/astral-unicode-literal.knobe.md", "verified", Some("omitted"), "valid"),
    ("interpretation/attribution-missing.knobe.md", "verified", Some("omitted"), "invalid"),
    ("interpretation/base64-unpadded.knobe.md", "unreadable", None, "invalid"),
    ("interpretation/begin-marker-mid-line.knobe.md", "verified", Some("yes"), "valid"),
    ("interpretation/boolean-null-values.knobe.md", "verified", Some("omitted"), "valid"),
    ("interpretation/spec-version-frontmatter-mismatch.knobe.md", "verified", Some("omitted"), "warnings"),
];

#[test]
fn every_published_vector_matches_its_expected_result() {
    let dir = common::protocol_dir().join("test-vectors");
    let mut failures = Vec::new();
    for (file, status, body, conformance) in EXPECTED {
        let r = verify_path(&dir.join(file));
        let got_body = r.body_verified.map(|b| b.as_str());
        if r.state.as_str() != *status
            || r.conformance.as_str() != *conformance
            || body.is_some_and(|b| got_body != Some(b))
        {
            failures.push(format!(
                "{file}: want {status}/{body:?}/{conformance}, got {}/{got_body:?}/{} ({:?})",
                r.state.as_str(),
                r.conformance.as_str(),
                r.conformance_issues
            ));
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

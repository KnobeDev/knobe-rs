//! Shared helpers for integration tests: locating the pinned protocol checkout
//! and running the reference verifier (lens.py) and sibling engine
//! (knobe-core.js) for differential comparison.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use knobe::Value;

/// The pinned KNOBE Protocol checkout. Override with KNOBE_PROTOCOL_DIR.
pub fn protocol_dir() -> PathBuf {
    let dir = std::env::var_os("KNOBE_PROTOCOL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../knobe-protocol"));
    assert!(
        dir.join("lens.py").is_file(),
        "KNOBE protocol checkout not found at {} (set KNOBE_PROTOCOL_DIR)",
        dir.display()
    );
    dir
}

/// Every published .knobe.md: test vectors (all sets), examples, and site copies.
pub fn corpus() -> Vec<PathBuf> {
    let root = protocol_dir();
    let mut out = Vec::new();
    for sub in ["test-vectors", "examples", "site"] {
        walk(&root.join(sub), &mut out);
    }
    out.sort();
    assert!(!out.is_empty(), "no .knobe.md files under {}", root.display());
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.to_string_lossy().ends_with(".knobe.md") {
            out.push(p);
        }
    }
}

/// The fields the upstream parity gate (knobe-core.selftest.mjs) compares.
#[derive(Debug, PartialEq)]
pub struct Gate {
    pub state: Value,
    pub conformance: Value,
    pub body_verified: Value,
    pub computed: Value,
    pub stored: Value,
    pub block_count: Value,
    pub multiple_blocks: Value,
    pub exit_code: i32,
}

pub fn gate_from_json(stdout: &str, exit_code: i32) -> Gate {
    let v = knobe::json::parse(stdout).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"));
    let get = |k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    Gate {
        state: get("state"),
        conformance: get("conformance"),
        body_verified: get("body_verified"),
        computed: get("computed"),
        stored: get("stored"),
        block_count: get("block_count"),
        multiple_blocks: get("multiple_blocks"),
        exit_code,
    }
}

/// Run `python3 lens.py --json FILE`. None if lens.py crashed (no JSON).
pub fn lens(file: &Path) -> Option<Gate> {
    let out = Command::new("python3")
        .arg(protocol_dir().join("lens.py"))
        .arg("--json")
        .arg(file)
        .output()
        .expect("python3 must be installed to run parity tests");
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.trim().is_empty() {
        return None;
    }
    Some(gate_from_json(&stdout, out.status.code().unwrap_or(-1)))
}

/// The Rust verifier, through the same JSON surface as lens.py.
pub fn rust(file: &Path) -> Gate {
    let r = knobe::verify_path(file);
    gate_from_json(&r.to_json(), r.exit_code())
}

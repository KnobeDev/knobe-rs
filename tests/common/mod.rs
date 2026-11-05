//! Shared helpers for integration tests: locating the pinned protocol checkout
//! and running the reference verifier (lens.py), the sibling engine
//! (knobe-core.js) and the `knobe` command for differential comparison.
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

/// Stdout and exit code of a finished command.
fn stdout_and_code(cmd: &mut Command) -> (Vec<u8>, i32) {
    let out = cmd.output().unwrap_or_else(|e| panic!("cannot run {cmd:?}: {e}"));
    (out.stdout, out.status.code().unwrap_or(-1))
}

/// `python3 lens.py [args] FILE`: stdout and exit code, byte for byte.
pub fn lens_cli(args: &[&str], file: &Path) -> (Vec<u8>, i32) {
    stdout_and_code(Command::new("python3").arg(protocol_dir().join("lens.py")).args(args).arg(file))
}

/// `knobe verify [args] FILE`, run as the built command: stdout and exit code.
pub fn knobe_cli(args: &[&str], file: &Path) -> (Vec<u8>, i32) {
    stdout_and_code(Command::new(env!("CARGO_BIN_EXE_knobe")).arg("verify").args(args).arg(file))
}

/// Whether the lens.py under test has the display fixes proposed upstream in
/// the patch series 3-display-escaping: safe() escapes bidi controls and
/// unpaired surrogates, and paths, issues and stored_hash go through it.
/// Until upstream merges them, the cases in PENDING_UPSTREAM may differ.
pub fn lens_has_display_patch() -> bool {
    static PATCHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PATCHED.get_or_init(|| {
        let check = "import sys; sys.path.insert(0, sys.argv[1]); import lens; \
                     print(lens.safe('\\u202e\\ud800') == '\\\\u202e\\\\ud800')";
        let out = Command::new("python3")
            .args(["-B", "-c", check])
            .arg(protocol_dir())
            .output()
            .expect("python3 must be installed to run parity tests");
        assert!(out.status.success(), "cannot load lens.py: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim() == "True"
    })
}

/// python3's "major.minor".
pub fn python_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        let out = Command::new("python3")
            .args(["-c", "import sys; print('%d.%d' % sys.version_info[:2])"])
            .output()
            .expect("python3 must be installed to run parity tests");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    })
}

/// Hostile cases whose lens.py report depends on CPython 3.13's json.loads
/// recursion limits (3.12 stops one level earlier). CI runs Python 3.13;
/// elsewhere these cases are skipped, with a note.
const CPYTHON_313_ONLY: &[&str] = &[
    "deep-nesting-9997",
    "deep-nesting-9997-scalar-leaf",
    "deep-nesting-9998",
    "deep-nesting-9998-then-dup-key",
    "top-level-list-9998",
    "top-level-list-9999",
    "deep-object-9995",
    "deep-object-9996",
    "deep-object-dup-key-9994",
    "deep-object-dup-key-9995",
    "deep-object-dup-key-9996",
    "deep-float-9995",
    "deep-float-9996",
    "deep-nan-9995",
    "deep-nan-9996",
    "deep-int-9998",
];

/// Whether to skip `name` on this python3 (printing why).
pub fn skip_on_this_python(name: &str) -> bool {
    let skip = CPYTHON_313_ONLY.contains(&name) && python_version() != "3.13";
    if skip {
        eprintln!("{name}: skipped, its limit is CPython 3.13's and python3 is {}", python_version());
    }
    skip
}

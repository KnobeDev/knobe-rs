//! `knobe` command line: `verify` mirrors `python3 lens.py`, `seal` mirrors
//! knobe-core.js `createKnobe`.

use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use knobe::pyfmt::{safe, safe_str};
use knobe::verify::State;
use knobe::{CreateOptions, Report, Value, create_knobe, verify_path};

const USAGE: &str = "\
usage: knobe verify [--json] FILE.knobe.md
       knobe seal [--fields FIELDS.json|-] [--body BODY.md] [--author NAME] [--date YYYY-MM-DD] [-o OUT]
       knobe --help

verify  Report integrity (status) and spec conformance, exactly as lens.py does.
        Exit 0: verified/verified-body-modified and valid/warnings;
             1: failed, or conformance invalid; 2: unreadable or usage error.
seal    Create a sealed .knobe.md from payload fields (JSON object) and an
        optional markdown body; the file is self-verified before it is written.
        Missing fields get createKnobe's defaults. Exit 1 if refused, 2 on usage/IO errors.

A match proves integrity, not truth. A `valid` proves conformance, not truth.
Inspect before trusting.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            0
        }
        Some("verify") => cmd_verify(&args[1..]),
        Some("seal") => cmd_seal(&args[1..]),
        _ => usage_error(),
    };
    ExitCode::from(code)
}

fn usage_error() -> u8 {
    eprintln!("{USAGE}");
    2
}

fn cmd_verify(args: &[String]) -> u8 {
    let (as_json, rest) = match args.first().map(String::as_str) {
        Some("--json") => (true, &args[1..]),
        _ => (false, args),
    };
    let [file] = rest else { return usage_error() };
    let r = verify_path(Path::new(file));
    if as_json {
        println!("{}", r.to_json());
    } else {
        print_human(&r);
    }
    r.exit_code() as u8
}

/// lens.py `_print_human`.
fn print_human(r: &Report) {
    let issues = || {
        for issue in &r.conformance_issues {
            println!("  - {issue}");
        }
    };
    if r.state == State::Unreadable {
        println!("status:            unreadable ({})", safe_str(r.reason.as_deref().unwrap_or("None"), 300));
        println!("conformance:       {}", r.conformance.as_str());
        issues();
        return;
    }
    let p = r.payload.as_ref().expect("readable reports carry a payload");
    let field = |k: &str| safe(p.get(k).unwrap_or(&Value::Null));
    println!("title:             {}", field("title"));
    println!("spec_version:      {}", field("spec_version"));
    println!("quarantine_status: {}", field("quarantine_status"));
    println!("privacy_level:     {}", field("privacy_level"));
    println!("computed_hash:     {}", r.computed.as_deref().unwrap_or(""));
    println!("stored_hash:       {}", r.stored.as_ref().map(safe).unwrap_or_default());
    println!("status:            {}", r.state.as_str());
    if r.multiple_blocks() {
        println!(
            "WARNING:           multiple payload blocks present. Evaluated block {} of {} per spec §3.3.",
            r.block_used(),
            r.block_count
        );
    }
    println!("body_verified:     {}", r.body_verified.map_or("None", |b| b.as_str()));
    println!("conformance:       {}", r.conformance.as_str());
    issues();
    if matches!(r.state, State::Verified | State::VerifiedBodyModified) {
        println!("note: integrity verified. Integrity is not truth — inspect before trusting.");
    }
    if r.state == State::VerifiedBodyModified {
        println!("note: the markdown body differs from the sealed body. Inspect before relying on this version.");
    }
}

fn read_input(path: &str) -> Result<String, String> {
    let mut s = String::new();
    let res = if path == "-" {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|t| s = t)
    };
    res.map(|()| s).map_err(|e| format!("cannot read {path}: {e}"))
}

fn cmd_seal(args: &[String]) -> u8 {
    let mut opts = CreateOptions::default();
    let mut out: Option<String> = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let Some(val) = it.next() else { return usage_error() };
        let result = match flag.as_str() {
            "--fields" => read_input(val)
                .and_then(|t| knobe::json::parse(&t).map_err(|e| format!("{val}: invalid JSON: {e}")))
                .map(|f| opts.fields = f),
            "--body" => read_input(val).map(|b| opts.body = b),
            "--author" => {
                opts.author = Some(val.clone());
                Ok(())
            }
            "--date" => {
                opts.today = Some(val.clone());
                Ok(())
            }
            "-o" | "--output" => {
                out = Some(val.clone());
                Ok(())
            }
            _ => return usage_error(),
        };
        if let Err(e) = result {
            eprintln!("knobe seal: {e}");
            return 2;
        }
    }
    let created = match create_knobe(&opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("knobe seal: refused: {e}");
            return 1;
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(&path, &created.text) {
                eprintln!("knobe seal: cannot write {path}: {e}");
                return 2;
            }
            eprintln!("sealed {path}  payload_hash {}", created.payload_hash);
        }
        None => print!("{}", created.text),
    }
    0
}

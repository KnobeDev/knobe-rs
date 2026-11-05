//! `knobe` command line: `verify` mirrors `python3 lens.py`, `seal` mirrors
//! knobe-core.js `createKnobe`.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::panic::{self, UnwindSafe};
use std::path::Path;
use std::process::ExitCode;

use knobe::pyfmt::{py_str, safe, safe_str};
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
    // Arguments as the OS gives them: a file name need not be UTF-8.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    panic::set_hook(Box::new(report_panic));
    let code = match args.first().and_then(|a| a.to_str()) {
        Some("-h" | "--help") => {
            println!("{USAGE}");
            0
        }
        Some("verify") => cmd_verify(&args[1..]),
        // A panic (a bug) has been reported by the hook; exit as for an I/O error.
        Some("seal") => panic::catch_unwind(|| cmd_seal(&args[1..])).unwrap_or(2),
        _ => usage_error(),
    };
    ExitCode::from(code)
}

fn usage_error() -> u8 {
    eprintln!("{USAGE}");
    2
}

fn cmd_verify(args: &[OsString]) -> u8 {
    let (as_json, rest) = match args.first().and_then(|a| a.to_str()) {
        Some("--json") => (true, &args[1..]),
        _ => (false, args),
    };
    let [file] = rest else { return usage_error() };
    let r = verify_guarded(|| verify_path(Path::new(file)));
    if as_json {
        println!("{}", r.to_json());
    } else {
        print_human(&r);
    }
    r.exit_code() as u8
}

const PANIC_REASON: &str = "verifier error (panic); rejected";

/// The command-line guard lens.py has: hostile input must never end in a
/// stack trace. A panic (which would be a bug in knobe) is reported the way
/// lens.py reports an exception from `verify()`: unreadable, with no blocks.
fn verify_guarded(verify: impl FnOnce() -> Report + UnwindSafe) -> Report {
    panic::catch_unwind(verify).unwrap_or_else(|_| Report::unreadable(PANIC_REASON.into(), 0, None))
}

/// Panic hook: one escaped line on stderr for a bug report, instead of the
/// default message.
fn report_panic(info: &panic::PanicHookInfo<'_>) {
    let payload = info.payload();
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(no message)");
    let at = info.location().map(|l| format!(" at {}:{}", l.file(), l.line())).unwrap_or_default();
    eprintln!("knobe: internal error: {}{at}", safe_str(msg, 300));
}

/// lens.py `_print_human`.
fn print_human(r: &Report) {
    let issues = || {
        for issue in &r.conformance_issues {
            println!("  - {}", safe_str(issue, usize::MAX));
        }
    };
    if r.state == State::Unreadable {
        println!("status:            unreadable ({})", safe_str(r.reason.as_deref().unwrap_or("None"), 300));
        println!("conformance:       {}", r.conformance.as_str());
        issues();
        return;
    }
    let p = r.payload.as_ref().expect("readable reports carry a payload");
    let field = |k: &str| p.get(k).unwrap_or(&Value::Null);
    // lens.py shows the title with safe(), the others with safe(str()).
    let str_field = |k: &str| safe_str(&py_str(field(k)), 300);
    println!("title:             {}", safe(field("title")));
    println!("spec_version:      {}", str_field("spec_version"));
    println!("quarantine_status: {}", str_field("quarantine_status"));
    println!("privacy_level:     {}", str_field("privacy_level"));
    println!("computed_hash:     {}", r.computed.as_deref().unwrap_or(""));
    println!("stored_hash:       {}", r.stored.as_ref().map(|s| safe_str(&py_str(s), 300)).unwrap_or_default());
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

fn read_input(path: &OsStr) -> Result<String, String> {
    let mut s = String::new();
    let res = if path == "-" {
        std::io::stdin().read_to_string(&mut s).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|t| s = t)
    };
    res.map(|()| s).map_err(|e| format!("cannot read {}: {e}", Path::new(path).display()))
}

/// A text option's value, which must be UTF-8.
fn text_arg(flag: &str, val: &OsStr) -> Result<String, String> {
    val.to_str().map(str::to_string).ok_or_else(|| format!("{flag}: not valid UTF-8"))
}

fn cmd_seal(args: &[OsString]) -> u8 {
    let mut opts = CreateOptions::default();
    let mut out: Option<&OsStr> = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let Some(val) = it.next() else { return usage_error() };
        let result = match flag.to_str().unwrap_or_default() {
            "--fields" => read_input(val)
                .and_then(|t| {
                    knobe::json::parse(&t).map_err(|e| format!("{}: invalid JSON: {e}", Path::new(val).display()))
                })
                .map(|f| opts.fields = f),
            "--body" => read_input(val).map(|b| opts.body = b),
            "--author" => text_arg("--author", val).map(|a| opts.author = Some(a)),
            "--date" => text_arg("--date", val).map(|d| opts.today = Some(d)),
            "-o" | "--output" => {
                out = Some(val);
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
    match out.map(Path::new) {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &created.text) {
                eprintln!("knobe seal: cannot write {}: {e}", path.display());
                return 2;
            }
            eprintln!("sealed {}  payload_hash {}", path.display(), created.payload_hash);
        }
        None => print!("{}", created.text),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use knobe::verify::{Conformance, State};

    #[test]
    fn a_panic_is_reported_as_unreadable() {
        let r = verify_guarded(|| panic!("boom \u{1b}[31m"));
        assert_eq!((r.state, r.conformance, r.exit_code()), (State::Unreadable, Conformance::Invalid, 2));
        assert_eq!((r.reason.as_deref(), r.block_count), (Some(PANIC_REASON), 0));
        let json = r.to_json();
        assert!(json.contains("\"block_count\": 0") && json.contains("\"stored\": null"), "{json}");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_name_that_is_not_utf8_is_reported_not_a_crash() {
        use std::os::unix::ffi::OsStringExt;
        let name = OsString::from_vec(b"missing-\xff.knobe.md".to_vec());
        assert_eq!(cmd_verify(&[OsString::from("--json"), name.clone()]), 2);
        let r = verify_path(Path::new(&name));
        assert_eq!(r.reason.as_deref(), Some(r"file not found: missing-\udcff.knobe.md"));
    }

    #[test]
    fn reports_pass_through_the_guard() {
        let want = knobe::verify_bytes(b"no block here");
        assert_eq!(verify_guarded(|| knobe::verify_bytes(b"no block here")), want);
    }
}

# knobe-rs: a KNOBE verifier for Rust

A conformant **KNOBE Protocol v1** verifier, plus a sealer, written in Rust and maintained by KnobeDev. It reproduces every published test vector of [KnobeOne/knobe-protocol](https://github.com/KnobeOne/knobe-protocol): the nine conformance vectors, the ten adversarial vectors and the six interpretation vectors.

It is published on crates.io as [`knobe`](https://crates.io/crates/knobe), with API documentation on [docs.rs](https://docs.rs/knobe).

| Upstream | What this crate matches |
|---|---|
| `lens.py`, the reference verifier | The complete `--json` report and the human report, byte for byte, with the same exit code, on every published file, 202 crafted hostile files and 7 hostile file names. The exceptions are documented: two points where it follows the explicit spec text ([below](#where-it-follows-the-spec-text-over-lenspy)), and the display fixes proposed upstream ([Display](#display)). |
| `knobe-core.js` `createKnobe()`, the sealer | Byte for byte, apart from the refusals listed below |

> A match proves integrity, not truth. A `valid` proves conformance, not truth. Inspect before trusting.

## Install

```bash
cargo install knobe
```

This installs the `knobe` command. It needs Rust 1.85 or later.

To build from a clone of this repository instead, run `cargo build --release`. The command is then `./target/release/knobe`.

## Use

```bash
knobe verify --json path/to/file.knobe.md
```

```bash
knobe seal --fields fields.json --body body.md --author "Ada" -o out.knobe.md
```

`verify` prints the same report as `python3 lens.py` and uses the same exit codes:

| Exit code | Meaning |
|---|---|
| 0 | Integrity holds and the file conforms (with or without warnings) |
| 1 | The payload failed its hash, or conformance is invalid |
| 2 | The file is unreadable, or the command was used wrongly |

`seal` takes payload fields as a JSON object. Any missing field gets `createKnobe`'s default. The sealer verifies the finished file itself before writing it.

### As a library

```bash
cargo add knobe
```

```rust
use std::path::Path;

let report = knobe::verify_path(Path::new("file.knobe.md"));
println!("{} / {}", report.state.as_str(), report.conformance.as_str());
for issue in &report.conformance_issues {
    println!("{issue}");
}
```

The crate exports `verify_bytes`, `verify_path`, `create_knobe` and `seal`. The full API is on [docs.rs](https://docs.rs/knobe).

## Scope and limits

**What it does.**
- **Verifies `.knobe.md` files.** It reports integrity (`verified`, `verified-body-modified`, `failed`, `unreadable`), the body check (`yes`, `modified`, `omitted`) and conformance (`valid`, `warnings`, `invalid`), with each issue listed individually (spec §7).
- **Creates sealed files**, with `createKnobe`'s defaults and output.

It runs entirely locally: no network access, no account, no server.

**What it does not do.**
- **It does not establish truth or trust.** A `verified` result does not mean the content is true, the attribution is honest, consent was obtained, or the object is fit for any use. It does not authenticate identity: v1 attribution is self-declared. It does not grant trust: `quarantine_status` is the sender's claim, not your clearance.
- **It does not implement the rest of the KNOBE toolset:** derivation (`transformKnobe`), use-condition evaluation (`permits`), a reader view, or a GUI.
- **It does not check everything the spec describes.** Types of optional fields and SHOULD-level guidance go unchecked, as in `lens.py`. They are listed in [docs/INTERPRETATIONS.md](docs/INTERPRETATIONS.md#not-checked).
- **The sealer refuses some inputs `createKnobe` accepts**; see below.

## How it is tested

`cargo test` needs `python3` and `node`. It also needs a checkout of upstream `main` of the protocol at `../knobe-protocol`; set `KNOBE_PROTOCOL_DIR` to use a different location. The parity tests track upstream `main`, so an older checkout reports differences.

| Test | What it checks |
|---|---|
| `tests/vectors.rs` | All 25 published vectors against the expected results in their READMEs |
| `tests/lens_parity.rs` | Runs `lens.py` side by side with the built `knobe` command over every published `.knobe.md`, 202 crafted hostile files and 7 hostile file names. The complete `--json` output and the human report must be byte-identical, with the same exit code. The hostile files are hashed by an independent Python oracle (`tests/support/pyhash.py`), never by the code under test. 8 of them pin the spec-text cases below with explicit expected results. |
| `tests/seal_parity.rs` | Feeds the same requests to upstream `createKnobe` (Node) and to `create_knobe`, and requires byte-identical files. `lens.py` must then verify every sealed file. |
| `tests/hostile_scale.rs` | Resource bounds: payloads with 200,000 keys verify in linear time, 100,000 levels of nesting are rejected cleanly, and the deepest payload `lens.py` accepts verifies on a thread with Rust's default 2 MB stack. |

CI runs against upstream `main` with Python 3.13 on every push and weekly, so any upstream change that affects parity shows up immediately. Sixteen hostile cases depend on CPython 3.13's `json.loads` nesting limits (3.12 stops one level earlier); with another Python they are skipped, with a note.

Until upstream merges the display fixes ([Display](#display)), 20 cases are expected to differ from `lens.py`, and the tests require that they still do. The tests detect a `lens.py` that has the fixes; against it, every case must match. To run them that way, point `KNOBE_PROTOCOL_DIR` at a checkout with the patch series applied.

## Where it follows the spec text over lens.py

The steward's governance says that where reference behavior conflicts with explicit normative text, the text wins. knobe-rs does so on two points. None changes the verdict of any published vector or example. Each is quoted and argued in [docs/INTERPRETATIONS.md](docs/INTERPRETATIONS.md):

| | Spec text | knobe-rs |
|---|---|---|
| I-1 | §3.1: "spec_version MUST appear in the frontmatter" | A frontmatter block without it is `invalid` |
| I-4 | §6: the body follows "the second line containing exactly ---" | `---` lines are counted from the start of the file |

Two earlier points are now settled by ERRATA E12, and knobe-rs and `lens.py` agree on both: I-2, a hash followed by a newline is `invalid`; and I-3, a payload block has ASCII space, tab, CR and LF stripped, as both reference engines do. knobe-rs 0.1.0 stripped only CR and LF. E12 says those four characters "may be stripped". The steward's [grounds for the ruling](https://github.com/KnobeOne/knobe-protocol/pull/12#pullrequestreview-5775198306) call divergent verdicts between conforming verifiers a defect, so knobe-rs now strips the same set.

The same document lists every other interpretive choice and what settled it: test vectors, ERRATA rulings, or `lens.py` for serialization questions.

## Hostile input

Since upstream PR #11, `lens.py` reports hostile input as `unreadable` instead of crashing, and knobe-rs reports exactly what it reports, reason text included:

| Input | Reported as |
|---|---|
| A float that overflows to infinity, such as `1e400`, anywhere in the payload, `payload_hash` included | `unreadable`: non-JSON numeric constant |
| An integer of more than 4300 digits | `unreadable`: payload could not be decoded or parsed |
| A non-string `spec_version`, such as a list | `unreadable`: unsupported spec_version, shown as Python `str()` shows it |
| An unpaired surrogate escape such as `"\ud800"`, in a key or a value | `unreadable`, once the payload has parsed and proved to be an object |
| A value or key nested 499 or more levels below the payload | `unreadable`: `verifier error (RecursionError); rejected`, with a block count of 0 |
| Arrays nested more than 9997 levels below the payload, or an object, a float or NaN/Infinity more than 9995 levels below it (an object with a duplicate key, 9995 or more) | `unreadable`: payload could not be decoded or parsed |
| A file that is not UTF-8 | `unreadable`, with CPython's decoding error, position included |

The nesting limits come from CPython 3.13. `lens.py`'s lone-surrogate check spends two stack frames per level against Python's 1000-frame limit, and `json.loads` stops at its C recursion limit, two levels sooner for a node it hands to one of `lens.py`'s Python hooks. When a payload has several defects, knobe-rs reports the one `lens.py` reports: a duplicate key counts only once its object has closed, as in Python, so an error later in that object comes first.

knobe-rs is built never to crash on any input. Its parser keeps its own stack, so nesting costs heap, not call stack, and the recursive steps (hashing, checks, output) only ever see payloads `lens.py` can walk, at most 498 levels deep. Verifying one that deep needs about 250 KB of stack in a release build (700 KB in a debug build), well within Rust's default of 2 MB per thread. If you call the library on a thread with a custom stack size, give it at least 1 MB. As a last line of defense, as in `lens.py`, `knobe verify` would report an internal error as `unreadable` (`verifier error (panic); rejected`) rather than print a stack trace.

## Display

Every KNOBE verifier escapes text taken from a file before showing it, so that a crafted value cannot spoof the report. They did not all escape the same characters, and `lens.py` crashed on some text it could not print. knobe-rs 0.1.2 follows the fixes proposed upstream in a patch series for `lens.py` and `knobe-core.js` (not yet merged). The rules:

- **`safe()`** writes C0 and C1 controls and DEL as `\xNN`. It writes bidi overrides and isolates and the line and paragraph separators (U+202A to U+202E, U+2066 to U+2069, U+2028, U+2029) as `\uNNNN`, the set `knobe-core.js` already escaped, and an unpaired surrogate as `\udXXX`. Other characters, joiners and emoji included, are shown as they are.
- **Duplicate keys** with an unpaired surrogate are reported, not a crash: `payload contains duplicate JSON key: \ud800 (ambiguous; rejected)`.
- **File names** are shown as Python decodes them: a byte that is not UTF-8 appears as `\udcXX`. "File not found" and "path is a directory" go through `safe()`; any other read error is Python's error text, such as `[Errno 13] Permission denied: '/tmp/x\udcff.knobe.md'`.
- **The human report** shows `stored_hash` and every conformance issue through `safe()`.

No published file's output changes under these rules. Until upstream merges them, `lens.py` differs from knobe-rs on such input: it crashes on an unpaired surrogate in a duplicate key, or on a missing file whose name is not UTF-8, and prints the rest raw.

## Changes in 0.1.2

0.1.1 matched upstream's overflow and block-whitespace rules, but not the rest of PR #11's hostile-input handling. 0.1.2 matches it, and its tests now compare complete output rather than verdicts.

- **Check order.** The lone-surrogate check now runs after the parse and the object check, and before the NFC and `spec_version` checks, as in `lens.py`. In 0.1.1 the parser rejected an unpaired surrogate at once, so a later syntax error, a duplicate key, or a payload that is not an object was reported as a surrogate.
- **Nesting.** A value or key 499 or more levels deep is a `RecursionError`, with a block count of 0; containers parse up to 9997 levels. 0.1.1 verified payloads up to 512 levels deep and called deeper ones undecodable.
- **Duplicate keys** are reported when their object closes, so a later error in the same object wins.
- **Long integers.** More than 4300 digits is `unreadable`, as in Python. 0.1.1 accepted any length.
- **Messages.** A non-string `spec_version` is shown as Python `str()` shows it, cut at 300 characters, and so are the human report's `spec_version`, `quarantine_status` and `privacy_level` lines. A file that is not UTF-8 is reported with CPython's error text. `repr()` now escapes exactly what CPython 3.13 does, from its own table.
- **Display.** Escaping follows the rules proposed upstream ([Display](#display)): bidi controls and unpaired surrogates are escaped, file names are shown as Python shows them, and the human report escapes `stored_hash` and conformance issues.
- **Command-line guard.** `knobe verify` reports an internal error as `unreadable` instead of crashing. A file name that is not UTF-8 no longer crashes `knobe`: it is read as the OS gives it.
- **Library.** `json::parse_payload` parses as `lens.py` does and reports unpaired surrogates and excess nesting in `Parsed::scan`. `json::parse` behaves as in 0.1.1: it rejects unpaired surrogates and nesting deeper than 512 levels. `Report::unreadable` is public.
- **Tests.** The complete `--json` output and the human report are compared with `lens.py` byte for byte, through the built command, on every published file, on 202 hostile files (80 new) and on 7 hostile file names.

## Sealer refusals

The sealer refuses a few inputs rather than emit a file that would lose information or not fully verify:

| Input | `knobe seal` |
|---|---|
| An integer beyond ±(2^53−1), which a JavaScript number cannot hold exactly | Refuses: write the number as a string |
| Keys that collapse to the same key under NFC normalization | Refuses |
| Duplicate keys in the fields JSON | Refuses |
| A line break in any field written to the YAML frontmatter (`title`, `spec_version`, `content_type`, `license`, `created_date`) | Refuses |
| Anything whose result would not verify as `verified`, with body `yes` whenever a body was given | Refuses |

Every malformed payload, whatever its shape, is reported as `unreadable` (exit 2). Hostile input never crashes the verifier.

## Provenance

knobe-rs is maintained by Joshua Hori (KnobeDev). It is not an official or reference KNOBE implementation, and the KNOBE steward did not build, review or endorse it.

It was written with AI assistance (Claude) at the maintainer's direction. As the steward's [governance notes](https://github.com/KnobeOne/knobe-protocol/blob/main/GOVERNANCE.md) ask, the reliance on the reference engines is disclosed:
- **It was first built as a port of `lens.py` and `knobe-core.js`.**
- **It was then checked clause by clause against the specification text** (§3–§10). That check produced the spec-text rules above and the interpretation record.

The maintainer's own review of each interpretation is tracked by the checkboxes in [docs/INTERPRETATIONS.md](docs/INTERPRETATIONS.md).

## License

Apache-2.0, matching the upstream verifier code. This crate shares no code with upstream. See [NOTICE](NOTICE).

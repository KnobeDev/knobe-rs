# knobe-rs: a KNOBE verifier for Rust

A conformant **KNOBE Protocol v1** verifier, plus a sealer, written in Rust and maintained by KnobeDev. It reproduces every published test vector of [KnobeOne/knobe-protocol](https://github.com/KnobeOne/knobe-protocol): the nine conformance vectors, the ten adversarial vectors and the six interpretation vectors.

| Upstream | What this crate matches |
|---|---|
| `lens.py`, the reference verifier | `state`, `conformance`, `body_verified`, computed and stored hash, block count and exit code, on every published file. On four points it follows the explicit spec text where `lens.py` does not ([below](#where-it-follows-the-spec-text-over-lenspy)). |
| `knobe-core.js` `createKnobe()`, the sealer | Byte for byte, apart from the refusals listed below |

> A match proves integrity, not truth. A `valid` proves conformance, not truth. Inspect before trusting.

## Use

```bash
cargo build --release
```

```bash
./target/release/knobe verify --json path/to/file.knobe.md
```

```bash
./target/release/knobe seal --fields fields.json --body body.md --author "Ada" -o out.knobe.md
```

`verify` prints the same report as `python3 lens.py` and uses the same exit codes:

| Exit code | Meaning |
|---|---|
| 0 | Integrity holds and the file conforms (with or without warnings) |
| 1 | The payload failed its hash, or conformance is invalid |
| 2 | The file is unreadable, or the command was used wrongly |

`seal` takes payload fields as a JSON object. Any missing field gets `createKnobe`'s default. The sealer verifies the finished file itself before writing it.

As a library: `knobe::verify_bytes`, `knobe::verify_path`, `knobe::create_knobe`, `knobe::seal`.

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

`cargo test` needs `python3` and `node`. It also needs the protocol checkout at `../knobe-protocol`; set `KNOBE_PROTOCOL_DIR` to use a different location.

| Test | What it checks |
|---|---|
| `tests/vectors.rs` | All 25 published vectors against the expected results in their READMEs |
| `tests/lens_parity.rs` | Runs `lens.py --json` side by side over every published `.knobe.md` (all must agree) and 113 crafted hostile files, and compares every field the upstream parity gate compares. The hostile files are hashed by an independent Python oracle (`tests/support/pyhash.py`), never by the code under test. 13 of them pin the spec-text cases below with explicit expected results. |
| `tests/seal_parity.rs` | Feeds the same requests to upstream `createKnobe` (Node) and to `create_knobe`, and requires byte-identical files. `lens.py` must then verify every sealed file. |
| `tests/hostile_scale.rs` | Resource bounds: payloads with 200,000 keys verify in linear time, and 100,000 levels of nesting are rejected cleanly instead of overflowing the stack. |

CI runs against upstream `main` on every push and weekly, so any upstream change that affects parity shows up immediately.

## Where it follows the spec text over lens.py

The steward's governance says that where reference behavior conflicts with explicit normative text, the text wins. knobe-rs does so on four points. None changes the verdict of any published vector or example. Each is quoted and argued in [docs/INTERPRETATIONS.md](docs/INTERPRETATIONS.md):

| | Spec text | knobe-rs |
|---|---|---|
| I-1 | §3.1: "spec_version MUST appear in the frontmatter" | A frontmatter block without it is `invalid` |
| I-2 | §4.1: hashes are "exactly 64 lowercase hexadecimal characters" | A hash followed by a newline is `invalid` |
| I-3 | §3.3: "Line breaks within the Base64 block MUST be ignored" (RFC 4648 §3.3 rejects anything else) | Only CR and LF are ignored; other stray characters make the file `unreadable` |
| I-4 | §6: the body follows "the second line containing exactly ---" | `---` lines are counted from the start of the file |

The same document lists every other interpretive choice and what settled it: test vectors, ERRATA rulings, or `lens.py` for serialization questions.

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
- **It was then checked clause by clause against the specification text** (§3–§10). That check produced the four spec-text rules above and the interpretation record.

The maintainer's own review of each interpretation is tracked by the checkboxes in [docs/INTERPRETATIONS.md](docs/INTERPRETATIONS.md).

## License

Apache-2.0, matching the upstream verifier code. This crate shares no code with upstream. See [NOTICE](NOTICE).

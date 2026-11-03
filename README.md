# knobe-rs

A Rust verifier and sealer for **KNOBE Protocol v1**, written as a sibling of the
two upstream engines in [KnobeOne/knobe-protocol](https://github.com/KnobeOne/knobe-protocol):

| Upstream | What this crate matches |
|---|---|
| `lens.py`, the reference verifier | Verdict for verdict: `state`, `conformance`, `body_verified`, computed and stored hash, block count, exit code |
| `knobe-core.js` `createKnobe()`, the sealer | Byte for byte, apart from three deliberate refusals listed below |

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

`verify` prints the same report and uses the same exit codes as `python3 lens.py`:

| Exit code | Meaning |
|---|---|
| 0 | Integrity holds and the file conforms (with or without warnings) |
| 1 | The payload failed its hash, or conformance is invalid |
| 2 | The file is unreadable, or the command was used wrongly |

`seal` takes payload fields as a JSON object. Any missing field gets `createKnobe`'s default. The sealer verifies the finished file itself before writing it.

As a library: `knobe::verify_bytes`, `knobe::verify_path`, `knobe::create_knobe`, `knobe::seal`.

## How parity is tested

`cargo test` needs `python3` and `node`. It also needs the protocol checkout at `../knobe-protocol`; set `KNOBE_PROTOCOL_DIR` to use a different location.

| Test | What it checks |
|---|---|
| `tests/vectors.rs` | All 25 published vectors (core, adversarial, interpretation) against the expected results in their READMEs |
| `tests/lens_parity.rs` | Runs `lens.py --json` side by side with this crate over every published `.knobe.md`, plus 117 crafted hostile files, and compares every field the upstream parity gate compares. The hostile files are hashed by an independent Python oracle (`tests/support/pyhash.py`), never by the code under test. |
| `tests/seal_parity.rs` | Feeds the same requests to upstream `createKnobe` (Node) and to `create_knobe`, and requires byte-identical files. `lens.py` must then verify every sealed file. |
| `tests/hostile_scale.rs` | Resource bounds: payloads with 200,000 keys verify in linear time, and 100,000 levels of nesting are rejected cleanly instead of overflowing the stack. |

CI runs against upstream `main`, so any change upstream that breaks parity shows up immediately.

## Deliberate differences

### Sealer refusals

The sealer refuses a few inputs rather than emit a file that would lose information or not fully verify:

| Input | `knobe seal` |
|---|---|
| An integer beyond ±(2^53−1), which a JavaScript number cannot hold exactly | Refuses: write the number as a string |
| Keys that collapse to the same key under NFC normalization | Refuses |
| Duplicate keys in the fields JSON | Refuses |
| A line break in any field written to the YAML frontmatter (`title`, `spec_version`, `content_type`, `license`, `created_date`) | Refuses |
| Anything whose result would not verify as `verified`, with body `yes` whenever a body was given | Refuses |

### Verifier

Every malformed payload, whatever its shape, is reported as `unreadable` (exit 2). Hostile input never crashes the verifier.

## Provenance

knobe-rs is maintained by Joshua Hori (KnobeDev). It is not an official or reference KNOBE implementation, and the KNOBE steward did not build, review or endorse it.

It was written with AI assistance (Claude) at the maintainer's direction. As the steward's [governance notes](https://github.com/KnobeOne/knobe-protocol/blob/main/GOVERNANCE.md) ask, the reliance on the reference engines is disclosed here: `lens.py` and `knobe-core.js` were consulted throughout. Every ambiguous case was settled by observing `lens.py`, which is canonical for serialization questions, and is pinned by the parity tests above.

## License

Apache-2.0, matching the upstream verifier code. This crate is an independent port: it shares no code with upstream but follows the behavior of `lens.py` and `knobe-core.js`. See [NOTICE](NOTICE).

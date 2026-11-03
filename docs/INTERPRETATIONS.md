# Interpretation record

This file records where the KNOBE Protocol v1 specification leaves room for interpretation, which reading knobe-rs implements, and why. It was compiled by checking the code against the specification text (`site/spec.html` §3–§10, KnobeOne/knobe-protocol at `c7ada1f`), its [ERRATA](https://github.com/KnobeOne/knobe-protocol/blob/main/ERRATA.md), and the published test vectors.

The order of authority follows the steward's governance:

1. The published test vectors and their expected results are the arbiter of conformance.
2. ERRATA rulings come next.
3. Explicit normative spec text comes next. Where observed `lens.py` behavior conflicts with explicit text, knobe-rs follows the text.
4. `lens.py` is canonical only for serialization ambiguity under §5, and for details the text leaves undecided.

**Maintainer review.** A box is ticked when the maintainer has read the cited spec text and agrees with the reading. Unticked boxes have not been reviewed by a person yet.

## Where knobe-rs follows the spec text rather than lens.py

None of these changes a verdict for any published vector or example. `tests/lens_parity.rs` pins each one with an explicit expected result. If `lens.py` changes to agree, the test flags the entry for removal.

### I-1. The frontmatter must declare `spec_version`

- [ ] Reviewed by maintainer

- **Spec:** §3.1, "At minimum, spec_version MUST appear in the frontmatter." §10: a conforming file MUST "Begin with a YAML frontmatter block including spec_version."
- **lens.py:** checks only that the frontmatter exists.
- **knobe-rs:** a frontmatter block with no `spec_version` line, or an empty value, is a conformance error: `YAML frontmatter does not declare spec_version (spec §3.1)`. Integrity is unaffected.
- **Hostile cases:** 8, e.g. `fm-spec-empty`.

### I-2. Hashes are exactly 64 lowercase hex characters

- [ ] Reviewed by maintainer

- **Spec:** §4.1 `payload_hash`, "Format: exactly 64 lowercase hexadecimal characters." §4.3 `parents`: "Any payload_hash value MUST follow the format constraint in §4.1." `body_hash` is checked with the same rule, as in both reference engines.
- **lens.py:** its `^[0-9a-f]{64}$` is matched with Python `re.match`, where `$` also matches before a final newline, so `<64 hex>\n` passes. `knobe-core.js` rejects it.
- **knobe-rs:** a trailing newline makes the format invalid. This is the same as `knobe-core.js` and as KnobeOne/knobe-protocol#12.
- **Hostile cases:** 3.

### I-3. Only line breaks are ignored inside the Base64 block

- [ ] Reviewed by maintainer

- **Spec:** §3.3, the content is "standard Base64 (RFC 4648 §4)" and "Line breaks within the Base64 block MUST be ignored by decoders." RFC 4648 §3.3 says implementations MUST reject characters outside the alphabet "unless the specification referring to this document explicitly states otherwise". The KNOBE spec makes that exception only for line breaks.
- **lens.py:** removes every character Python counts as whitespace (`str.split()`), including spaces, tabs, U+001C–U+001F, U+0085 and Unicode spaces. `knobe-core.js` removes JavaScript `\s`, which is a different set.
- **knobe-rs:** removes CR and LF only. Any other character outside the alphabet makes the file `unreadable`.
- **Note:** this is stricter than KnobeOne/knobe-protocol#12, which also allows spaces and tabs. No published file has a space or tab inside its payload block.
- **Hostile cases:** 2.

### I-4. The body starts after the second `---` line, counted from the start of the file

- [ ] Reviewed by maintainer

- **Spec:** §6, "The body is extracted as the text immediately following the second line containing exactly ---… If a verifier cannot locate two --- lines before the -----BEGIN KNOBE B64----- marker, it MUST report unreadable."
- **lens.py:** requires the first line of the file to be one of the two `---` lines.
- **knobe-rs:** counts lines that are exactly `---` from the start of the file. Trailing CRs are treated as line-ending residue, as in `lens.py`, so a CRLF file counts. A line with a byte-order mark before `---` is not "exactly ---", so it does not count.
- **When it differs:** only for files whose first line is not `---` but that still have two such lines before the marker. §3.1 already makes those nonconforming.
- **Hostile cases:** 1.

## Where knobe-rs follows lens.py, because the vectors or ERRATA decide it

| Topic | Spec text | Settled by | knobe-rs |
|---|---|---|---|
| Missing required fields | §7 lists "All required fields present" as a condition of `verified` | ERRATA E4, E9; `attribution-missing` vector (verified · invalid) | Integrity and conformance are reported independently. A missing field is a conformance error, not a change of state. |
| Wider `unreadable` | §7: "No payload block found, or the block cannot be decoded or parsed" | ERRATA E10; adversarial vectors | Duplicate keys, NFC key collisions, a non-object payload and an unsupported `spec_version` are all `unreadable` |
| Multiple blocks | §3.3, §6 | ERRATA E3; `multi-block` vectors | Evaluate the last block, `conformance: warnings`, `body_verified: omitted` |
| Padding | §3.3 (RFC 4648 §4) | ERRATA E7 | Missing `=` padding is `unreadable` |
| Escapes in the canonical form | §5 "MUST NOT use \uXXXX escapes for characters that can be represented directly" | ERRATA E8 | Only U+0000–U+001F are escaped; `\b \t \n \f \r` use short forms |
| `body_verified` for unreadable files | §7 "MUST be omitted" | ERRATA E11 (`null` or `"omitted"`) | `null` in JSON, as `lens.py` |
| Booleans and null | §5 | ERRATA E6 | Not numeric; hashed as literal tokens |

## Where the text is ambiguous and knobe-rs follows lens.py

| Topic | Ambiguity | knobe-rs |
|---|---|---|
| Key order | §5 says "sorted alphabetically" | Unicode code-point order, as `lens.py` (§5 serialization is `lens.py`'s to decide) |
| Number formatting | §5 requires numbers as strings but still hashes bare ones (ERRATA E1 pins integers only) | Python `repr` for floats, plain digits for integers |
| Non-zero trailing Base64 bits | RFC 4648 §3.5 says decoders MAY reject them | Accepted, as CPython does |
| BOM before the frontmatter | §3.1 says the file "MUST begin with" frontmatter; nothing about a BOM | Skipped when checking that frontmatter exists, as `lens.py`; not skipped when counting `---` lines for §6 (I-4) |
| Line endings in `---` lines | "exactly ---" with CRLF files | Trailing CRs ignored, as `lens.py` |
| `attribution.sources` "at least one entry" | What counts as present | Python truthiness, as `lens.py` |
| Unrecognized `spec_version` | §9 says "SHOULD report this clearly" | `unreadable`, as pinned by `unsupported-spec-version` |

## Not checked

These are spec expectations knobe-rs does not enforce, and neither does `lens.py`. Enforcing them would turn files that the reference calls `valid` into failures, with no vector to arbitrate.

- **Types of optional fields** in the §4.3 table, e.g. `is_seed` boolean, lowercase `tags`, BCP 47 `language`. These are written as notes, not MUSTs.
- **SHOULD-level guidance:**
  - source entries carrying `author` and `contribution`;
  - AI contributors carrying `"rights_bearing": false`;
  - vocabularies for `parents.relationship` and `accessibility.adaptation_type`.
- **Rendering canonical and custom vocabulary values differently** (§8 SHOULD). Custom values without a namespace are reported as warnings, but the CLI does not style them differently.

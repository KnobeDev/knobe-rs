# Interpretation record

This file records where the KNOBE Protocol v1 specification leaves room for interpretation, which reading knobe-rs implements, and why. It was compiled by checking the code against the specification text (`site/spec.html` §3–§10, KnobeOne/knobe-protocol at `c7ada1f`), its [ERRATA](https://github.com/KnobeOne/knobe-protocol/blob/main/ERRATA.md), and the published test vectors. It was brought up to date for 0.1.1 against KnobeOne/knobe-protocol at `6132595`, which includes PR #11 (hostile input is reported unreadable), PR #12 and ERRATA E12 (ASCII-strict formats and block whitespace), and for 0.1.2 with the rest of PR #11's limits (nesting, integer length, check order).

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

### I-2. Hashes are exactly 64 lowercase hex characters (settled by ERRATA E12)

This was a spec-over-reference point until ERRATA E12 ruled the same way. `lens.py` and `knobe-core.js` now agree with knobe-rs, so it has moved to the [table below](#where-knobe-rs-follows-lenspy-because-the-vectors-or-errata-decide-it). The number is kept so older references stay valid.

### I-3. Whitespace inside the Base64 block (decided by ERRATA E12 and its grounds)

knobe-rs 0.1.0 stripped only CR and LF, reading §3.3 ("Line breaks within the Base64 block MUST be ignored") with RFC 4648 §3.3.

- **ERRATA E12** says: "Only ASCII space, tab, CR and LF may be stripped from a payload block; any other character inside the block makes the base64 invalid and the file unreadable." Read alone, "may" leaves open whether a verifier that strips only CR and LF also conforms.
- **The steward's grounds for the ruling** ([approving review of PR #12](https://github.com/KnobeOne/knobe-protocol/pull/12#pullrequestreview-5775198306), 2026-11-04) answer that: "divergent verdicts between conforming verifiers break the determinism the seal promises, which makes this a defect, not a preference."
- **`lens.py` and `knobe-core.js`** strip exactly space, tab, CR and LF. So stripping fewer than they do produces exactly that kind of split.

Since 0.1.1, knobe-rs strips the same four characters, so this entry has moved to the [table below](#where-knobe-rs-follows-lenspy-because-the-vectors-or-errata-decide-it). The number is kept so older references stay valid. No vector pins a space or tab inside a block yet.

- [x] Reviewed by maintainer (2026-11-04, for 0.1.2: keep stripping space, tab, CR and LF)

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
| Hash and date formats (formerly I-2) | §4.1: hashes are "exactly 64 lowercase hexadecimal characters"; `created_date` is ISO 8601 `YYYY-MM-DD` | ERRATA E12 | A hash is exactly 64 lowercase ASCII hex characters and a date exactly ten ASCII characters, with nothing following: `<64 hex>\n` and Arabic-Indic digits are invalid |
| Whitespace inside the payload block (formerly I-3) | §3.3: "Line breaks within the Base64 block MUST be ignored" | ERRATA E12, which lists the four characters that "may be stripped", read with the steward's [grounds](https://github.com/KnobeOne/knobe-protocol/pull/12#pullrequestreview-5775198306) that divergent verdicts between conforming verifiers are a defect | Strips ASCII space, tab, CR and LF, as both reference engines do. Any other character outside the Base64 alphabet, e.g. U+0085, U+00A0, U+001C–U+001F, VT or FF, makes the file `unreadable` |
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
| Unrecognized `spec_version` | §9 says "SHOULD report this clearly" | `unreadable`, as pinned by `unsupported-spec-version`; a non-string value (a number, list or object) is unsupported too, and shown as Python `str()` shows it, as `lens.py` since PR #11 |
| Nesting depth | RFC 8259 §9 lets a parser limit nesting; the spec sets no limit | As `lens.py` on CPython 3.13: a value or key 499 or more levels below the payload is `unreadable` (`verifier error (RecursionError)`, block count 0). An array more than 9997 levels deep, an object, float or NaN/Infinity more than 9995, or an object with a duplicate key 9995 or more, cannot be parsed ("could not be decoded or parsed") |
| Integer length | RFC 8259 §9 lets a parser limit the range of numbers; §5 hashes integers as written | More than 4300 digits is `unreadable`, Python's limit for `int()` |
| Which defect is reported | §7 lists the `unreadable` conditions but not their order | `lens.py`'s order: a parse error (a duplicate key counts once its object closes), then a payload that is not an object, an unpaired surrogate, an NFC key collision, and an unsupported `spec_version` |
| A number that overflows to infinity, e.g. `1e400` | RFC 8259 allows the lexeme, but §5 has no canonical form for infinity, and no ERRATA entry or vector covers it | `unreadable` wherever it appears, `payload_hash` included, as `lens.py` and `knobe-core.js` since PR #11. An integer of any length stays readable, and a float that underflows becomes `0.0` |

## Not checked

These are spec expectations knobe-rs does not enforce, and neither does `lens.py`. Enforcing them would turn files that the reference calls `valid` into failures, with no vector to arbitrate.

- **Types of optional fields** in the §4.3 table, e.g. `is_seed` boolean, lowercase `tags`, BCP 47 `language`. These are written as notes, not MUSTs.
- **SHOULD-level guidance:**
  - source entries carrying `author` and `contribution`;
  - AI contributors carrying `"rights_bearing": false`;
  - vocabularies for `parents.relationship` and `accessibility.adaptation_type`.
- **Rendering canonical and custom vocabulary values differently** (§8 SHOULD). Custom values without a namespace are reported as warnings, but the CLI does not style them differently.

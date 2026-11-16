// Refusal oracle: asks upstream knobe-core.js seal() about every Unicode
// scalar value, one at a time, and prints the ones it refuses as unassigned.
//
// Line 1 is "unicode <version>", the Unicode version of this Node's tables.
// Every other line is an inclusive range of refused code points in hex,
// "START-END". seal() is asked rather than a copy of its regular expression,
// so a change to what upstream refuses shows up here.
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const { seal } = await import(
  pathToFileURL(join(process.env.KNOBE_PROTOCOL_DIR, "knobe-core.js")).href);

const lines = [`unicode ${process.versions.unicode}`];
let start = null;
const close = (end) => {
  if (start !== null) lines.push(`${start.toString(16)}-${end.toString(16)}`);
  start = null;
};
for (let cp = 0; cp <= 0x10ffff; cp++) {
  if (cp >= 0xd800 && cp <= 0xdfff) { close(cp - 1); continue; } // not scalar values
  let refused = false;
  try {
    await seal({ v: String.fromCodePoint(cp) });
  } catch (e) {
    const named = /contains U\+([0-9A-F]+),/.exec(String(e?.message ?? e));
    if (!named || parseInt(named[1], 16) !== cp) {
      throw new Error(`seal() refused U+${cp.toString(16)} for another reason: ${e}`);
    }
    refused = true;
  }
  if (refused) start ??= cp; else close(cp - 1);
}
close(0x10ffff);
process.stdout.write(lines.join("\n") + "\n");

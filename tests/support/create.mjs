// Seal oracle: runs upstream knobe-core.js createKnobe() on a JSON request
// read from stdin — {"fields": {...}, "body": "...", "author": "..."|null} —
// and writes the emitted .knobe.md text to stdout. If createKnobe refuses the
// request, it writes the refusal message to stderr and exits with status 3.
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const { createKnobe } = await import(
  pathToFileURL(join(process.env.KNOBE_PROTOCOL_DIR, "knobe-core.js")).href);

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);
try {
  const { text } = await createKnobe({ fields: req.fields, body: req.body ?? "", author: req.author ?? null });
  process.stdout.write(text);
} catch (e) {
  process.stderr.write(String(e?.message ?? e));
  process.exitCode = 3;
}

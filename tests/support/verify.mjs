// Verify oracle: runs upstream knobe-core.js verify() on the file named by
// the first argument and prints the fields the parity gate compares as JSON.
// The exit status is upstream's exitCode() for the report.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const { verify, exitCode } = await import(
  pathToFileURL(join(process.env.KNOBE_PROTOCOL_DIR, "knobe-core.js")).href);

const r = await verify(readFileSync(process.argv[2]));
process.stdout.write(JSON.stringify({
  state: r.state,
  conformance: r.conformance,
  body_verified: r.body_verified,
  computed: r.computed,
  stored: r.stored,
  block_count: r.block_count,
  multiple_blocks: r.multiple_blocks,
  conformance_issues: r.conformance_issues,
}) + "\n");
process.exitCode = exitCode(r);

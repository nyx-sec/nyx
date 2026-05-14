// Phase 13 — ES module default export, vulnerable.
//
// `export default` body is the entry the harness imports dynamically.  The
// harness builder stages this file at `workdir/entry.mjs` (per
// js_shared::entry_subpath_for_shape) so Node parses it under ESM semantics
// regardless of the on-disk `.js` extension under the fixture tree.

// nyx-shape: esm-default
import { execSync } from 'child_process';

export default function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        const out = execSync('echo hello ' + host, { encoding: 'utf8', timeout: 5000 });
        process.stdout.write(out);
        return out;
    } catch (e) {
        const out = (e.stdout || '') + (e.stderr || '');
        process.stdout.write(out);
        return out;
    }
}

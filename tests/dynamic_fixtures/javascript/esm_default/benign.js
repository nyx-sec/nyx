// Phase 13 — ES module default export, benign control.
//
// nyx-shape: esm-default
import { execFileSync } from 'child_process';

export default function runPing(host) {
    process.stdout.write('__NYX_SINK_HIT__\n');
    try {
        execFileSync('true', [host], {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
        });
        return 'ok';
    } catch (_e) {
        return 'err';
    }
}

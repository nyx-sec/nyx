// Phase 05 negative fixture — a user-defined `readFile` shadowing the
// fs/promises import. The gate must NOT fire because the local-import
// view has no entry for `readFile` mapped to `fs/promises`. A flat
// bare-name match would over-fire here; the gate is the whole point.
//
// The fixture deliberately has no other sinks downstream of the call
// (no `res.send`, no shell exec) so any taint finding produced for
// this file proves the gate over-fired.
import type { Request } from "express";

function readFile(path: string): string {
    return `mock read of ${path}`;
}

export function handler(req: Request): void {
    const path = req.body.path;
    const _data = readFile(path);
}

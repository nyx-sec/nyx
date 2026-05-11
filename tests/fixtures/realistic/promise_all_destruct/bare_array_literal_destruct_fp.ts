// Forcing-function fixture: bare-array-literal RHS destructure
// `const [a, b] = [safe, tainted];` must paint each binding from its
// source-order RHS slot rather than the scalar union of every ident.
//
// Pre-fix: `info.taint.uses = ["safe", "tainted"]` painted both `a`
// and `b` with the union taint via the cloned primary Assign op.
//   exec(a) → false positive
//   exec(b) → true positive
//
// Post-fix: `info.taint.rhs_array_elements = [Some("safe"),
// Some("tainted")]` drives per-binding ops in `src/ssa/lower.rs`:
//   primary `a` → Assign(safe_value)  (no taint)
//   extra   `b` → Assign(tainted_value) (carries req.body taint)
//
// Sinks intentionally use Node's `child_process.exec` so the scalar-
// union FP is structurally inspectable in the diagnostic output.

import express from "express";
import { exec } from "child_process";

const app = express();

app.get("/u", (req, res) => {
    const tainted = req.body.cmd as string;
    const safe = "ok";
    const [a, b] = [safe, tainted];
    exec(a);              // Negative: a = safe (literal binding), MUST NOT fire.
    exec(b);              // Positive: b = tainted (line ~28), MUST fire.
});

app.get("/v", (req, res) => {
    const tainted = req.body.cmd as string;
    // Mixed bare-ident + string-literal slots: slot 0 is an ident
    // bound to `tainted`, slot 1 is a syntactic literal.
    const [x, y] = [tainted, "literal"];
    exec(x);              // Positive: x = tainted (line ~37), MUST fire.
    exec(y);              // Negative: y = string literal, MUST NOT fire.
});

app.get("/w", (req, res) => {
    const tainted = req.body.cmd as string;
    // Skip-leading destructure: `b` lives at pattern position 1.
    const [, b] = [tainted, "safe-literal"];
    exec(b);              // Negative: b = literal "safe-literal", MUST NOT fire.
});

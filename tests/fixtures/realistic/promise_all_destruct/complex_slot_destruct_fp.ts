// Forcing-function fixture: complex-slot bare-array RHS destructure.
// Closes the deferred follow-on for slots whose shape is not a bare
// identifier or syntactic literal (call, binary, subscript, member
// access, interpolated string, nested array literal). Pre-fix the
// helper `collect_rhs_array_literal_elements` bailed on these shapes,
// the per-element rewrite skipped, and the legacy scalar union
// painted every binding with the union of every RHS ident on the
// source-labeled CFG node — producing a FP on every literal-aligned
// binding.
//
// Post-fix:
//   * Ident slot         → `Assign(reaching def)`.
//   * Literal slot       → `Const(None)` (clean binding).
//   * Complex slot       → `Assign(union of inner ident reaching defs)`,
//     OR `Source` when the outer CFG node carried a Source label
//     (preserves the outer-node classification for the slot whose
//     subtree contained the source-matching pattern, without painting
//     Literal siblings).

import express from "express";
import { exec } from "child_process";

const app = express();

function normalize(s: string): string {
    return s;
}

app.get("/call_slot", (req, res) => {
    // Slot 0 is a call (`normalize(req.body.cmd)`), slot 1 a literal.
    const [a, b] = [normalize(req.body.cmd), "static-prefix"];
    exec(a);              // Positive (line 32): a carries Source via Complex slot.
    exec(b);              // Negative (line 33): b = literal, MUST NOT fire.
});

app.get("/binary_slot", (req, res) => {
    // Slot 0 is a binary expression, slot 1 a literal.
    const [c, d] = ["log-" + req.body.cmd, "static-tail"];
    exec(c);              // Positive (line 39).
    exec(d);              // Negative (line 40): d = literal, MUST NOT fire.
});

app.get("/member_slot", (req, res) => {
    // Slot 0 is a bare member expression, slot 1 a literal.
    const [e, f] = [req.body.cmd, "static"];
    exec(e);              // Positive (line 46).
    exec(f);              // Negative (line 47): f = literal, MUST NOT fire.
});

app.get("/subscript_slot", (req, res) => {
    // Slot 0 is a subscript on a tainted local, slot 1 a literal.
    const arr = [req.body.cmd];
    const [g, h] = [arr[0], "static"];
    exec(g);              // Positive (line 54).
    exec(h);              // Negative (line 55): h = literal, MUST NOT fire.
});

app.get("/template_slot", (req, res) => {
    // Slot 0 is a template literal carrying the source via ${...},
    // slot 1 is a plain string literal.
    const [i, j] = [`hi-${req.body.cmd}`, "tail"];
    exec(i);              // Positive (line 62).
    exec(j);              // Negative (line 63): j = literal, MUST NOT fire.
});

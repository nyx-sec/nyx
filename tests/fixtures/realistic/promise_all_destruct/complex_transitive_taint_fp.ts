// Forcing-function fixture for slot-scoped taint propagation when the
// outer destructure node carries a Source label.
//
// Pre-session 0048: the bare-array kill arm in `src/ssa/lower.rs`
// emitted `SsaOp::Const(None)` for a safe Complex sibling when the
// sibling slot's text did not classify as a Source.  Transitive taint
// through the sibling's inner uses (e.g. `helper(tainted_local)` where
// `tainted_local` is bound to `req.body.cmd`) was lost.
//
// Post-session: the kill arm emits `SsaOp::Assign(mapped)` and records
// the SSA value in `SsaBody.slot_scoped_assigns`.  The taint transfer's
// Assign arm consults the set to skip the outer-node Source label
// pickup while still unioning operand taint, so transitive taint via
// inner uses propagates without the sibling slot inheriting the
// outer-node Source attribution.

import express from "express";
import { exec } from "child_process";

const app = express();

function helper(s: string): string {
    return "wrap:" + s;
}

app.get("/transitive_taint", (req, res) => {
    const tainted_local: string = req.body.cmd;
    const [a, b] = [req.body.other, helper(tainted_local)];
    exec(a);  // line 29: positive — slot 0 directly carries req.body.other.
    exec(b);  // line 30: positive — slot 1 transitively carries req.body.cmd.
});

app.get("/safe_sibling_when_outer_source", (req, res) => {
    const safe = "literal";
    const [c, d] = [req.body.cmd, helper(safe)];
    exec(c);  // line 36: positive — slot 0 carries req.body.cmd.
    exec(d);  // line 37: negative — slot 1's inner ident is a literal.
});

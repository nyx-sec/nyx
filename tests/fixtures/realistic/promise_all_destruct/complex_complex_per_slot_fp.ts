// Forcing-function fixture for per-slot Source classification on
// `RhsArraySlot::Complex` slots.
//
// Pre-session 0047: when the outer destructure node carried a Source
// label (any RHS subtree contained a member-expression Source), every
// Complex slot was conservatively re-emitted as `SsaOp::Source` by the
// outer-node fallback in `src/ssa/lower.rs`.  Sibling Complex slots
// whose own subtree was SAFE got mis-painted with the outer Source.
//
// Post-session: `RhsArraySlot::Complex.source_cap` carries per-slot
// caps recognised via `first_member_label` on the slot's subtree.
// When ANY Complex slot has a non-empty per-slot source_cap, sibling
// Complex slots without per-slot caps fall through to slot-scoped
// `Assign(inner uses)` — so a safe Complex sibling stays clean.

import express from "express";
import { exec } from "child_process";

const app = express();

function normalize(s: string): string { return s; }
function helper(s: string): string { return s; }

app.get("/call_vs_call", (req, res) => {
    const safe = "literal";
    const [a, b] = [normalize(req.body.cmd), helper(safe)];
    exec(a);   // line 27: positive — slot 0 carries per-slot Source.
    exec(b);   // line 28: negative — slot 1's subtree has no Source.
});

app.get("/member_vs_call", (req, res) => {
    const safe = "ok";
    const [c, d] = [req.body.cmd, helper(safe)];
    exec(c);   // line 34: positive.
    exec(d);   // line 35: negative — slot 1 is locally bound to a literal.
});

app.get("/binary_vs_call", (req, res) => {
    const safe = "tail";
    const [e, f] = ["log-" + req.body.cmd, helper(safe)];
    exec(e);   // line 41: positive — binary expression contains the source.
    exec(f);   // line 42: negative — helper(safe) does NOT classify as Source.
});

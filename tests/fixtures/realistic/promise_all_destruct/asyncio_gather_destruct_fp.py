"""Forcing-function fixture: Python `a, b = await asyncio.gather(safe, tainted)`
must bind each name to its argument-position's taint, not the scalar union
of every element.

Pre-fix the destructure-promise rewrite at src/ssa/lower.rs only fired for
JS/TS `array_pattern` and Rust `tuple_pattern`. Python `assignment` whose
LHS is `pattern_list` (bare `a, b = ...`) or `tuple_pattern` (parenthesised
`(a, b) = ...`) fell through to `Kind::Assignment::idents.pop()`, which
discarded every binding except the LAST identifier — `a` was lost entirely
and `b` painted with the scalar union of every gather argument.

Engine fix (session 0043):
  * `collect_array_pattern_bindings_indexed` recognises `pattern_list`.
  * `def_use::Kind::Assignment` calls the indexed helper, populating
    `extra_defines` + `array_pattern_indices` parallel to the existing
    `Kind::CallWrapper` arm.

The remaining tail (combinator recognition for `asyncio.gather`, SSA
lowering, and per-binding Assign emission) was already in place from
sessions 0023 / 0042.
"""

import asyncio


# Bare locals shape: shape (b) in lower.rs picks up `[["safe"], ["tainted"]]`
# as N positional args each with one ident, mapping each per index.
async def view_safe_then_tainted(request):
    safe = "ok"
    tainted = request.args.get("x")
    a, b = await asyncio.gather(safe, tainted)
    cursor.execute(b)  # Positive: index 1 = tainted, MUST fire.
    cursor.execute(a)  # Negative: index 0 = safe, must NOT fire.


async def view_tainted_then_safe(request):
    safe = "ok"
    tainted = request.args.get("x")
    a, b = await asyncio.gather(tainted, safe)
    cursor.execute(a)  # Positive: index 0 = tainted, MUST fire.
    cursor.execute(b)  # Negative: index 1 = safe, must NOT fire.


# Parenthesised destructure surfaces as `tuple_pattern` (vs `pattern_list`
# for the bare form).  Same per-index rewrite applies.
async def view_paren_destruct(request):
    safe = "ok"
    tainted = request.args.get("x")
    (a, b) = await asyncio.gather(safe, tainted)
    cursor.execute(b)  # Positive: index 1 = tainted, MUST fire.
    cursor.execute(a)  # Negative: index 0 = safe, must NOT fire.

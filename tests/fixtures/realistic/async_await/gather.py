# Phase 12 recall-gap fixture (Python combinator).  `asyncio.gather`
# concurrently awaits its argument futures and resolves to a list whose
# elements carry the union of argument taints.  The SQL sink on
# `results[0]` proves the engine's `PromiseCombinator` rule fires for
# Python via the `is_promise_combinator("python", "asyncio.gather")`
# entry added in this phase.
import asyncio


async def main(request):
    a = request.args.get("x")
    b = request.form.get("y")
    results = await asyncio.gather(a, b)
    cursor.execute(results[0])

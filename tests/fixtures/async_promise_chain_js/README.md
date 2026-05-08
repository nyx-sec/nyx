# async_promise_chain_js — chained-receiver promise taint

## Intended flow
A promise chain reads `process.env.PREFIX` inside the second `.then`
callback, concatenates it with fetched text, and sinks the result via
`child_process.exec` from the third callback.  The intended finding is
`taint-unsanitised-flow` from the env source to the exec sink.

## Engine behaviour
The engine now closes this gap.  The chained-receiver promise shape
(`fetch(...).then(..).then(..).then(..)`) keeps each `.then` call's
identity at the CFG level so `try_apply_promise_callback` and the
synthetic `source_to_callback` emission see the chain head's Source
label and seed the callback's first parameter, propagating taint
through the chain to the `exec` sink.

## Expectation
`required_findings` pins the taint flow finding so a future
regression that re-collapses the chain (e.g. an inner-call rewrite
that erases the outer `.then` identity) will fail this test.

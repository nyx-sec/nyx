# Roadmap

## Now: recall and precision on real codebases

The current focus is straightforward. Run Nyx against real open-source repositories and real CVEs, then close the gap between what it finds and what it should find.

That means:

- **Recall.** Pick CVEs with public fixes. Reproduce them on the vulnerable commit. If Nyx misses, figure out why (missing source, missing sink, lost flow across a call, dropped at a sanitizer that was not actually a sanitizer) and fix the underlying analysis, not the fixture.
- **Precision.** Triage the noise on large repos (phpMyAdmin, Nextcloud, and others). Each false positive gets reduced to a pattern: receiver-type gate, non-crypto context for `md5`/`sha1`, type-safe sink suppression, etc. Land the gate, re-run the corpus, confirm the count drops without taking real bugs with it.
- **Corpus discipline.** Every fix lands with a fixture (positive or negative) and a corpus row. Rule-level F1 on `tests/benchmark/corpus/` is the scoreboard. CI floors only ratchet up.

The scanner internals (SSA, cross-file summaries, abstract interpretation, symbolic execution, auth analysis) are in place. They get refined in service of the recall/precision work, not extended for their own sake.

## Later: dynamic capability

Static analysis confirms a flow exists. Dynamic execution confirms it fires. The plan is a local sandbox that picks up entry points Nyx already identifies, builds a harness, injects a payload, and watches for the crash or shell. Pairs naturally with fuzzing (libFuzzer, cargo-fuzz, go-fuzz, HTTP) where the static engine picks the targets.

Not started. Lands after the static side is honest on real corpora.

## Later still: reasoning layer

Embeddings for cross-codebase pattern similarity. LLM-assisted detection for logic bugs that resist taint modeling. Automated exploit refinement loops. All speculative until the foundation is solid.

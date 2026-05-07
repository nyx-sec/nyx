## Deferred items

- Open-redirect sanitizer recognition is name-only: `validateRedirectUrl` / `ensureRelativeUrl` / `is_safe_redirect` (and snake_case mirrors) clear `Cap::OPEN_REDIRECT` purely by callee identifier. The phase-05 deliverable also lists structural recognition — `URL parse + host allowlist comparison` and `url.starts_with("/")` followed by no-scheme check. That requires the abstract-string-domain / TypeFacts pattern hook to track URL parse calls (`new URL(...)`, `urllib.parse.urlparse`, `url::Url::parse`, `net/url.Parse`) plus the host-equality / leading-slash pattern; a fixture that performs the same allowlist inline (without delegating to a named helper) currently falls through to the sink.
- Phase-09 prototype-pollution `Object.create(null)` receiver fact is implemented as a same-function AST scan (`pp_receiver_is_null_prototype` in `src/cfg/mod.rs`) rather than a `TypeKind::NullPrototypeObject` carried through SSA.  The current scan walks the function body and matches *any* `target = Object.create(null)` assignment, so cross-block reassignment and phi joins do suppress, but **flow-insensitively** — the if/else shape `if (cond) { target = Object.create(null); } else { target = {}; }` suppresses even though the else branch leaves `target` pollutable.  A flow-sensitive fix needs a new `TypeKind::NullPrototypeObject` populated by a constructor / factory rule for `Object.create(null)`, propagated through copy / phi like the existing `XmlParser` config sidecar, and consulted at the synthetic `__index_set__` sink-emission site so the suppression honours the lattice meet.  Same engine shape as Phase 07's `XmlParserConfigResult`.

## Deferred phases

### From phase 01

- Log4Shell XXE-leg CVE fixture — real-world exercise of the new TypeFacts + xml_config sidecar end-to-end.
- Real-world prototype-pollution CVE fixtures (lodash deep clone bugs, immer nested-set bugs, jsonpath / set-value libraries) — phase 09 covers the synthetic `__index_set__` channel but the labelled gates still depend on each library's specific call shape.
- Stage-1 bare `extend` (jQuery shallow / Underscore-style) flat-suffix matcher — deliberately omitted because the suffix is too broad (Backbone `Model.extend`, `Collection.extend`, `View.extend`, etc. would over-fire); recognising deep `extend` requires either a `jQuery` TypeKind or a constructor-options style abstract-string fact.
- Python proto-pollution opt-in needs a positive fixture once a real-world Python proto-pollution CVE is ported into the corpus.

### From phase 05: Open redirect follow-ups

- Spring MVC `"redirect:" + url` controller-return string. Needs the abstract-string-domain prefix-fact to detect a return whose value has prefix `redirect:` and whose suffix is tainted, then emit OPEN_REDIRECT on the return point. No flat-matcher equivalent exists because `return` is the structural shape, not a callee.
- Inline structural sanitizer recognition (URL parse + host allowlist, leading-slash check without a developer-named helper) tracked under `## Deferred items` above.

### From phase 06: SSTI follow-ups

- Liquid / Mako template-loader paths where the source is loaded from a tainted file system — symbolic-string / config-check pattern hooks.

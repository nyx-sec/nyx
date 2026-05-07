## Deferred items

- Open-redirect URL-parse + host-allowlist sanitiser (e.g. `if (new URL(url).host === ALLOW) redirect(url)`) still falls through to the sink. The leading-slash inline form (`x.startsWith("/")`) is recognised via `PredicateKind::RelativeUrlValidated` and clears `Cap::OPEN_REDIRECT` on the validated branch; the parse-+-host form needs the abstract-string-domain pattern hook to track `new URL(...)` / `urllib.parse.urlparse` / `url::Url::parse` / `net/url.Parse` then attach the host-equality fact.

## Deferred phases

### From phase 01

- Log4Shell XXE-leg CVE fixture — real-world exercise of the new TypeFacts + xml_config sidecar end-to-end.
- Real-world prototype-pollution CVE fixtures (lodash deep clone bugs, immer nested-set bugs, jsonpath / set-value libraries) — phase 09 covers the synthetic `__index_set__` channel but the labelled gates still depend on each library's specific call shape.
- Stage-1 bare `extend` (jQuery shallow / Underscore-style) flat-suffix matcher — deliberately omitted because the suffix is too broad (Backbone `Model.extend`, `Collection.extend`, `View.extend`, etc. would over-fire); recognising deep `extend` requires either a `jQuery` TypeKind or a constructor-options style abstract-string fact.
- Python proto-pollution opt-in needs a positive fixture once a real-world Python proto-pollution CVE is ported into the corpus.

### From phase 06: SSTI follow-ups

- Liquid / Mako template-loader paths where the source is loaded from a tainted file system — symbolic-string / config-check pattern hooks.

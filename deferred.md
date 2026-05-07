## Deferred items

- Open-redirect URL-parse + host-allowlist sanitiser, multi-statement form (Rust `url::Url::parse` + `Result` unwrap, Go `net/url.Parse` + `err` check). The inline JS/TS/Python forms (`new URL(x).host === Y`, `urlparse(x).netloc == Y`) are recognised via `PredicateKind::HostAllowlistValidated`; the multi-statement form needs the abstract-string-domain pattern hook to track the parse result across statements then attach the host-equality fact.

## Deferred phases

### From phase 01

- Real-world prototype-pollution CVE fixtures (lodash deep clone bugs, immer nested-set bugs, jsonpath / set-value libraries) — phase 09 covers the synthetic `__index_set__` channel but the labelled gates still depend on each library's specific call shape.
- Stage-1 bare `extend` (jQuery shallow / Underscore-style) flat-suffix matcher — deliberately omitted because the suffix is too broad (Backbone `Model.extend`, `Collection.extend`, `View.extend`, etc. would over-fire); recognising deep `extend` requires either a `jQuery` TypeKind or a constructor-options style abstract-string fact.

### From phase 06: SSTI follow-ups

- Liquid / Mako template-loader paths where the source is loaded from a tainted file system — symbolic-string / config-check pattern hooks.

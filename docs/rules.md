# Rule reference

Every finding Nyx emits has a rule ID. This page enumerates the IDs that ship with the scanner, grouped by family.

> This page is written by hand and drifts against the code. Authoritative sources: [`src/patterns/<lang>.rs`](https://github.com/elicpeter/nyx/tree/master/src/patterns) for AST patterns, [`src/labels/<lang>.rs`](https://github.com/elicpeter/nyx/tree/master/src/labels) for taint matchers, and [`src/auth_analysis/config.rs`](https://github.com/elicpeter/nyx/blob/master/src/auth_analysis/config.rs) for auth rules. If a rule fires that isn't listed here, the source file is right and this page is wrong.

If you'd rather browse rules interactively, [`nyx serve`](serve.md) ships a Rules page that lists every loaded matcher with its language, kind, and capability:

<p align="center"><img src="assets/screenshots/docs/serve-rules.png" alt="Nyx Rules page: filterable list of 218 rules with language, kind (SOURCE/SANITIZER/SINK), capability, and finding count columns" width="900"/></p>

## ID format

| Prefix | Detector | Example |
|---|---|---|
| `taint-*` | Taint analysis | `taint-unsanitised-flow (source 5:11)` |
| `cfg-*` | CFG structural | `cfg-unguarded-sink`, `cfg-auth-gap` |
| `state-*` | State model | `state-use-after-close`, `state-resource-leak` |
| `<lang>.auth.*` | Auth analysis | `rs.auth.missing_ownership_check` |
| `<lang>.<category>.<name>` | AST patterns | `rs.memory.transmute`, `js.code_exec.eval` |

Language prefixes: `rs`, `c`, `cpp`, `go`, `java`, `js`, `ts`, `py`, `php`, `rb`.

## Cross-language rules

### Taint

The taint family is split into cap-specific rule classes. The `taint-unsanitised-flow` id is the catch-all for the legacy caps that have not migrated to a dedicated rule id yet (`sql_query`, `ssrf`, `code_exec`, `file_io`, `fmt_string`, `deserialize`, `crypto`). The seven new vulnerability classes plus auth and data-exfil emerge under their own rule id. The parenthetical identifies the source location.

| Rule ID | Cap | Severity |
|---|---|---|
| `taint-unsanitised-flow (source L:C)` | `sql_query` / `ssrf` / `code_exec` / `file_io` / `fmt_string` / `deserialize` / `crypto` | Varies |
| `taint-ldap-injection` | `ldap_injection` | High |
| `taint-xpath-injection` | `xpath_injection` | High |
| `taint-header-injection` | `header_injection` | High |
| `taint-open-redirect` | `open_redirect` | Medium |
| `taint-template-injection` | `ssti` | High |
| `taint-xxe` | `xxe` | High |
| `taint-prototype-pollution` | `prototype_pollution` | High |
| `taint-data-exfiltration` | `data_exfil` | High / Medium |
| `rs.auth.missing_ownership_check.taint` | `unauthorized_id` | High |

Each cap-class entry is registered in `CAP_RULE_REGISTRY` (`src/labels/mod.rs`). Browse the registry from the CLI with `nyx rules list --class-only`, or via the dashboard's Rules page. The matcher sets (sources, sanitizers, sinks, gated sinks) live per-language in `src/labels/<lang>.rs`. [Language maturity](language-maturity.md) gives per-language counts and what's covered.

### CFG structural

| Rule ID | Severity |
|---|---|
| `cfg-unguarded-sink` | High/Medium |
| `cfg-auth-gap` | High |
| `cfg-unreachable-sink` | Medium |
| `cfg-unreachable-sanitizer` | Low |
| `cfg-unreachable-source` | Low |
| `cfg-error-fallthrough` | High/Medium |
| `cfg-resource-leak` | Medium |
| `cfg-lock-not-released` | Medium |

### State model

| Rule ID | Severity |
|---|---|
| `state-use-after-close` | High |
| `state-double-close` | Medium |
| `state-resource-leak` | Medium |
| `state-resource-leak-possible` | Low |
| `state-unauthed-access` | High |

### Auth analysis (Rust only, today)

| Rule ID | Severity |
|---|---|
| `rs.auth.missing_ownership_check` | High |
| `rs.auth.missing_ownership_check.taint` | High (gated by `scanner.enable_auth_as_taint`) |

See [auth.md](auth.md) for scope, the five sink-classes, and tuning.

## AST patterns by language

Each language ships a tree-sitter pattern registry. Structural match on the pattern, no dataflow. Some patterns also have a Tier B heuristic guard (e.g. SQL execute must receive a concatenation, not a literal) noted in the registry.

The tables below are generated from `src/patterns/<lang>.rs` by [`tools/docgen`](https://github.com/elicpeter/nyx/tree/master/tools/docgen). Run `cargo run --features docgen --bin nyx-docgen` after changing the registry to refresh them.

<!-- BEGIN AUTOGEN rules-by-language -->

### C: 8 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `c.cmdi.system` | High | A | High |
| `c.memory.gets` | High | A | High |
| `c.memory.printf_no_fmt` | High | B | Medium |
| `c.memory.scanf_percent_s` | High | A | High |
| `c.memory.sprintf` | High | A | High |
| `c.memory.strcat` | High | A | High |
| `c.memory.strcpy` | High | A | High |
| `c.cmdi.popen` | Medium | A | High |

### C++: 9 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `cpp.cmdi.popen` | High | A | High |
| `cpp.cmdi.system` | High | A | High |
| `cpp.memory.gets` | High | A | High |
| `cpp.memory.printf_no_fmt` | High | B | Medium |
| `cpp.memory.sprintf` | High | A | High |
| `cpp.memory.strcat` | High | A | High |
| `cpp.memory.strcpy` | High | A | High |
| `cpp.memory.const_cast` | Medium | A | High |
| `cpp.memory.reinterpret_cast` | Medium | A | High |

### Go: 8 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `go.cmdi.exec_command` | High | A | High |
| `go.transport.insecure_skip_verify` | High | A | High |
| `go.deser.gob_decode` | Medium | A | High |
| `go.memory.unsafe_pointer` | Medium | A | High |
| `go.secrets.hardcoded_key` | Medium | A | High |
| `go.sqli.query_concat` | Medium | B | Medium |
| `go.crypto.md5` | Low | A | Medium |
| `go.crypto.sha1` | Low | A | Medium |

### Java: 9 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `java.cmdi.runtime_exec` | High | A | High |
| `java.code_exec.text4shell_interpolator` | High | A | High |
| `java.deser.readobject` | High | A | High |
| `java.deser.snakeyaml_unsafe_constructor` | High | A | High |
| `java.crypto.weak_algorithm` | Medium | A | Medium |
| `java.reflection.class_forname` | Medium | A | High |
| `java.reflection.method_invoke` | Medium | A | High |
| `java.sqli.execute_concat` | Medium | B | Medium |
| `java.crypto.insecure_random` | Low | A | Medium |

### JavaScript: 23 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `js.code_exec.eval` | High | A | High |
| `js.code_exec.new_function` | High | A | High |
| `js.config.cors_dynamic_origin` | High | A | Medium |
| `js.code_exec.settimeout_string` | Medium | A | High |
| `js.config.insecure_session_httponly` | Medium | A | High |
| `js.config.reject_unauthorized` | Medium | A | High |
| `js.config.verbose_error_response` | Medium | A | Medium |
| `js.crypto.weak_hash_import` | Medium | A | Medium |
| `js.prototype.extend_object` | Medium | A | High |
| `js.prototype.proto_assignment` | Medium | A | High |
| `js.secrets.fallback_secret` | Medium | A | Medium |
| `js.xss.cookie_write` | Medium | A | High |
| `js.xss.document_write` | Medium | A | High |
| `js.xss.insert_adjacent_html` | Medium | A | High |
| `js.xss.location_assign` | Medium | A | High |
| `js.xss.outer_html` | Medium | A | High |
| `js.config.insecure_session_samesite` | Low | A | High |
| `js.config.insecure_session_secure` | Low | A | Medium |
| `js.crypto.hardcoded_key` | Low | A | Medium |
| `js.crypto.math_random` | Low | A | Medium |
| `js.crypto.weak_hash` | Low | A | Medium |
| `js.secrets.hardcoded_secret` | Low | A | Medium |
| `js.transport.fetch_http` | Low | A | Medium |

### PHP: 11 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `php.cmdi.system` | High | A | High |
| `php.code_exec.assert_string` | High | A | High |
| `php.code_exec.create_function` | High | A | High |
| `php.code_exec.eval` | High | A | High |
| `php.code_exec.preg_replace_e` | High | A | High |
| `php.deser.unserialize` | High | A | High |
| `php.path.include_variable` | High | B | Medium |
| `php.sqli.query_concat` | Medium | B | Medium |
| `php.crypto.md5` | Low | A | Medium |
| `php.crypto.rand` | Low | A | Medium |
| `php.crypto.sha1` | Low | A | Medium |

### Python: 17 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `py.cmdi.os_popen` | High | A | High |
| `py.cmdi.os_system` | High | A | High |
| `py.cmdi.subprocess_shell` | High | B | Medium |
| `py.code_exec.eval` | High | A | High |
| `py.code_exec.exec` | High | A | High |
| `py.deser.pickle_loads` | High | A | High |
| `py.deser.yaml_load` | High | A | High |
| `py.code_exec.compile` | Medium | A | High |
| `py.deser.shelve_open` | Medium | A | High |
| `py.sqli.execute_format` | Medium | B | Medium |
| `py.sqli.text_format` | Medium | B | Medium |
| `py.xss.jinja_from_string` | Medium | A | High |
| `py.xss.make_response_format` | Medium | B | Medium |
| `py.crypto.md5` | Low | A | Medium |
| `py.crypto.md5_bare` | Low | A | Low |
| `py.crypto.sha1` | Low | A | Medium |
| `py.crypto.sha1_bare` | Low | A | Low |

### Ruby: 11 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `rb.cmdi.backtick` | High | A | High |
| `rb.cmdi.system_interp` | High | A | High |
| `rb.code_exec.class_eval` | High | A | High |
| `rb.code_exec.eval` | High | A | High |
| `rb.code_exec.instance_eval` | High | A | High |
| `rb.deser.marshal_load` | High | A | High |
| `rb.deser.yaml_load` | High | A | High |
| `rb.reflection.constantize` | Medium | A | High |
| `rb.reflection.send_dynamic` | Medium | B | Medium |
| `rb.ssrf.open_uri` | Medium | A | High |
| `rb.crypto.md5` | Low | A | Medium |

### Rust: 13 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `rs.memory.copy_nonoverlapping` | High | A | High |
| `rs.memory.get_unchecked` | High | A | High |
| `rs.memory.mem_zeroed` | High | A | High |
| `rs.memory.ptr_read` | High | A | High |
| `rs.memory.transmute` | High | A | High |
| `rs.quality.unsafe_block` | Medium | A | High |
| `rs.quality.unsafe_fn` | Medium | A | High |
| `rs.memory.mem_forget` | Low | A | High |
| `rs.memory.narrow_cast` | Low | A | Medium |
| `rs.quality.expect` | Low | A | High |
| `rs.quality.panic_macro` | Low | A | High |
| `rs.quality.todo` | Low | A | High |
| `rs.quality.unwrap` | Low | A | High |

### TypeScript: 23 patterns

| Rule ID | Severity | Tier | Confidence |
|---|---|---|---|
| `ts.code_exec.eval` | High | A | High |
| `ts.code_exec.new_function` | High | A | High |
| `ts.config.cors_dynamic_origin` | High | A | Medium |
| `ts.code_exec.settimeout_string` | Medium | A | High |
| `ts.config.insecure_session_httponly` | Medium | A | High |
| `ts.config.reject_unauthorized` | Medium | A | High |
| `ts.config.verbose_error_response` | Medium | A | Medium |
| `ts.crypto.weak_hash_import` | Medium | A | Medium |
| `ts.prototype.proto_assignment` | Medium | A | High |
| `ts.secrets.fallback_secret` | Medium | A | Medium |
| `ts.xss.document_write` | Medium | A | High |
| `ts.xss.insert_adjacent_html` | Medium | A | High |
| `ts.xss.location_assign` | Medium | A | High |
| `ts.xss.outer_html` | Medium | A | High |
| `ts.config.insecure_session_samesite` | Low | A | High |
| `ts.config.insecure_session_secure` | Low | A | Medium |
| `ts.crypto.hardcoded_key` | Low | A | Medium |
| `ts.crypto.math_random` | Low | A | Medium |
| `ts.crypto.weak_hash` | Low | A | Medium |
| `ts.quality.any_annotation` | Low | A | Medium |
| `ts.quality.as_any` | Low | A | Medium |
| `ts.secrets.hardcoded_secret` | Low | A | Medium |
| `ts.xss.cookie_write` | Low | A | Medium |

<!-- END AUTOGEN rules-by-language -->

## Capability list for custom rules

`nyx config add-rule --cap <name>` and `[analysis.languages.*.rules]` in config accept:

`env_var`, `html_escape`, `shell_escape`, `url_encode`, `json_parse`, `file_io`, `fmt_string`, `sql_query`, `deserialize`, `ssrf`, `code_exec`, `crypto`, `unauthorized_id`, `data_exfil`, `ldap_injection`, `xpath_injection`, `header_injection`, `open_redirect`, `ssti`, `xxe`, `prototype_pollution`, `all`

Aliases: `data_exfiltration` for `data_exfil`, `ldapi` for `ldap_injection`, `xpathi` for `xpath_injection`, `crlf` and `response_splitting` for `header_injection`, `redirect` for `open_redirect`, `template_injection` for `ssti`, `proto_pollution` for `prototype_pollution`.

Source for both the enum and the `to_cap` mapping: [`src/labels/mod.rs`](https://github.com/elicpeter/nyx/blob/master/src/labels/mod.rs) (`Cap` and `CAP_RULE_REGISTRY`) and [`src/utils/config.rs`](https://github.com/elicpeter/nyx/blob/master/src/utils/config.rs) (`CapName`).

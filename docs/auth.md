# Auth analysis

**Rust today.** Other languages have rule scaffolding in [`src/auth_analysis/config.rs`](https://github.com/elicpeter/nyx/blob/master/src/auth_analysis/config.rs) (Python, Ruby, Go, Java, JavaScript, TypeScript), but only Rust has benchmark corpus coverage and the precision work to back it. Treat findings on other languages as preview; the rule prefix (`py.auth.*`, `js.auth.*`, `rb.auth.*`, `go.auth.*`, `java.auth.*`) is reserved but the matchers haven't been validated against real codebases yet.

## What it catches

The Rust rule is `rs.auth.missing_ownership_check`. It fires when a request handler reaches a privileged operation that takes a scoped identifier (`*_id`, row reference, scoped resource) without a preceding ownership or membership check.

Concretely, it looks for these patterns of authorization in the function body and flags the call when none are present:

- A call to a recognised authorization helper. Defaults: `check_ownership`, `has_ownership`, `require_ownership`, `ensure_ownership`, `is_owner`, `authorize`, `verify_access`, `has_permission`, `can_access`, `can_manage`, plus `*_membership` and `require_{group,org,workspace,tenant,team}_member` variants. Extend in `[analysis.languages.rust]`.
- An ownership-equality check on a row reference: `if owner_id != user.id { return 403 }` or any `field_id != self_actor` shape. The check writes `AuthCheck` evidence back to the row-fetch arguments via `AnalysisUnit.row_field_vars`.
- A self-actor reference: `let user = require_auth(...).await?` followed by use of `user.id`, `user.user_id`, `user.uid`. The actor is recognised from typed extractor params (`Extension<Session>`, `CurrentUser`, etc.) and from typed helper bindings.
- A typed extractor wrapper that proves route-level capability/policy enforcement: meilisearch-style `GuardedData<ActionPolicy<X>, _>`. Recognised by outer wrapper name (last segment, case-insensitive `starts_with`) so `GuardedData<ActionPolicy<X>, Data<AuthController>>` is classified by the outer `GuardedData`, not by whether an inner generic arg substring-matches `auth`. Configured via `policy_guard_names` (Rust default: `["Guarded"]`). Distinct from authentication-only wrappers so the pattern doesn't pollute regular call recognition.
- A SQL query that joins through an ACL table or filters by `user_id` predicate. Detected without a SQL parser via [`sql_semantics.rs`](https://github.com/elicpeter/nyx/blob/master/src/auth_analysis/sql_semantics.rs); the authorized result variable propagates through `let row = ...prepare(LIT)...`, `for row in result`, `let id = row.get(...)`.
- A helper-summary lift: handler calls `validate_target(db, widget_id, user.id)` whose body contains a `require_*_member` call. Cross-function summaries are merged at fixed-point (capped at 4 iterations).

Handlers registered through attribute macros (`#[get("/path")]`, `#[routes::path(…)]`) or external service-config builders are also walked for typed-extractor guards, complementing the `.route(...)` registration path.

## Caller-scope-entity exemption

`<entity>.id` / `<entity>.pk` is not flagged when `<entity>` is a unit parameter named after a multi-tenant scope primitive: `organization` / `org`, `project`, `team`, `workspace`, `tenant`, `account`, `community`, `group`, `repository` / `repo`, `company`. The argument represents the caller's scope, not a user-controlled target, so internal helpers like `def get_environments(request, organization): Environment.objects.filter(organization_id=organization.id, …)` inherit the caller's authorization. Other field names (`.name`, `.slug`) still flag, and `user` / `member` / `actor` are deliberately excluded; those are handled by the actor-context recogniser.

## Project-level web-framework gate (Rust)

In Rust, the `context_inputs` and param-name arms of the user-input heuristic are gated by a project-level web-framework signal. The signal is three-valued:

- `Some(true)`: the project's `Cargo.toml` names `axum`, `actix-web`, or `rocket`, OR the file directly imports one (`axum::`, `actix_web::`, `rocket::`, `axum_extra::`). Heuristics stay on.
- `Some(false)`: `Cargo.toml` was inspected and named no web framework, AND the file does not directly import one. Heuristics off; only `RouteHandler` classification (concrete route-registration evidence) survives.
- `None`: no detection ran (single-file scan with no project root). Heuristics on; behavior unchanged.

This avoids a class of FPs in non-web Rust crates where a debug-session handle named `session` would trip on `session.update(cx, …)`-style desktop-app code. Other languages keep prior behavior; the gate is currently Rust-only.

## Sink classification

The same call name can be safe on a local collection and dangerous on a database. The detector categorises each candidate sink before deciding whether to flag:

| Class | Examples | Default treatment |
|---|---|---|
| `InMemoryLocal` | `map.insert`, `set.insert`, `vec.push` on tracked local | Never a sink |
| `RealtimePublish` | `realtime.publish_to_group`, `pubsub.send` | Sink unless ownership is established for the channel scope |
| `OutboundNetwork` | `http.post`, `reqwest::Client::post` | Sink unless a sanitiser is on the path |
| `CacheCrossTenant` | `redis.set`, `memcached.set` with scoped keys | Sink unless tenant is checked |
| `DbMutation` | `db.insert`, `repo.save` with scoped IDs | Sink unless ownership is established |
| `DbCrossTenantRead` | `db.query` returning rows from a tenant scope | Sink unless ACL-join or tenant predicate is present |

Receiver type drives the classification when SSA type facts are available, so `client.send(...)` correctly resolves through the receiver's inferred type.

## What it can't catch

- **Non-Rust frameworks**, in practice. Scaffolding exists; coverage doesn't.
- **Type-system authorization.** A typestate pattern that makes unauthenticated handlers fail to compile (`fn endpoint(user: AuthenticatedUser<Admin>)`) is invisible. This is mostly fine because the type system already enforced the check, but the rule won't credit it.
- **Authorization performed only via macros** that the AST doesn't expose as a recognisable call.
- **Cross-async-boundary actor binding.** If the handler awaits `let user = require_auth(...).await?` and then spawns a task that uses `user.id` after a `tokio::spawn`, the spawn body is treated as a separate scope.

## The taint-based variant

A second rule, `rs.auth.missing_ownership_check.taint`, folds the same logic into the SSA/taint engine using the `Cap::UNAUTHORIZED_ID` capability (bit 12). Request-bound handler parameters seed `UNAUTHORIZED_ID` into taint state; ownership checks act as sanitizers that strip the cap; sinks that take scoped IDs require it absent.

This path is **off by default** while the standalone analyser carries the stable signal. Enable both:

```toml
[scanner]
enable_auth_as_taint = true
```

Run them together; if both fire for the same site, treat it as the same finding (the taint variant carries fuller flow evidence).

## Tuning

### Add a project-specific authorization helper

```toml
[[analysis.languages.rust.rules]]
matchers = ["require_subscription", "ensure_paid_seat"]
kind     = "sanitizer"
cap      = "unauthorized_id"
```

The same rule recognised in the standalone analyser also strips `Cap::UNAUTHORIZED_ID` for the taint-based variant.

### Add a project-specific typed-extractor policy wrapper

```toml
[analysis.languages.rust.auth]
policy_guard_names = ["MyAppGuarded", "PolicyExtractor"]
```

Matched as last-segment + case-insensitive `starts_with` (so a single entry `"Guarded"` covers `Guarded`, `GuardedData`, `GuardedRoute`). Distinct from `login_guard_names` and `admin_guard_names`.

### Recognised actor names

Recognised by default: `user.id`, `user.user_id`, `user.uid`, `session.user_id`, `current_user.id`, plus typed extractor parameters with `CurrentUser`, `SessionUser`, `AuthUser`, `Extension<...>` shapes. To add a custom binding pattern, file an issue or add a fixture; the heuristic is in [`src/auth_analysis/checks.rs`](https://github.com/elicpeter/nyx/blob/master/src/auth_analysis/checks.rs) under `extract_validation_target` and friends.

### Suppress

Inline:

```rust
db.insert(widget_id, value)?;  // nyx:ignore rs.auth.missing_ownership_check
```

Or filter by severity / confidence in CI:

```bash
nyx scan . --severity ">=MEDIUM" --min-confidence medium
```

## In the UI

Auth findings render alongside taint findings in the [browser UI](serve.md). The flow visualiser shows the sink call, the actor reference (when one was found), and any helper-summary path the engine traversed; the How to fix panel mirrors the rule's recommendation.

<p align="center"><img src="assets/screenshots/docs/serve-finding-detail.png" alt="Nyx finding detail: numbered source → call → sink walk with a How to fix panel and an inline evidence object" width="900"/></p>

## Benchmark corpus

The Rust auth corpus at [`tests/benchmark/corpus/rust/auth/`](https://github.com/elicpeter/nyx/tree/master/tests/benchmark/corpus/rust/auth/) covers the recognised authorization patterns, true-positive controls, typed-extractor guard injection, and the project-level web-framework gate (full-Cargo.toml fixtures under `safe_non_web_rust_project/` and `unsafe_actix_web_project_no_check/`). Per-row metrics live under the Rust auth row in `tests/benchmark/RESULTS.md`.

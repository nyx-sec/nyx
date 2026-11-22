# Auth analysis

Rust is the stable target. Python and Go shipped precision work as of 0.7.0 (FastAPI cross-file dependencies, Go DAO-helper filtering, same-file caller-scope IPA) and are usable on real codebases. Ruby, Java, JavaScript, and TypeScript have rule scaffolding in [`src/auth_analysis/config.rs`](https://github.com/nyx-sec/nyx/blob/master/src/auth_analysis/config.rs) but no benchmark corpus yet; treat findings there as preview.

## What it catches

The Rust rule is `rs.auth.missing_ownership_check`. It fires when a request handler reaches a privileged operation that takes a scoped identifier (`*_id`, row reference, scoped resource) without a preceding ownership or membership check.

It looks for these authorization patterns in the function body and flags the call when none are present:

- A call to a recognised authorization helper. Defaults: `check_ownership`, `has_ownership`, `require_ownership`, `ensure_ownership`, `is_owner`, `authorize`, `verify_access`, `has_permission`, `can_access`, `can_manage`, plus `*_membership` and `require_{group,org,workspace,tenant,team}_member` variants. Extend in `[analysis.languages.rust]`.
- An ownership-equality check on a row reference: `if owner_id != user.id { return 403 }` or any `field_id != self_actor` shape. The check writes `AuthCheck` evidence back to the row-fetch arguments via `AnalysisUnit.row_field_vars`.
- A self-actor reference: `let user = require_auth(...).await?` followed by use of `user.id`, `user.user_id`, `user.uid`. The actor is recognised from typed extractor params (`Extension<Session>`, `CurrentUser`, etc.) and from typed helper bindings.
- A typed extractor wrapper that proves route-level capability/policy enforcement, meilisearch-style `GuardedData<ActionPolicy<X>, _>`. Recognised by outer wrapper name (last segment, case-insensitive `starts_with`), so `GuardedData<ActionPolicy<X>, Data<AuthController>>` is classified by the outer `GuardedData` rather than by whether an inner generic arg substring-matches `auth`. Configured via `policy_guard_names` (Rust default: `["Guarded"]`), and kept distinct from authentication-only wrappers so the pattern doesn't pollute regular call recognition.
- A SQL query that joins through an ACL table or filters by `user_id` predicate. Detected without a SQL parser via [`sql_semantics.rs`](https://github.com/nyx-sec/nyx/blob/master/src/auth_analysis/sql_semantics.rs); the authorized result variable propagates through `let row = ...prepare(LIT)...`, `for row in result`, `let id = row.get(...)`.
- A helper-summary lift: handler calls `validate_target(db, widget_id, user.id)` whose body contains a `require_*_member` call. Cross-function summaries are merged at fixed-point (capped at 4 iterations).

Handlers registered through attribute macros (`#[get("/path")]`, `#[routes::path(...)]`) or external service-config builders are also walked for typed-extractor guards, complementing the `.route(...)` registration path.

## Caller-scope-entity exemption

`<entity>.id` / `<entity>.pk` is not flagged when `<entity>` is a unit parameter named after a multi-tenant scope primitive: `organization` / `org`, `project`, `team`, `workspace`, `tenant`, `account`, `community`, `group`, `repository` / `repo`, `company`. The argument represents the caller's scope, not a user-controlled target, so internal helpers like `def get_environments(request, organization): Environment.objects.filter(organization_id=organization.id, ...)` inherit the caller's authorization. Other field names (`.name`, `.slug`) still flag, and `user` / `member` / `actor` are deliberately excluded; those are handled by the actor-context recogniser.

## What counts as an identifier

A subject is a scoped id when its name reads as one: `id`, `user_id`, `userId`, `userID`, `UserIDs`, `userid`, `uuid`. The match is made on word boundaries, so ordinary words that end in the letters "id" (`grid`, `valid`, `paid`, `android`, `void`, `fluid`) are not ids. A single lowercase token such as `docid` is accepted unless the whole word is plain English; the list lives in [`naming.rs`](https://github.com/nyx-sec/nyx/blob/master/src/auth_analysis/naming.rs).

A `uid` is treated as a possible schema selector. Strapi, for one, passes a content-type UID such as `api::article.article` to `strapi.getModel(uid)` and `db.query(uid)`. Outside a route handler a bare `uid` is not a subject and a `uid` parameter does not make a helper an entry point. In a route handler, or when it is read off a request chain, it stays a subject.

## Go: request roots and package names

`Get`, `Query`, `Param` and friends are user input only on the request. For Go the extractor collects the parameters and receiver whose type is `*http.Request`, a framework context (`*gin.Context`, `echo.Context`, `*fiber.Ctx`, `*context.APIContext`, a package-local `*Context`) and the locals copied from them (`q := r.URL.Query()`, `repo := ctx.Repo.Repository`). A `cache.Get("k")`, `resp.Header.Get("ETag")` or `db.Query(sql)` on anything else does not open the function as a request entry point.

The same set makes request-context chains readable:

- `ctx.Doer.ID` (also `User`, `SignedUser`) is the signed-in user.
- `ctx.Repo.Repository.ID`, `ctx.Org.Organization.ID`, `ctx.Package.Owner.ID` are the repo, organisation or package owner the router resolved from the URL and checked before the handler ran. They are scope, not foreign ids. A chain that goes through request payload (`ctx.Req.Form.ID`) is not.
- A call that also passes a scope id, such as `GetLabelInRepoByID(ctx, repo.ID, labelID)`, is confined to that scope and is not flagged. The unscoped `GetLabelByID(ctx, labelID)` still is. This co-subject rule applies to every language, next to the existing actor co-subject rule.

A selector rooted at an imported package (`common.LDAPUID`, `grid.GetByteBuffer()`) or at a file-level const names a declaration and is never a per-request value. A parameter or local with the same name shadows it, so a `event *Event` parameter next to an `event` import is still a subject.

Values that cannot be a data-layer client are not sinks: an id or a collection of ids (`uniqueIDs.Remove(0)`, `r.configVersionID.Load()`), `make`/map/slice/`sync`/`atomic`/`url.Values`/set locals, the standard-library helper packages (`slices`, `sort`, `strings`, ...), request data fields (`r.Header.Add`, `r.Form.Get`), and router registrations (`m.Get("/blob/{sha}", handler)`).

Internal helpers whose id parameters have a named id type (`portainer.EndpointID`, `...TargetID`) or are slices and maps of ids are treated like the bounded-scalar helpers above. A Go `row, err := Fetch(...)` records the row, so a permission check on `row` after the fetch covers the fetch, as in the other languages.

## JavaScript and TypeScript

- **Browser code is skipped.** A unit is browser code when its file starts with `'use client'`, it is named or calls like a React hook (`useState`, `useSidebarLabel`), it calls a binding imported from a browser-only module (`react-query`, `swr`, `mobx-react`, `react-dom`, `@angular/*`, ...), or it is a synchronous function that builds JSX. A file that imports a web framework or a database client is never browser code. An `async` App Router server component has no hooks and no directive, so it stays in scope.
- **HTTP clients are not queries.** `axios.delete(`/api/todos/${id}`)` and `api.put(url, body)` are requests. Outside a route handler, in a file that is not a server file, they are not checked; the check belongs on the server end.
- **Shorthand properties** count: `where: { id }` carries `id`.
- **Array predicates** (`providers.find((p) => p.id === providerId)`) are not reads, and a function-literal argument contributes no subjects to the call that receives it.
- **Fetch then authorize** survives a later field write, a reassignment, sibling blocks that declare the same name, a `Promise.all` destructure and a `??`/ternary right-hand side. Each binding of a name is kept, so an authorize call on the row covers every fetch of it.
- **Actors**: `const { user } = ctx.state.auth`, `const user = ctx.state.user` and `req.session.userId` are the caller. `user.teamId`, `organizationId`, `tenantId` and `accountId` on a recognised actor are the caller's own tenant. `workspaceId` and `groupId` are not, since a user can belong to several.
- **Route-level middleware.** Express, Koa, Fastify, Gin and Echo routes copy their authorization-bearing middleware onto the handler as a route-level check, the way the decorator frameworks do. A path-less `router.use(mw)` guards the routes registered on that router after it. A handler registered on several routes keeps only the checks every registration has. Login-only middleware never suppresses an ownership finding.
- **Handlers that are not top-level functions** are analysed: `exports.remove = (req, res) => ..`, `module.exports.show = ..`, `module.exports = { update(req, res) {} }` and methods of an undecorated class. Decorated classes (NestJS) are left out because their guards live in decorators the pass does not read yet. Routers can have any name when they are bound from `express()`, `express.Router()` or `new Router()`.
- Sequelize `destroy`, `bulkDestroy` and `upsert` are writes. Schema registry lookups (`strapi.getModel`, `getContentType`) are not reads.

## The caller is not a foreign id

A query or write keyed by the signed-in user is not an ownership gap. These forms are the caller:

- The user object itself: `owner=current_user`, `owner: req.user`, `owner=request.user`, `g.user`.
- The user's own identifiers: `current_user.id`, `request.user.pk`, `req.user._id`, `g.user.id`. Other fields of `current_user` (`organization_id`, `workspace_id`) are not the caller, since a user can belong to several.
- A query that starts at the caller or at a scope that only holds what the caller may reach: `current_user.notes.find(params[:id])`, `request.user.documents.filter(id=doc_id)`, Pundit's `policy_scope(Note).find(..)`, CanCanCan's `Note.accessible_by(ability).find(..)`.

A field named like an owner pin (`ownerId`, `authorId`, `createdBy`) counts only when the caller did not supply it. `req.query.ownerId`, `req.body.ownerId`, a local copied from such a chain and a route handler's own `owner_id` parameter are chosen by whoever sends the request. Pinning a lookup to them scopes nothing, and writing one reassigns the row. A local that was read from a request through a call or a destructure (`const { ownerId } = req.query`) is not traced back yet, so it still counts as the caller.

## Token lookups

The token-override rule looks for a handler that finds a row by an invitation token and then writes through it. A dotted default such as `Invitation.objects.get` (Python) or `Invitation.find_by` (Ruby) keeps its receiver: the callee must end in the same receiver segments, and its last segment must start with the pattern's. So `Document.objects.get(id=doc_id)`, `request.json.get("title")`, `db.session.get(User, user_id)` and `Document.find_by(id: params[:id])` are ordinary reads and go through the ownership rule. A pattern without a dot still matches on the last segment alone (`find_by_token`, `findByToken`). Add your own with `token_lookup_names`.

In Python, `.get(..)` and `.get_*(..)` are reads of rows only on an ORM receiver: a manager (`Model.objects.get`, `Model.objects.get_from_cache`), a query property (`Model.query.get`), a session (`db.session.get`) or a queryset chain (`Model.objects.select_related(..).get`). `options.get(key)`, `cache.get(k)`, `client.get(url)`, `request.GET.get(..)` and object methods such as `group.get_absolute_url(..)` are not operations the ownership rule looks at. Django's `get_object_or_404` is not classified as a read yet: the views that call it usually authorize the row after the fetch with helpers the pass does not recognise (`page.permissions_for_user(user).can_delete()`), so reporting it would add noise on large admin-style Django projects.

## Rails filters

`before_action`, `prepend_before_action` and `skip_before_action` honour `only:` and `except:` written as `[:a, :b]`, `%i[a b]`, `%w[a b]` or a single symbol. An option that is present but is not a literal list (`only: ACTIONS`) cannot be read, so the guard is credited only where it provably applies: a filter with such an option covers no action, and a `skip_before_action` with one is taken to remove the guard from every action.

CanCanCan's `load_and_authorize_resource` and `authorize_resource` are class-level authorization for the actions they cover, with the same `only:` and `except:` options. `skip_authorize_resource` removes them again.

## Django decorators and class views

A view function's auth decorators (`@permission_required(..)`, `@user_passes_test(..)`, `@login_required`) apply to the function wherever its route is registered, so a `views.py` without a `path()` call is read the same way as one with it. `@login_required` alone proves identity, not ownership.

A class that derives from a Django `View` or a DRF `APIView` / `ViewSet` (a base ending in `View` or `ViewSet`) is analysed even when `urls.py` registers it, as long as every base is imported from `django`, `rest_framework` or `flask`. A project-defined base (`class DocView(BaseObjectView)`) can carry permission classes, a restricted queryset or an authorization mixin that the file does not show, so such a class is left alone. Its `get`, `post`, `put`, `patch`, `delete` and the viewset actions `list`, `retrieve`, `create`, `update`, `partial_update`, `destroy` are route handlers, and `@action` methods too. Class decorators, base classes such as `LoginRequiredMixin` and `permission_classes = [..]` are route-level checks: `IsAuthenticated` is a login guard, `IsAdminUser` an admin guard, and `DjangoObjectPermissions` or a custom `IsOwner` an authorization check. Both sides of `A & B` count; `A | B` counts only as much as its weaker side, and `~A` not at all. In a route handler a bare `pk` is an id like `doc_id`.

## axum and actix-web layers

`Router::layer` and `route_layer` wrap the routes added before the call, so the layers that cover a route are the ones applied further out in the same method chain. A layer written before the route (`Router::new().layer(L).route(..)`) wraps nothing. `delete(handler).route_layer(L)` covers its own handler. In actix-web, `.wrap(..)` and `.guard(..)` on a scope or resource cover every route it serves, whether they come before or after the route.

Layers and wraps that carry authorization are copied onto the handler as route-level checks, so `route_layer(from_fn(require_doc_owner))` covers the handler, and an admin layer satisfies the admin-route rule. A login-only layer does neither.

## Role guards

Spring annotations are read from the method's modifiers, so a `@PreAuthorize(` that wraps over several lines, a comment between annotations and a SpEL string split with `+` all work. Each operand of `and` / `&&` is its own check. A request passes `a or b` when either side holds, so a disjunction counts only as much as its weakest side: `hasRole('ADMIN') or hasRole('USER')` is a login guard, and `hasRole('ADMIN') or @sec.isOwner(#id, authentication)` authorizes the row without being an admin guard. A negated operand grants nothing. `hasAnyRole(..)` and `hasAnyAuthority(..)` admit a holder of any listed role, so they are admin guards only when every listed role is an admin, manager or superuser role, and login guards otherwise.

In JavaScript, role middleware (`authorize`, `checkRole`, `requireRoles`, `restrictTo`) is read the same way: `authorize('admin')` and `checkRole(['admin'])` are admin guards, `checkRole(['admin', 'viewer'])` is not.

## Framework detection per language

The project manifests list frameworks for several languages at once, and React is a browser library. An extractor for framework X runs on a file unless the manifests name some other server framework for the file's language. A Next.js repo (`next` and `react`, no Express) still gets the Express, Koa and Fastify route extractors, and a FastAPI backend with a UI `package.json` that lists only React still gets the Flask and FastAPI extractor.

## Project-level web-framework gate (Rust)

In Rust, the `context_inputs` and param-name arms of the user-input heuristic are gated by a project-level web-framework signal. The signal is three-valued:

- `Some(true)`: the project's `Cargo.toml` names `axum`, `actix-web`, or `rocket`, OR the file directly imports one (`axum::`, `actix_web::`, `rocket::`, `axum_extra::`). Heuristics stay on.
- `Some(false)`: `Cargo.toml` was inspected and named no web framework, AND the file does not directly import one. Heuristics off; only `RouteHandler` classification (concrete route-registration evidence) survives.
- `None`: no detection ran (single-file scan with no project root). Heuristics on; behavior unchanged.

This avoids a class of FPs in non-web Rust crates where a debug-session handle named `session` would trip on `session.update(cx, ...)`-style desktop-app code. Other languages keep prior behavior; the gate is currently Rust-only.

## Python: FastAPI cross-file dependencies

FastAPI's `include_router` chain is resolved across files. A child router declared in `routes/task_instances.py` and attached on a parent in `routes/__init__.py` inherits the parent's `dependencies=[...]`.

- Module-level `router = APIRouter(dependencies=[Security(...)])` is pre-walked once per file and merged onto every `@<router>.<verb>(...)` route attached in the same file.
- `<parent>.include_router(<child_module>.<child_var>)` edges are captured per file in pass 1, persisted into `GlobalSummaries::router_facts_by_module`, and lifted onto the active file's `AuthorizationModel::cross_file_router_deps` at pass 2 entry. Transitive lifts (grandparent to parent to child) iterate to fixpoint.
- `Security(callable, scopes=[...])` is recognised distinctly from `Depends(callable)` and promotes the synthetic `AuthCheck` to `AuthCheckKind::Other` (route-level scope-checked authorization). Bare `Depends(callable)` is still a Login-only check.

Module identity is the file basename without `.py`. That is sufficient for airflow-style `task_instances.router` naming; a project with two files of the same name in different subtrees will currently collide.

## Go: DAO-helper id-scalar precision pass

For non-route Go units, a parameter whose declared type is a bounded primitive scalar (`int64`, `uint32`, `string`, `bool`, `byte`, `rune`, `float64`, etc.) and whose name is id-shaped (`id`, `*Id`, `*_id`, `*ids`) is dropped from `unit.params` before ownership-check evaluation.

Real Go HTTP handlers always carry a framework-request-typed param (`*http.Request`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`); per-framework route extractors set `include_id_like_typed=true` so id-shaped path params survive on real routes. The filter only fires when the unit was not classified as a route handler, so helpers like `func GetRunByRepoAndID(ctx, repoID, runID int64)` are recognised as DAO callees and the ownership check is expected at the calling route handler, not inside the helper.

## Same-file caller-scope IPA

When a private helper is called only from authorized route handlers in the same file, the caller's auth checks lift onto the helper as synthetic `is_route_level=true` `AuthCheck` entries.

- Iterated to a small fixpoint so transitive chains (route to mid_helper to leaf_helper) are covered.
- Refuses to authorize helpers with no in-file caller, helpers called from a mix of authorized and unauthorized callers, and helpers called only from un-lifted helpers.
- Cross-file caller-scope lifting is not implemented yet.

This closes the FastAPI / Django / Flask shape where a route authenticates via decorator or dependency, then delegates to a private helper that performs the sink.

## Sink classification

The same call name can be safe on a local collection and dangerous on a database, so each candidate sink is categorised before the flag decision:

| Class | Examples | Default treatment |
|---|---|---|
| `InMemoryLocal` | `map.insert`, `set.insert`, `vec.push` on tracked local | Never a sink |
| `RealtimePublish` | `realtime.publish_to_group`, `pubsub.send` | Sink unless ownership is established for the channel scope |
| `OutboundNetwork` | `http.post`, `reqwest::Client::post` | Sink unless a sanitiser is on the path |
| `CacheCrossTenant` | `redis.set`, `memcached.set` with scoped keys | Sink unless tenant is checked |
| `DbMutation` | `db.insert`, `repo.save` with scoped IDs | Sink unless ownership is established |
| `DbCrossTenantRead` | `db.query` returning rows from a tenant scope | Sink unless ACL-join or tenant predicate is present |

Receiver type drives the classification when SSA type facts are available, so `client.send(...)` resolves through the receiver's inferred type.

## What it can't catch

- Non-Rust frameworks, in practice. Scaffolding exists; coverage doesn't.
- Type-system authorization. A typestate pattern that makes unauthenticated handlers fail to compile (`fn endpoint(user: AuthenticatedUser<Admin>)`) is invisible. This is mostly fine because the type system already enforced the check, but the rule won't credit it.
- Authorization performed only via macros that the AST doesn't expose as a recognisable call.
- Cross-async-boundary actor binding. If the handler awaits `let user = require_auth(...).await?` and then spawns a task that uses `user.id` after a `tokio::spawn`, the spawn body is treated as a separate scope.

## The taint-based variant

A second rule, `rs.auth.missing_ownership_check.taint`, folds the same logic into the SSA/taint engine using the `Cap::UNAUTHORIZED_ID` capability (bit 12). Request-bound handler parameters seed `UNAUTHORIZED_ID` into taint state; ownership checks act as sanitizers that strip the cap; sinks that take scoped IDs require it absent.

This path is off by default while the standalone analyser carries the stable signal. Enable both:

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

Matched as last-segment + case-insensitive `starts_with`, so a single entry `"Guarded"` covers `Guarded`, `GuardedData`, `GuardedRoute`. Distinct from `login_guard_names` and `admin_guard_names`.

### Recognised actor names

Recognised by default: `user.id`, `user.user_id`, `user.uid`, `session.user_id`, `current_user.id`, plus typed extractor parameters with `CurrentUser`, `SessionUser`, `AuthUser`, `Extension<...>` shapes. To add a custom binding pattern, file an issue or add a fixture; the heuristic lives in [`src/auth_analysis/extract/common.rs`](https://github.com/nyx-sec/nyx/blob/master/src/auth_analysis/extract/common.rs) under the `*self_actor*` helpers (`collect_self_actor_binding`, `collect_typed_extractor_self_actor`, `is_self_actor_type_text`).

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

Auth findings render alongside taint findings in the [browser UI](serve.md). The flow visualiser shows the sink call, the actor reference when one was found, and any helper-summary path the engine traversed; the How to fix panel mirrors the rule's recommendation.

<p align="center"><img src="assets/screenshots/docs/serve-finding-detail.png" alt="Nyx finding detail: numbered source, call and sink walk with a How to fix panel and an inline evidence object" width="900"/></p>

## Benchmark corpus

The Rust auth corpus at [`tests/benchmark/corpus/rust/auth/`](https://github.com/nyx-sec/nyx/tree/master/tests/benchmark/corpus/rust/auth/) covers the recognised authorization patterns, true-positive controls, typed-extractor guard injection, and the project-level web-framework gate (full-Cargo.toml fixtures under `safe_non_web_rust_project/` and `unsafe_actix_web_project_no_check/`). Per-row metrics live under the Rust auth row in `tests/benchmark/RESULTS.md`.

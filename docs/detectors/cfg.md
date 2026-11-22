# CFG structural analysis

Nyx builds an intra-procedural control-flow graph per function and checks structural properties: whether sinks are guarded by sanitizers or validators, whether web handlers check authentication, whether resources are released on all exit paths, and whether error paths terminate before reaching dangerous code.

These detectors use dominator analysis. A guard dominates a sink when the guard must execute before the sink on every path from entry.

## Rule IDs

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

## What it detects

`cfg-unguarded-sink`: a sink call (`system`, `eval`, `Command::new`, `db.execute`, etc.) reachable from function entry without passing any guard or sanitizer that matches the sink's capability.

`cfg-auth-gap`: a function identified as a web handler (by parameter naming conventions like `req`, `res`, `ctx`, `request`, language-dependent) reaches a privileged sink (shell execution, file I/O) with no preceding authentication call. An authentication test written in a branch condition counts as a call: `if (!req.isAuthenticated()) return ..;` and `if not request.user.is_authenticated: return ..` guard what follows, but only when the failed branch cannot rejoin the flow before the sink. A rejection that redirects without returning guards nothing, and a condition that compares the result (`req.isAuthenticated() === false`) or negates a compound test is not read as a guard.

`cfg-unreachable-*`: sinks, sanitizers, or sources in dead code. Usually a refactoring error that silently disabled security-relevant logic.

`cfg-error-fallthrough`: an error-handling branch (null check, error-return check) does not terminate, so execution falls through to a dangerous operation on the error path. A sink whose payload arguments are all constant literals (`exec.Command("sync")`, `res.send('saved')`) does not count, since nothing from the failed call can reach it.

`cfg-resource-leak`, `cfg-lock-not-released`: a resource acquisition (`File::open`, `fopen`, `socket`, `Lock`) is not matched by a release on every exit path from the function.

## What it can't detect

- Inter-procedural guards. Middleware-level auth, helper functions that internally call auth, and cleanup performed in a caller are invisible.
- Dynamic dispatch. Virtual calls, function pointers, and closures resolve to no specific callee.
- Correctness of guards. The detector checks that *a* guard dominates the sink, not that the guard is correct: a no-op `if true {}` would suppress the finding.
- Custom validation logic. Only recognised guard names are checked, so `if password == expected` is not a recognised guard.
- Cross-function resource flows. If a file handle opens in one function and closes in another, the opener gets flagged as a leak. This is the largest source of FPs on factory-pattern code.

## Common false positives

| Scenario | Why | Mitigation |
|---|---|---|
| Framework middleware auth | Handler doesn't call auth directly | Expected; suppress with severity filter or exclude handlers |
| RAII / defer cleanup | Implicit release not visible to CFG (partially handled for Rust Drop and Go defer) | Known limitation |
| Custom guard name | Function not in the recognised guard list | Add it as a sanitizer rule in config |
| Test handlers | Intentional lack of auth | Default non-prod downgrade reduces severity; or exclude test dirs |

## Common false negatives

| Scenario | Why |
|---|---|
| Auth in a called helper | Cross-function guards not tracked |
| Type-system guards | Rust `AuthenticatedUser<T>` wrappers, typestate patterns not analysed |
| Cleanup in `finally`/`ensure`/`defer` in callers | Cross-function cleanup not tracked |

## Tuning

### Recognised guard names

Nyx accepts these patterns as dominating guards:

| Pattern | Applies to |
|---|---|
| `validate*`, `sanitize*` | All sinks |
| `check_*`, `verify_*`, `assert_*` | All sinks |
| `shell_escape` | Shell sinks |
| `html_escape` | HTML/XSS sinks |
| `url_encode` | URL sinks |
| `which` | Shell execution (binary lookup) |

### Recognised auth names

| Pattern | Language |
|---|---|
| `is_authenticated`, `require_auth`, `check_permission`, `authorize`, `authenticate`, `require_login`, `check_auth`, `verify_token`, `validate_token` | Cross-language |
| `middleware.auth`, `auth.required` | Go |
| `isAuthenticated`, `checkPermission`, `hasAuthority`, `hasRole` | Java |

For Rust auth checks (`require_*`, ownership equality, row-level checks), see [auth.md](../auth.md).

### Custom guards

```toml
[[analysis.languages.python.rules]]
matchers = ["validate_request", "check_csrf"]
kind = "sanitizer"
cap  = "all"
```

### Custom auth functions

```toml
[[analysis.languages.javascript.rules]]
matchers = ["ensureLoggedIn", "requirePermission"]
kind = "sanitizer"
cap  = "all"
```

## Examples

Unguarded sink:

```go
func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", cmd).Run()  // cfg-unguarded-sink
}
```

Auth gap:

```javascript
app.get('/admin/delete', (req, res) => {
    // No auth call
    db.execute("DELETE FROM users WHERE id = " + req.params.id);  // cfg-auth-gap
});
```

Resource leak:

```c
void process() {
    FILE *f = fopen("data.txt", "r");
    if (error) {
        return;           // cfg-resource-leak: f not closed on this path
    }
    fclose(f);
}
```

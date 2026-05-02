# AST patterns

AST patterns are tree-sitter queries that match dangerous structural shapes in source. No dataflow, no CFG. A match means the construct is present; it's not proof the construct is exploitable.

Patterns run in every analysis mode. In `--mode ast` they're the only active detector.

## Rule IDs

```
<lang>.<category>.<name>
```

Examples: `js.code_exec.eval`, `py.deser.pickle_loads`, `c.memory.gets`, `java.sqli.execute_concat`.

Full list: [rules.md](../rules.md).

## Tiers

| Tier | Meaning |
|---|---|
| **A** | Structural presence alone is high-signal. `gets`, `eval`, `pickle.loads`, `mem::transmute` |
| **B** | Pattern includes a tree-sitter heuristic guard. Example: `java.sqli.execute_concat` only fires when `executeQuery` receives a `binary_expression` (string concatenation), not a literal or a parameterized statement |

## Categories

| Category | Examples |
|---|---|
| CommandExec | `system`, `os.system`, `Runtime.exec`, backticks |
| CodeExec | `eval`, `Function`, PHP `assert("string")`, `class_eval`, `instance_eval` |
| Deserialization | `pickle.loads`, `yaml.load`, `Marshal.load`, `readObject`, `unserialize` |
| SqlInjection | `executeQuery`/`Query`/`execute` with concatenated argument (Tier B) |
| PathTraversal | PHP `include $var` |
| Xss | `document.write`, `outerHTML`, `insertAdjacentHTML`, `getWriter().print` |
| Crypto | `md5`, `sha1`, `Math.random`, `java.util.Random` for security use |
| Secrets | hardcoded API keys (Go, JS, TS) |
| InsecureTransport | `InsecureSkipVerify`, `fetch("http://...")` |
| Reflection | `Class.forName`, `Method.invoke`, `send`, `constantize` |
| MemorySafety | `transmute`, `unsafe`, `gets`, `strcpy`, `sprintf` |
| Prototype | `__proto__` assignment, `Object.prototype.*` |
| Config | CORS dynamic origin, `rejectUnauthorized: false`, insecure session settings |
| CodeQuality | `unwrap`, `panic!`, `as any` |

## What patterns can't tell you

- **Dataflow.** `eval("1+1")` (safe) and `eval(userInput)` (dangerous) both match `js.code_exec.eval`. The taint detector is the one that distinguishes them.
- **Reachability.** A pattern in dead code matches identically.
- **Semantics.** `strcpy(dst, src)` always matches, regardless of buffer sizes.
- **Indirect calls.** `let e = eval; e(input)` doesn't match `eval`.
- **Aliased imports.** `from os import system as s; s(cmd)` won't match `system`.
- **Macro expansions.** Tree-sitter parses the macro call site, not the expansion.

## Common false positives

| Scenario | Why | Mitigation |
|---|---|---|
| `eval("hardcoded literal")` | Pattern matches structure | Run `--mode cfg` to drop AST patterns and rely on taint |
| `unsafe` block with sound justification | Every `unsafe` matches `rs.quality.unsafe_block` | Filter `>=MEDIUM` (it's Medium) or accept the noise |
| `.unwrap()` in tests | Acceptable in test code | Default non-prod severity downgrade reduces it |
| `md5` for non-cryptographic checksums | Pattern can't see intent in most languages | PHP recognises non-crypto consuming context structurally (cache keys, ETag, dedup, `getCacheKey()` returns) and suppresses. Other languages: `--severity ">=MEDIUM"` or per-line `nyx:ignore` |
| SQL concat with trusted data (Tier B) | Heuristic can't verify the source | Taint is more precise; or convert to a parameterized query |
| C++ `reinterpret_cast<T>(...)` for byte-pointer / void* / `sockaddr` | Pattern fires on every cast regardless of target type | Suppressed when the target is well-defined by C++ aliasing rules: `char*`, `unsigned char*`, `signed char*`, `wchar_t*`, `uint8_t*`, `int8_t*`, `std::byte*`, `byte*`, `void*`, `uintptr_t` / `intptr_t` (and `std::` variants), and the BSD socket address family. User-defined struct or class pointer targets keep firing. |
| JS / TS `secrets.fallback_secret` on `process.env.X \|\| ""` | Empty-string fallback satisfies non-undefined string types without committing a secret | Empty-string fallbacks are excluded from the rule. Non-empty literal fallbacks still fire. |

## Confidence levels

Every AST pattern carries an explicit confidence:

| Confidence | Use |
|---|---|
| High | Inherently dangerous construct with no safe usage. `gets`, `pickle.loads`, `eval` with no guard |
| Medium | Likely issue, context may change the call. SQL concatenation (Tier B), `unsafe` blocks, `exec` |
| Low | Heuristic. Often appears in safe code. Weak crypto for checksums, `unwrap` outside tests, `Math.random` |

`--min-confidence medium` (or `output.min_confidence = "medium"`) drops Low-confidence matches.

## Tuning

```bash
nyx scan . --severity ">=MEDIUM"        # drop Low-tier patterns
nyx scan . --severity HIGH              # banned APIs and code-exec only
nyx scan . --mode cfg                   # drop AST patterns; keep taint + state + cfg
```

```toml
[scanner]
excluded_directories = ["node_modules", "vendor", "generated"]
```

## Examples

Tier A, structural presence:

```c
char buf[64];
gets(buf);                              // c.memory.gets
```

```python
import pickle
data = pickle.loads(user_input)         // py.deser.pickle_loads
```

Tier B, heuristic guard:

```java
// Fires: concatenated argument
stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);  // java.sqli.execute_concat

// Does not fire: parameterized
stmt.executeQuery(preparedSql);
```

```c
printf(user_input);                     // c.memory.printf_no_fmt: fires (variable as fmt)
printf("%s", user_input);               // does not fire (literal fmt)
```

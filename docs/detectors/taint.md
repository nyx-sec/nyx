# Taint analysis

Nyx tracks untrusted data from **sources** (where it enters the program) through assignments and function calls to **sinks** (where it's used dangerously). If the flow reaches a sink without passing a matching **sanitizer**, a finding fires.

The engine is a monotone forward dataflow over a finite lattice with guaranteed termination. It's flow-sensitive inside a function, and interprocedural across files via persisted per-function summaries.

## Rule ID

```
taint-unsanitised-flow (source <line>:<col>)
```

One rule ID, parameterized by the source location. Suppressions can target either the base ID or the full string.

## What it detects

- User input flowing to shell execution: `req.body.cmd` → `child_process.exec`
- User input flowing to code evaluation: `req.query.code` → `eval`
- User input flowing to SQL: `request.args.get('id')` → `cursor.execute(f"... {id}")`
- Environment variables flowing to shell: `env::var("CMD")` → `Command::new("sh").arg("-c")`
- Request parameters flowing to HTML: `req.query.name` → `innerHTML`
- File contents flowing to privileged sinks: `fs::read_to_string` → `db.execute`
- Any other source-to-sink flow where the sink's required capability is not stripped along the way

## What it can't detect

- **Library calls without summaries.** If a callee has no summary (no source, binary-only dependency), Nyx treats it as neither propagating nor sanitizing. This is conservative for sanitization but lossy for propagation.
- **Deep pointer aliasing.** `let y = &x; sink(*y)` works through one level, but arbitrary chains of pointer arithmetic and aliased writes (`*p`, `p->field` in C/C++) are not tracked end-to-end. Function pointers and indirect calls resolve to no callee.
- **Implicit flows.** Taint follows explicit data, not branching signal. `if (secret) x = 1 else x = 0` does not taint `x`.
- **Globals and statics across functions.** Not tracked across function boundaries.

## Common false positives

| Scenario | Why | Mitigation |
|---|---|---|
| Custom sanitizer not recognised | Only built-in + configured sanitizers match | Add a custom sanitizer rule in config |
| Container holds mixed-typed items the engine cannot tell apart | A `vector<int>` of port numbers and a `vector<string>` of user input share the same store/load model | Sanitize the values on the way in (numeric parse / explicit validator) so the values themselves carry no cap, not just the container |
| Dead branches | Path-insensitive within a function | Constraint solving catches trivially infeasible combos; path-validated findings are scored lower |
| Library wrapper re-introduces taint | Wrapper opaque, or summary marks it as propagating | Summarize the wrapper explicitly or add it as a sanitizer |

## Common false negatives

| Scenario | Why |
|---|---|
| Third-party library on the path | No summary available, callee treated opaquely |
| Globals / statics across function boundaries | Not tracked |
| Some closure captures | Closure analysis is limited. JS/TS/Ruby/Go anonymous functions passed as callbacks *are* analyzed as separate scopes |
| Very deep cross-file chains | Summary approximation loses precision at depth |

## Confidence signals

Higher confidence:
- Source + Sink both present in evidence with specific call locations.
- `source_kind: user_input` (direct attacker control).
- `path_validated: false`.
- No dominating guard on the path.
- Symex produced a witness string (rendered sink value visible in JSON/SARIF `evidence.symbolic.witness`).

Lower confidence:
- Path-validated taint (`path_validated: true`).
- Source is a database read or internal file (pre-validated at insertion is common).
- Engine note `ForwardBailed` / `PathWidened`. Use `--require-converged` to drop these in strict gates.

## Tuning

### Custom sanitizer

```toml
# nyx.local
[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml", "sanitizeInput"]
kind     = "sanitizer"
cap      = "html_escape"
```

Or: `nyx config add-rule --lang javascript --matcher escapeHtml --kind sanitizer --cap html_escape`.

### Filter by severity or confidence

```bash
nyx scan . --severity HIGH
nyx scan . --min-confidence medium
```

### Skip dataflow entirely

```bash
nyx scan . --mode ast
```

AST-only mode gives you structural pattern matches without taint.

In the browser UI, taint findings render as a numbered flow walk so you can see each hop the engine took:

<p align="center"><img src="../assets/screenshots/docs/serve-finding-detail.png" alt="Nyx finding detail: HIGH taint-unsanitised-flow with numbered source → call → sink steps and How to fix guidance" width="900"/></p>

## Example

Rust:

```rust
use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("USER_CMD").unwrap();           // source
    Command::new("sh").arg("-c").arg(&cmd).output();   // sink
}
```

Finding:

```
[HIGH] taint-unsanitised-flow (source 5:15)  src/main.rs:6:5
       Unsanitised user input flows from env::var → Command::new
       Source: env::var (5:15)
       Sink:   Command::new
```

Safe rewrite: drop the shell and pass the value as argv directly (`Command::new(&cmd).output()`), or validate against an allowlist before passing to the shell.

## Capabilities

Sources, sanitizers, and sinks are linked by named capabilities. A sanitizer only clears taint for the cap it declares. A sink only fires when the remaining taint still carries its required cap.

| Capability | Typical source | Typical sanitizer | Typical sink |
|---|---|---|---|
| `env_var` | `env::var`, `getenv`, `process.env` | | |
| `html_escape` | | `html.escape`, `DOMPurify.sanitize` | `innerHTML`, `document.write` |
| `shell_escape` | | `shlex.quote`, `shell_escape::escape` | `system`, `Command::new`, `eval` |
| `url_encode` | | `encodeURIComponent` | `location.href`, HTTP client URL arg |
| `json_parse` | | `JSON.parse` | |
| `file_io` | | `os.path.realpath`, `filepath.Clean`, canonicalise + `starts_with`-rooted guard | `open`, `fs::read_to_string`, `send_file` |
| `fmt_string` | | | `printf(var)` |
| `sql_query` | | parameterized query binders | `cursor.execute`, `db.query` with concatenation |
| `deserialize` | | | `pickle.loads`, `yaml.load`, `Marshal.load` |
| `ssrf` | | URL-prefix locks | `requests.get`, `fetch` URL arg, outbound HTTP destination |
| `data_exfil` | cookies, headers, env, db rows, file reads (Sensitive-tier sources only) | | `fetch` body / headers / json, `XMLHttpRequest.send` body |
| `code_exec` | | | `eval`, `exec`, `Function` |
| `crypto` | | | weak-algorithm constructors |
| `unauthorized_id` | request-bound scoped IDs (Rust auth analysis) | ownership check | row-level write |
| `all` | Sources typically use `all` so they match any sink | | |

Sources typically use `cap = "all"` so they match every sink. Sinks declare the specific cap they need. Sanitizers only clear the cap they name.

## Source sensitivity

Some detector classes need to know not just *that* a value is attacker-influenced but *what kind* of value it is. Each source carries a `SourceKind` (`UserInput`, `Cookie`, `Header`, `EnvironmentConfig`, `FileSystem`, `Database`, `CaughtException`, `Unknown`) and a derived sensitivity tier:

| Tier | Source kinds | Meaning |
|---|---|---|
| `Plain` | `UserInput` (request bodies, query strings, form fields, argv, stdin) | Attacker-controlled but already in the attacker's hands. Echoing it back to them is not a disclosure. |
| `Sensitive` | `Cookie`, `Header`, `EnvironmentConfig`, `FileSystem`, `Database`, `CaughtException`, `Unknown` | Operator-bound state that should not leak across boundaries. |
| `Secret` | (reserved for explicit credential sources) | Highest tier; treated identically to `Sensitive` today. |

`Cap::DATA_EXFIL` only fires when the contributing source is at least `Sensitive`. Plain user input flowing into an outbound `fetch` body is suppressed at finding-emission time — the canonical false-positive class for API gateways and telemetry forwarders that proxy `req.body`. SSRF and other classes are unaffected; the gate is scoped to `DATA_EXFIL`.

If a project legitimately classifies a request body as sensitive (e.g. an internal forwarder where `req.body` carries a pre-authenticated user token), override via custom rules in `nyx.conf`:

```toml
# Treat the forwarder's outbound payload as already-sanitized so the
# DATA_EXFIL gate stops firing on it.
[[analysis.languages.javascript.rules]]
matchers = ["sanitizeOutbound"]
kind     = "sanitizer"
cap      = "data_exfil"
```

Or re-classify the source itself with a custom Source rule whose name matches one of the Sensitive substrings (`cookie`, `header`).

## DATA_EXFIL suppression layers

Three knobs ship out of the box so projects can match the cap to their architecture without per-call suppressions.

### 1. Forwarding-wrapper sanitizer convention

A named function that exists to *forward* a payload across a known boundary is the developer's explicit decision to send the data. The default sanitizer rules treat the following identifiers as `Sanitizer(data_exfil)` in JavaScript and TypeScript:

```
serializeForUpstream
forwardPayload
tracker.send
analytics.track
metrics.report
logEvent
```

If your codebase follows this convention, the cap stops firing on these calls automatically. Extend the convention with your own forwarding wrappers via the standard custom-rule path:

```toml
[[analysis.languages.javascript.rules]]
matchers = ["dispatchTelemetry", "sendToBus"]
kind     = "sanitizer"
cap      = "data_exfil"
```

The rule of thumb: a function that *only* exists to ship a payload to a known boundary belongs in this list. A function that *might* leak (a generic HTTP wrapper, a logging helper that writes to an arbitrary destination) does not.

### 2. Destination allowlist

Configure a set of trusted outbound prefixes once and the cap is dropped on every site whose destination argument has a static prefix that begins with one of them:

```toml
[detectors.data_exfil]
trusted_destinations = [
  "https://api.internal/",
  "https://telemetry.",
]
```

Use full origins or origin-pinned paths so a partial-host match across unrelated origins cannot occur. `https://api.` would also match `https://api.evil.example.com/` — the entry must include the path separator (`/`) at the end of the host.

The match consults the abstract string domain: a literal URL is a static prefix; a template literal `\`https://api.internal/${id}\`` exposes the prefix `https://api.internal/`; a fully dynamic URL has no prefix and the cap fires as usual.

### 3. Detector-class disable

Some projects forward user-bound payloads as a matter of architecture. Turn the entire detector class off when the noise is permanent:

```toml
[detectors.data_exfil]
enabled = false
```

`enabled = false` strips `Cap::DATA_EXFIL` from sink caps before event emission, so no `taint-data-exfiltration` finding reaches the report. The decision is per-project — other projects loaded by the same `nyx serve` instance keep their own settings.

## DATA_EXFIL sinks per language

Sinks Nyx ships with for `Cap::DATA_EXFIL`. The body, headers, or json payload arg fires; the URL arg routes through the SSRF gate and emits `taint-unsanitised-flow` instead.

| Language | Sinks | Example |
|---|---|---|
| JavaScript, TypeScript | `fetch(url, {body, headers, json})` body-bind, `XMLHttpRequest.prototype.send`, type-qualified `HttpClient.send` | `fetch('/upload', {method: 'POST', body: req.cookies.session})` |
| Python | `requests.post / put / patch` body and json kwargs, `httpx.AsyncClient().post` json kwarg, `aiohttp.ClientSession().post` body, dict round-trip into json | `requests.post('https://api.internal/ingest', json={'k': os.environ.get('SECRET')})` |
| Java | `HttpClient.send` with `BodyPublishers.ofString`, OkHttp `newCall(req).execute` body chain, Apache `HttpClient.execute(HttpPost)`, `RestTemplate.postForEntity / exchange`, `WebClient.post().bodyValue / body` | `client.send(HttpRequest.newBuilder().uri(...).POST(BodyPublishers.ofString(token)).build(), ...)` |
| Go | `http.Post(url, ct, body)` body arg, `http.PostForm` form arg, `(*http.Client).Do(req)` after `http.NewRequest`, `(*http.Request).Body` assignment | `http.Post("https://analytics.internal/track", "text/plain", strings.NewReader(c.Value))` |
| Rust | `reqwest::Client.post().body / json / form / multipart().send()`, `ureq::post().send_string / send_form / send_json`, `surf::post().body_string / body_json`, `hyper::Request::builder().body()` | `reqwest::Client::new().post(url).form(&secret).send()` |
| Ruby | `Net::HTTP.post(uri, body)` body arg, `Net::HTTP::Post.new(uri).body=`, `RestClient.post / put`, `HTTParty.post(url, body: ...)` body | `Net::HTTP.post(URI('https://analytics.internal/track'), "session=#{request.cookies[:auth]}")` |
| C, C++ | `curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body)` and `CURLOPT_COPYPOSTFIELDS` gated sinks (macro-arg activation), `CURLOPT_POSTFIELDSIZE` body-bind | `curl_easy_setopt(curl, CURLOPT_POSTFIELDS, getenv("AUTH_TOKEN"));` |
| PHP | `curl_setopt($ch, CURLOPT_POSTFIELDS, $body)`, `Guzzle\Client.post($url, ['body' => $tainted])`, `Symfony\HttpClient->request('POST', $url, ['body' => $tainted])` | `curl_setopt($ch, CURLOPT_POSTFIELDS, $_COOKIE['session']);` |

Add project-specific sinks with `nyx config add-rule --kind sink --cap data_exfil --matcher <name>` or the equivalent TOML rule.

## DATA_EXFIL calibration ranges

`taint-data-exfiltration` is calibrated below the other taint classes on purpose.

| Source kind | Severity | Confidence ceiling |
|---|---|---|
| Cookie, environment variable | High | Medium |
| Header | Medium | Medium |
| File system, database | Medium | Medium |
| Caught exception | Medium | Low |

Path-validated flows (`path_validated: true`) drop one severity tier. Confidence drops to Low when the abstract or symbolic domain cannot corroborate a concrete string reaching the outbound payload (for example, when the body comes from a callee with no summary).

Attack-surface score ranges:

| Finding shape | Score |
|---|---|
| High DATA_EXFIL, cookie or env source, body confirmed | around 76 |
| Medium DATA_EXFIL, header, fs, db, or caught-exception source | 40 to 45 |
| Low DATA_EXFIL, no abstract corroboration, path-validated | 18 to 25 |

For reference: High SSRF, SQLi, cmdi land at 76 to 81; Medium taint with env source lands at 45 to 50; AST-only patterns sit around 10. Data-exfil sits below the direct-compromise classes but above informational AST patterns.

use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::{DetectedFramework, FrameworkContext};
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["os.Getenv", "os.LookupEnv", "os.Environ"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "http.Request",
            "r.FormValue",
            "r.URL",
            "r.Body",
            "r.Header",
            "r.Header.Get",
            "r.Header.Values",
            "r.URL.Query",
            "r.URL.Query.Get",
            "r.Cookie",
            "r.Cookies",
            "Request.FormValue",
            "Request.URL",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        matchers: &[
            "html.EscapeString",
            "template.HTMLEscapeString",
            "template.HTMLEscaper",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["url.QueryEscape", "url.PathEscape"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["filepath.Clean", "filepath.Base"],
        label: DataLabel::Sanitizer(Cap::FILE_IO),
        case_sensitive: false,
    },
    // Type conversion sanitizers
    LabelRule {
        matchers: &[
            "strconv.Atoi",
            "strconv.ParseInt",
            "strconv.ParseFloat",
            "strconv.ParseBool",
        ],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["exec.Command"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "db.Query",
            "db.Exec",
            "db.QueryRow",
            "db.Prepare",
            // Phase 15 — GORM `db.Raw(sql)` raw-SQL passthrough.  GORM's
            // `*gorm.DB` is conventionally bound to a `db`-named receiver,
            // so the suffix `db.Raw` carries the GORM semantic without
            // colliding with stdlib `*sql.DB` (which has no `Raw` method).
            // The `GormDb.Raw` type-qualified variant in the receiver-typed
            // rule list below covers receivers tagged from `gorm.Open(...)`
            // with non-`db` names.
            "db.Raw",
            // Phase 15 — `database/sql`-context variants.  `db.QueryContext`,
            // `db.ExecContext`, `db.QueryRowContext`, `db.PrepareContext`
            // accept the SQL string at arg 1 (after `ctx`).  Receivers
            // typed as `*sql.DB` / `*sql.Tx` / `*sql.Stmt` resolve via
            // suffix-matching on `db.<verb>`; calls on differently-named
            // bound receivers (`tx.QueryContext(...)`) only suffix-match
            // when the receiver text ends with `db` (covers `userDb`,
            // `pgDb`, etc.).  More-precise receiver typing is in scope
            // for `DatabaseConnection.<verb>` rules below.
            "db.QueryContext",
            "db.ExecContext",
            "db.QueryRowContext",
            "db.PrepareContext",
            // goqu raw SQL literal builders: `goqu.L(s)` and the alias
            // `goqu.Lit(s)` insert `s` verbatim into the generated SQL with no
            // parameterisation.  CVE-2026-41422 (daptin) loops a user-controlled
            // `c.QueryArray("column")` value into `goqu.L(project)` to allow
            // arbitrary SELECT subqueries.  Modelled by name — `goqu.L` is the
            // documented escape hatch for raw SQL.  The safe siblings
            // `goqu.I` (identifier), `goqu.C` (column), `goqu.T` (table),
            // `goqu.V` (parameterised value), and the typed function
            // constructors (`goqu.COUNT`, `goqu.SUM`, …) are not sinks.
            "goqu.L",
            "goqu.Lit",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Phase 15 — receiver-typed Go ORM/raw-SQL sinks.  `*gorm.DB` (set by
    // `constructor_type` for `gorm.Open(...)`) exposes `Raw(sql)` and
    // `Exec(sql)` as raw-SQL passthrough; the type-qualified resolver
    // rewrites `db.Raw(...)` → `GormDb.Raw`.  `*sqlx.DB` likewise gets
    // `NamedExec` / `NamedQuery` / `Select` / `Get` rewriting via
    // `SqlxDb.<verb>`.  `DatabaseConnection.<verb>` covers the stdlib
    // `*sql.DB` / `*sql.Tx` receivers tagged by the existing
    // `sql.Open` / `sql.OpenDB` constructor mapping — currently the
    // chained QueryContext shape suffix-matches `db.QueryContext` above,
    // so `DatabaseConnection.QueryContext` is here for receivers whose
    // identifier text doesn't end in `db`.
    LabelRule {
        matchers: &[
            "GormDb.Raw",
            "GormDb.Exec",
            "SqlxDb.NamedExec",
            "SqlxDb.NamedQuery",
            "SqlxDb.Select",
            "SqlxDb.Get",
            "SqlxDb.MustExec",
            "DatabaseConnection.QueryContext",
            "DatabaseConnection.ExecContext",
            "DatabaseConnection.QueryRowContext",
            "DatabaseConnection.Query",
            "DatabaseConnection.Exec",
            "DatabaseConnection.QueryRow",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // fmt.Printf/Sprintf write to stdout or build strings in memory, not
    // security sinks.  fmt.Fprintf writes to an io.Writer (often http.ResponseWriter)
    // so it IS a security sink for XSS.
    LabelRule {
        matchers: &["fmt.Fprintf"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "os.Open",
            "os.OpenFile",
            "os.Create",
            "ioutil.ReadFile",
            "os.ReadFile",
            // Mutating filesystem operations.  Path-traversal CVEs commonly
            // sink into delete/write rather than read (Owncast CVE-2024-31450
            // sinks into `os.Remove(filepath.Join(root, userInput))`).
            "os.Remove",
            "os.RemoveAll",
            "os.WriteFile",
            "ioutil.WriteFile",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["template.HTML", "template.JS", "template.CSS"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // ── Outbound HTTP clients (SSRF) ───────────────────────────────────
    //
    // These are modeled as destination-aware gated sinks in `GATED_SINKS`
    // below.  Flat Sink rules would over-flag every positional argument as
    // SSRF (so a tainted body in `http.Post(url, contentType, body)` would
    // fire SSRF on the body), and the gate machinery short-circuits when a
    // flat Sink label is already attached to the callee, blocking DATA_EXFIL
    // body-flow gates from running.
    //
    // `net.Dial` / `net.DialTimeout` keep their flat-sink modeling: the
    // first positional arg is the network address with no body / payload
    // companion, so the over-flag concern does not apply.
    LabelRule {
        matchers: &["net.Dial", "net.DialTimeout"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "md5.New",
            "md5.Sum",
            "sha1.New",
            "sha1.Sum",
            "des.NewCipher",
            "rc4.NewCipher",
        ],
        label: DataLabel::Sink(Cap::CRYPTO),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // go-ldap (`github.com/go-ldap/ldap/v3`): `conn, _ := ldap.DialURL(url);
    // req := ldap.NewSearchRequest(base, scope, deref, sizeLimit, timeLimit,
    // typesOnly, filter, attrs, controls)`.  The filter argument (position 6)
    // is the LDAP-injection vector; passing the request to `conn.Search(req)`
    // executes the filter.  Type-qualified resolution rewrites `conn.Search`
    // → `LdapClient.Search` when the receiver was returned by
    // `ldap.DialURL` / `ldap.Dial` / `ldap.DialTLS` (see
    // [`crate::ssa::type_facts::constructor_type`]).  We also tag
    // `ldap.NewSearchRequest` directly so taint reaching the filter argument
    // surfaces at the construction call (matches the typical FP-free shape
    // where the request is built once and passed straight to `Search`).
    LabelRule {
        matchers: &[
            "LdapClient.Search",
            "LdapClient.SearchWithPaging",
            "ldap.NewSearchRequest",
        ],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizer ───
    //
    // go-ldap exposes `ldap.EscapeFilter(s string) string` (RFC 4515 metachar
    // escaping).  Treat any call as clearing the LDAP_INJECTION cap.
    LabelRule {
        matchers: &["ldap.EscapeFilter"],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── Header / CRLF injection sinks ───
    //
    // `net/http` `ResponseWriter.Header()` returns a `Header` map; calls to
    // `Set(name, val)` / `Add(name, val)` write a single header value.
    // After paren-group stripping the chain text becomes
    // `w.Header.Set` / `w.Header.Add`, so suffix matchers on `Header.Set` /
    // `Header.Add` cover both the bound-receiver form (`w.Header().Set(...)`)
    // and the documentation-style class-qualified form (`Header.Set`).
    // Tainted strings without `\r\n` stripping enable response splitting.
    LabelRule {
        matchers: &["Header.Set", "Header.Add"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: true,
    },
    // ─── Header / CRLF sanitizers ───
    //
    // Project-local `stripCRLF` / `escapeHeader` helpers that strip `\r` and
    // `\n` from a value before it is written to a response header.
    LabelRule {
        matchers: &["stripCRLF", "stripCrlf", "escapeHeader", "sanitizeHeader"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Open redirect sinks ───
    //
    // `net/http` `http.Redirect(w, r, url, code)` writes a `Location` header
    // and a 3xx status from the supplied URL.  Without an allowlist check,
    // a tainted `url` is the canonical Go open-redirect vector.
    LabelRule {
        matchers: &["http.Redirect"],
        label: DataLabel::Sink(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "validateRedirectUrl",
            "isSafeRedirect",
            "stripScheme",
            "ensureRelativeUrl",
            "assertRelativePath",
            "isRelativeUrl",
        ],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // `text/template` and `html/template` parse a template source string via
    // `template.New(name).Parse(src)`.  After paren-group stripping the chain
    // text becomes `template.New.Parse`, so the suffix matcher catches both
    // packages (`text/template`, `html/template`) regardless of import alias.
    // `template.ParseFiles` / `ParseGlob` take file paths (path-traversal,
    // not SSTI) and are intentionally excluded.  `html/template`'s auto-
    // escaping applies during `Execute`, not `Parse`, so a tainted source
    // string still yields SSTI.
    LabelRule {
        matchers: &["template.New.Parse"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: false,
    },
];

/// Argument-role-aware Go sinks.  Two classes coexist on the outbound HTTP
/// surface, mirroring the JS/TS modeling:
///
///   * SSRF on the URL-bearing position of a one-shot request (`http.Get`,
///     `http.Post`, `http.NewRequest`, `http.DefaultClient.*`).
///   * `Cap::DATA_EXFIL` on the body / payload position when the source is
///     Sensitive (cookies, headers, env, db reads).  Gates fire only when
///     taint reaches the body argument, so a tainted URL alone never
///     activates DATA_EXFIL and a tainted body alone never activates SSRF.
///
/// `http.NewRequest` / `http.NewRequestWithContext` carry an SSRF gate on
/// their URL position only.  In Go's two-step idiom the actual network
/// call happens at `client.Do(req)`; body taint flows from the body
/// argument through the returned `*http.Request` via default arg → return
/// propagation, and then activates the `http.DefaultClient.Do` DATA_EXFIL
/// gate below.  Modeling NewRequest as a body propagator (rather than a
/// body sink) avoids duplicate findings on the idiomatic
/// `req, _ := http.NewRequest(...); client.Do(req)` shape.
pub static GATED_SINKS: &[SinkGate] = &[
    // ── SSRF gates (URL-bearing position) ────────────────────────────────
    // `http.Get(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.Head(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Head",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.Post(url, contentType, body)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.Post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.PostForm(url, data)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.PostForm",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.NewRequest(method, url, body)` — url is arg 1.
    SinkGate {
        callee_matcher: "http.NewRequest",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.NewRequestWithContext(ctx, method, url, body)` — url is arg 2.
    SinkGate {
        callee_matcher: "http.NewRequestWithContext",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Get(url)` / `.Head(url)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.Get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "http.DefaultClient.Head",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Post(url, contentType, body)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.Post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.PostForm(url, data)` — url is arg 0.
    SinkGate {
        callee_matcher: "http.DefaultClient.PostForm",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── DATA_EXFIL gates (body-bearing position) ─────────────────────────
    // `http.Post(url, contentType, body)` — body is arg 2.
    SinkGate {
        callee_matcher: "http.Post",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.PostForm(url, data)` — `data` (arg 1) is `url.Values`.  Form
    // bodies serialize the same operator state cookies / headers do, so a
    // tainted Sensitive value reaching the form payload is DATA_EXFIL.
    SinkGate {
        callee_matcher: "http.PostForm",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Do(req)` — `req` (arg 0) is the `*http.Request`
    // value.  Body taint introduced via either `http.NewRequest(_, _, body)`
    // (default arg → return propagation) or a later `req.Body = body` field
    // write reaches this sink through the request value.
    SinkGate {
        callee_matcher: "http.DefaultClient.Do",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.PostForm(url, data)` — same as `http.PostForm`
    // but invoked through the package-level default `*http.Client`.
    SinkGate {
        callee_matcher: "http.DefaultClient.PostForm",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.DefaultClient.Post(url, contentType, body)` — body is arg 2.
    SinkGate {
        callee_matcher: "http.DefaultClient.Post",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── Common third-party HTTP clients ─────────────────────────────────
    //
    // `go-resty/resty`: `client.R().SetBody(body).Post(url)` style.
    // `SetBody(body)` carries the body into the chained request; the
    // network call happens at the verb method.  We model the verb
    // methods (Get / Post / Put / Patch / Delete / Send / Execute) as
    // DATA_EXFIL gates with `payload_args: &[]` (empty), which engages
    // the receiver-tainted fallback in `collect_tainted_sink_vars`.  A
    // builder receiver carrying body taint from `SetBody` activates the
    // sink without us needing a positional body arg.
    SinkGate {
        callee_matcher: "resty.Request.Post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "resty.Request.Put",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "resty.Request.Patch",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `imroc/req`: `req.Post(url, req.BodyJSON(payload))`, the `BodyJSON`
    // / `BodyXML` helpers wrap a tainted payload and pass it as arg 1+ of
    // the verb call.  Since the helper return value carries the body
    // taint, gating the verb on every payload arg is sufficient.
    SinkGate {
        callee_matcher: "req.Post",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1, 2, 3],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "req.Put",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
        payload_args: &[1, 2, 3],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── SQL execute payload-arg gating (Phase 15 deferred fix, Go) ────────
    //
    // Mirrors the Python resolution recorded in `python::GATED_SINKS`.  The
    // flat rules above already classify these callees as `Sink(SQL_QUERY)`
    // on every argument.  `database/sql` and the Go ORM/raw-SQL ecosystem
    // (GORM, sqlx, goqu) follow the convention that the SQL string is at
    // arg 0 (or arg 1 for the `*Context` variants whose first arg is a
    // `context.Context`); subsequent positional arguments are bind values
    // sent through the driver's parameterised path.  Tainted bind values
    // are SAFE; tainted SQL is the SQLi vector.
    //
    // Destination-activation gates carry the same `Sink(SQL_QUERY)` label
    // as the flat rule (cap dedupes against the flat label) and propagate
    // `payload_args: &[0]` (or `&[1]` for `*Context` shapes) into
    // `sink_payload_args`, narrowing the SSA sink scan to the SQL position.
    SinkGate {
        callee_matcher: "db.Query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.Exec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.QueryRow",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.Prepare",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.Raw",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `*Context` variants take `ctx` at arg 0 and the SQL string at arg 1.
    SinkGate {
        callee_matcher: "db.QueryContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.ExecContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.QueryRowContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "db.PrepareContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // goqu raw SQL literal builders.  Single arg, payload at 0.
    SinkGate {
        callee_matcher: "goqu.L",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "goqu.Lit",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // Receiver-typed (case-sensitive, matching the flat rule): GORM / sqlx
    // / `*sql.DB` typed via `constructor_type`.  All take SQL at arg 0
    // EXCEPT the `*Context` variants on `DatabaseConnection`, which take
    // SQL at arg 1.
    SinkGate {
        callee_matcher: "GormDb.Raw",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "GormDb.Exec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "SqlxDb.NamedExec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "SqlxDb.NamedQuery",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "SqlxDb.Select",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "SqlxDb.Get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "SqlxDb.MustExec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.Query",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.Exec",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.QueryRow",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.QueryContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.ExecContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "DatabaseConnection.QueryRowContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
];

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"             => Kind::If,
    "for_statement"            => Kind::For,

    "return_statement"         => Kind::Return,
    "break_statement"          => Kind::Break,
    "continue_statement"       => Kind::Continue,

    // structure
    "source_file"              => Kind::SourceFile,
    "block"                    => Kind::Block,
    "statement_list"           => Kind::Block,
    "function_declaration"     => Kind::Function,
    "method_declaration"       => Kind::Function,
    "func_literal"             => Kind::Function,
    "expression_switch_statement"  => Kind::Switch,
    "type_switch_statement"        => Kind::Switch,
    "expression_case"              => Kind::Block,
    "type_case"                    => Kind::Block,
    "default_case"                 => Kind::Block,
    "select_statement"             => Kind::Block,
    "communication_case"           => Kind::Block,
    "go_statement"                 => Kind::Block,
    "defer_statement"              => Kind::Block,
    // `outer: for { ... }` wraps the whole labeled loop in a
    // labeled_statement; map to Block so the CFG builder recurses into the
    // inner statement instead of collapsing the loop body into one leaf Seq
    // node (mirrors c.rs / cpp.rs).
    "labeled_statement"            => Kind::Block,

    // data-flow
    "call_expression"          => Kind::CallFn,
    "assignment_statement"     => Kind::Assignment,
    "short_var_declaration"    => Kind::CallWrapper,
    "expression_statement"     => Kind::CallWrapper,
    "var_declaration"          => Kind::CallWrapper,
    "type_assertion_expression" => Kind::Seq,

    // trivia
    "comment"                  => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "import_declaration"       => Kind::Trivia,
    "package_clause"           => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    // `variadic_parameter_declaration` covers `func run(args ...string)`;
    // without it the variadic param is dropped, registering wrong arity and
    // never seeding caller taint into the variadic position.
    param_node_kinds: &["parameter_declaration", "variadic_parameter_declaration"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Go.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Gin) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.Param".into(),
                "c.Query".into(),
                "c.PostForm".into(),
                "c.DefaultQuery".into(),
                "c.DefaultPostForm".into(),
                "c.GetHeader".into(),
                "c.Cookie".into(),
                "c.BindJSON".into(),
                "c.ShouldBindJSON".into(),
                // Array-returning sibling helpers.  `c.QueryArray("k")` returns
                // every value of repeated query param `k`; `c.PostFormArray`
                // and `c.GetQueryArray` / `c.GetPostFormArray` are the
                // documented `[]string` counterparts of the scalar methods
                // above.  CVE-2026-41422 (daptin) reads `c.QueryArray("column")`
                // and loops directly into a SQL_QUERY sink.
                "c.QueryArray".into(),
                "c.GetQueryArray".into(),
                "c.PostFormArray".into(),
                "c.GetPostFormArray".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.String".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    if ctx.has(DetectedFramework::Echo) {
        rules.push(RuntimeLabelRule {
            matchers: vec![
                "c.QueryParam".into(),
                "c.FormValue".into(),
                "c.Param".into(),
                "c.Bind".into(),
            ],
            label: DataLabel::Source(Cap::all()),
            case_sensitive: false,
        });
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.String".into(), "c.JSON".into()],
            label: DataLabel::Sink(Cap::HTML_ESCAPE),
            case_sensitive: false,
        });
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::{KINDS, PARAM_CONFIG};
    use crate::labels::Kind;

    #[test]
    fn labeled_statement_is_walkable_block() {
        // `outer: for { ... }` must be a Block so the CFG builder recurses
        // into the labeled loop body instead of collapsing it to a leaf Seq.
        assert_eq!(KINDS.get("labeled_statement"), Some(&Kind::Block));
    }

    #[test]
    fn variadic_param_is_extracted() {
        // `func run(args ...string)` emits variadic_parameter_declaration;
        // it must be a recognised param node so arity registers correctly.
        assert!(
            PARAM_CONFIG
                .param_node_kinds
                .contains(&"variadic_parameter_declaration")
        );
    }
}

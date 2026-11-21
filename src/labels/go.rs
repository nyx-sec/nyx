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
    // `*http.Request` accessors keyed on the canonical `Request` receiver.
    // A formal declared `*http.Request` is classified with its root
    // identifier rewritten to `Request` whatever the binding is named
    // (`req.FormValue` → `Request.FormValue`, see
    // `request_receiver_prefix`), and a struct field named `Request` (gin's
    // `c.Request.Header.Get`) suffix-matches directly.  Case-sensitive so a
    // local that merely happens to be named `request` does not match.
    LabelRule {
        matchers: &[
            "Request.Body",
            "Request.Header",
            "Request.Header.Get",
            "Request.Header.Values",
            "Request.URL.Query",
            "Request.URL.Query.Get",
            "Request.Cookie",
            "Request.Cookies",
            "Request.PathValue",
            "Request.PostFormValue",
            "Request.Form",
            "Request.Form.Get",
            "Request.PostForm",
            "Request.PostForm.Get",
            "Request.FormFile",
            "Request.MultipartForm",
            "Request.Referer",
            "Request.UserAgent",
            "Request.RequestURI",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    // Framework request contexts keyed on their declared type: a formal
    // `ctx *gin.Context` is classified as `GinContext.<method>` and a formal
    // `c echo.Context` as `EchoContext.<method>`.  The declared type is the
    // framework witness, so these do not wait on manifest detection the way
    // the receiver-name rules in `framework_rules` do.  The bind helpers
    // write the request body into their pointer argument; see
    // `OUTPUT_PARAM_SOURCES`.
    LabelRule {
        matchers: &[
            "GinContext.Param",
            "GinContext.Query",
            "GinContext.GetQuery",
            "GinContext.DefaultQuery",
            "GinContext.QueryArray",
            "GinContext.GetQueryArray",
            "GinContext.PostForm",
            "GinContext.GetPostForm",
            "GinContext.DefaultPostForm",
            "GinContext.PostFormArray",
            "GinContext.GetPostFormArray",
            "GinContext.GetHeader",
            "GinContext.Cookie",
            "GinContext.FormFile",
            "GinContext.GetRawData",
            "GinContext.Bind",
            "GinContext.BindJSON",
            "GinContext.BindQuery",
            "GinContext.BindUri",
            "GinContext.BindHeader",
            "GinContext.BindXML",
            "GinContext.BindYAML",
            "GinContext.BindWith",
            "GinContext.ShouldBind",
            "GinContext.ShouldBindJSON",
            "GinContext.ShouldBindQuery",
            "GinContext.ShouldBindUri",
            "GinContext.ShouldBindHeader",
            "GinContext.ShouldBindXML",
            "GinContext.ShouldBindYAML",
            "GinContext.ShouldBindWith",
            "GinContext.ShouldBindBodyWith",
            "EchoContext.Param",
            "EchoContext.QueryParam",
            "EchoContext.FormValue",
            "EchoContext.Bind",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
    },
    // Router path parameters.  gorilla/mux `mux.Vars(r)` returns the route
    // variables as a `map[string]string`; chi `chi.URLParam(r, key)` and
    // `chi.URLParamFromCtx(ctx, key)` return one value.  The package
    // qualifier is specific to each router, so these do not wait on
    // manifest detection.
    LabelRule {
        matchers: &["mux.Vars", "chi.URLParam", "chi.URLParamFromCtx"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: true,
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
    // encoding/json escapes `<`, `>`, `&`, U+2028 and U+2029 inside string
    // values by default (`json.Marshal`, `json.MarshalIndent`), so the bytes
    // cannot open a tag or script context.  This is the serialiser, not a
    // parser: decoding (`json.Unmarshal`) is not a sanitizer.
    LabelRule {
        matchers: &["json.Marshal", "json.MarshalIndent"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["url.QueryEscape", "url.PathEscape"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // `filepath.Base` keeps only the final element.  `path.Base` splits on
    // `/` alone, so on a Windows host a `..\` component survives it; it is not
    // listed.
    // `filepath.Clean` is lexical and leaves `../../x` alone, so it is a
    // PathFact primitive that a `strings.HasPrefix` containment check clears,
    // not a sanitiser.
    LabelRule {
        matchers: &["filepath.Base"],
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
    // GORM query-builder methods that accept a raw SQL fragment at arg 0.
    // GORM's `*gorm.DB` is conventionally bound to a `db`-named receiver, so
    // the suffix `db.Where` / `db.Order` etc. carries the GORM semantic
    // (stdlib `*sql.DB` has none of these methods, so the suffix can't collide
    // with `database/sql`).  Each takes the SQL string at arg 0; the variadic
    // forms (`Where(query, args...)`, `Having`, `Or`, `Not`, `Joins`) send
    // subsequent positional args through the driver's parameterised path, so
    // payload-arg gating (`payload_args: &[0]` in `GATED_SINKS`) keeps the safe
    // `db.Where("col = ?", val)` shape silent while the raw-concat
    // `db.Where("col = '" + v + "'")` / `db.Order(userInput)` shapes fire.
    // `Order` / `Group` have no parameterised form (the whole arg is the
    // ORDER BY / GROUP BY clause) and so are always raw.  Motivated by
    // CVE-2024-37896 (gin-vue-admin export `db.Order(values.Get("order"))`).
    //
    // NOTE: only the *terminal* / assigned builder call resolves by suffix
    // (`db = db.Order(x)` → callee text `db.Order`); a builder chained before a
    // finisher (`db.Where(x).Find(&out)` → `db.Where.Find`) collapses to a
    // single Call whose suffix is the finisher, so the inner builder is not yet
    // recognised — that depends on the chained-method-call SSA-lowering split
    // tracked in CVE_DEFERRED.md.
    LabelRule {
        matchers: &[
            "db.Where",
            "db.Order",
            "db.Group",
            "db.Having",
            "db.Or",
            "db.Not",
            "db.Joins",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // Receiver-typed GORM builder variants (case-sensitive), for receivers
    // tagged `GormDb` by `constructor_type` (`gorm.Open(...)`) whose identifier
    // text does not end in `db` (e.g. `tx := gorm.Open(...); tx.Order(x)`).
    LabelRule {
        matchers: &[
            "GormDb.Where",
            "GormDb.Order",
            "GormDb.Group",
            "GormDb.Having",
            "GormDb.Or",
            "GormDb.Not",
            "GormDb.Joins",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // fmt.Printf/Sprintf write to stdout or build strings in memory, not
    // security sinks.  `fmt.Fprint*` and `io.WriteString` write to the
    // io.Writer at arg 0, which is often the http.ResponseWriter, so they are
    // XSS sinks.  When the writer is typed as something else (a
    // `*bytes.Buffer`, a `strings.Builder`, an `*os.File`, an `io.Writer`
    // formal, os.Stderr) the taint engine and `cfg-unguarded-sink` drop the
    // label; see `type_facts::is_go_writer_sink_callee`.
    LabelRule {
        matchers: &[
            "fmt.Fprintf",
            "fmt.Fprint",
            "fmt.Fprintln",
            "io.WriteString",
        ],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // `w.Write(b)` / `w.WriteString(s)` on a value typed `http.ResponseWriter`
    // (a formal or local declared with that type).  Reached only through
    // type-qualified resolution, so a `Write` on a buffer, file or hash is
    // never a sink.
    LabelRule {
        matchers: &["HttpResponse.Write", "HttpResponse.WriteString"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
    },
    // Echo writes the string or bytes given to `c.HTML` / `c.HTMLBlob` as
    // `text/html` without escaping.  The typed form fires for a formal
    // declared `echo.Context` whatever it is named; the receiver-name form
    // waits on framework detection (`framework_rules`).
    LabelRule {
        matchers: &["EchoContext.HTML", "EchoContext.HTMLBlob"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: true,
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
    // below.  A flat Sink rule alone would over-flag every positional
    // argument as SSRF (so a tainted body in `http.Post(url, contentType,
    // body)` would fire SSRF on the body).  When a flat Sink does exist, the
    // CFG gate pass still narrows it to each gate's payload positions.
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
    // Header injection sinks (`w.Header().Set(name, val)`) are argument-role
    // aware and live in `GATED_SINKS`.
    //
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
    // A `*http.Client` the code builds itself (`&http.Client{Timeout: t}`, a
    // formal or local declared `*http.Client`) is typed `HttpClient`, and
    // type-qualified resolution rewrites `c.Get(u)` to `HttpClient.Get`.  The
    // argument roles match the `http.DefaultClient.*` gates above.  These
    // names are case-sensitive so they never match a lowercase method on an
    // untyped receiver.
    SinkGate {
        callee_matcher: "HttpClient.Get",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.Head",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.Post",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.PostForm",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
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
    // Typed `*http.Client` body positions, same roles as the
    // `http.DefaultClient.*` gates above.
    SinkGate {
        callee_matcher: "HttpClient.Do",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.Post",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: true,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "HttpClient.PostForm",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: true,
        payload_args: &[1],
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
    // `exec.CommandContext(ctx, name, args...)` is `exec.Command` with a
    // leading `context.Context`.  The context is not part of the command, so
    // only the program name and its arguments are payloads.
    SinkGate {
        callee_matcher: "exec.CommandContext",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
        payload_args: &[1, 2, 3, 4, 5, 6, 7, 8],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // `http.ServeFile(w, r, name)` opens and streams the file at `name`.  The
    // `..` rejection it applies looks at `r.URL.Path`, not at `name`, so a name
    // built from a query value or form field can still leave the served root.
    SinkGate {
        callee_matcher: "http.ServeFile",
        arg_index: 2,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[2],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── Response header writes (HEADER_INJECTION) ────────────────────────
    //
    // `http.ResponseWriter` exposes its header map through the `Header()`
    // METHOD, while `*http.Request` and `*http.Response` expose `Header` as a
    // struct FIELD.  Matching the call form `Header().Set` keeps the sink on
    // the response the server sends (`w.Header().Set`,
    // `c.Writer.Header().Set`, `c.Response().Header().Set`) and leaves
    // inbound-request rewrites (`r.Header.Set`) and outbound client requests
    // (`req.Header.Set`) alone.  The matcher sees the raw callee text, where
    // the call's parentheses are still present.
    //
    // Only the value (arg 1) is a payload, so a receiver that merely carries
    // taint does not fire.  net/http replaces CR and LF in header values with
    // spaces when it writes the response, so the risk here is an
    // attacker-chosen value in a header with meaning (`Location`,
    // `Set-Cookie`, `Access-Control-Allow-Origin`, `Content-Type`), not
    // response splitting.
    SinkGate {
        callee_matcher: "Header().Set",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: true,
        payload_args: &[1],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Header().Add",
        arg_index: 1,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: true,
        payload_args: &[1],
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
    // GORM query-builder gates: SQL fragment at arg 0, bind values at
    // arg 1+ travel the parameterised path (safe).  Mirrors db.Where /
    // db.Raw above.  CVE-2024-37896.
    SinkGate {
        callee_matcher: "db.Where",
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
        callee_matcher: "db.Order",
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
        callee_matcher: "db.Group",
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
        callee_matcher: "db.Having",
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
        callee_matcher: "db.Or",
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
        callee_matcher: "db.Not",
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
        callee_matcher: "db.Joins",
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
        callee_matcher: "GormDb.Where",
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
        callee_matcher: "GormDb.Order",
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
        callee_matcher: "GormDb.Group",
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
        callee_matcher: "GormDb.Having",
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
        callee_matcher: "GormDb.Or",
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
        callee_matcher: "GormDb.Not",
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
        callee_matcher: "GormDb.Joins",
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
    // `select` runs exactly one ready case; lowered like a switch.
    "select_statement"             => Kind::Switch,
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
    // `i++` / `i--` statements: read-modify-write, see `cfg::rmw_assignment`.
    "inc_statement"            => Kind::Assignment,
    "dec_statement"            => Kind::Assignment,
    "short_var_declaration"    => Kind::CallWrapper,
    "expression_statement"     => Kind::CallWrapper,
    "var_declaration"          => Kind::CallWrapper,
    // `const x = "lit"` defines a name like `var x = "lit"` does, so a
    // constant is a constant to const-prop and to module-level URL prefixes.
    "const_declaration"        => Kind::CallWrapper,
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

/// Canonical receiver prefix for a request-carrying formal parameter type.
/// The prefix keys the type-qualified source rules above (`Request.*`,
/// `GinContext.*`, `EchoContext.*`).  Strips one pointer marker; everything
/// else, including unqualified or differently qualified `Context` types,
/// returns `None`.
pub fn request_receiver_prefix(type_text: &str) -> Option<&'static str> {
    match type_text.trim().trim_start_matches('*').trim() {
        "http.Request" => Some("Request"),
        "gin.Context" => Some("GinContext"),
        "echo.Context" => Some("EchoContext"),
        _ => None,
    }
}

/// True when `text` is a call of echo's name-keyed HTML sinks (`c.HTML`,
/// `c.HTMLBlob`) on a receiver the enclosing function declares as a gin
/// context.  The echo rules in [`framework_rules`] match on the receiver name
/// alone, so a file that imports both frameworks would otherwise treat gin's
/// `c.HTML(code, name, data)`, a named html/template that escapes `data`, as a
/// raw HTML write.  `declared_prefix` maps a receiver name to the canonical
/// prefix of its declared type.
pub fn name_rule_sink_contradicts_declared_type(
    text: &str,
    declared_prefix: impl Fn(&str) -> Option<&'static str>,
) -> bool {
    let Some((root, method)) = text.split_once('.') else {
        return false;
    };
    matches!(method, "HTML" | "HTMLBlob") && declared_prefix(root) == Some("GinContext")
}

/// Request binders that decode the request into the pointer passed at the
/// listed argument positions and return only an `error`
/// (`c.ShouldBindJSON(&in)`, `c.Bind(&in)`).  Consulted only when the call
/// already carries a `Source` label, so a same-named method on an unrelated
/// receiver is never treated as a binder.
pub static OUTPUT_PARAM_SOURCES: &[(&str, &[usize])] = &[
    ("Bind", &[0]),
    ("BindJSON", &[0]),
    ("BindQuery", &[0]),
    ("BindUri", &[0]),
    ("BindHeader", &[0]),
    ("BindXML", &[0]),
    ("BindYAML", &[0]),
    ("BindWith", &[0]),
    ("ShouldBind", &[0]),
    ("ShouldBindJSON", &[0]),
    ("ShouldBindQuery", &[0]),
    ("ShouldBindUri", &[0]),
    ("ShouldBindHeader", &[0]),
    ("ShouldBindXML", &[0]),
    ("ShouldBindYAML", &[0]),
    ("ShouldBindWith", &[0]),
    ("ShouldBindBodyWith", &[0]),
];

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
        // No gin response method is modelled as an XSS sink.  `c.String`
        // sends `text/plain`, `c.JSON` sends JSON, and `c.HTML(code, name,
        // obj)` executes a named html/template, which escapes `obj`.  Raw
        // HTML handed to a template still fires at `template.HTML`.
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
        // Echo `c.HTML(code, html)` and `c.HTMLBlob(code, b)` write raw
        // HTML.  `c.String` is `text/plain` and `c.JSON` is
        // `application/json` with encoding/json's HTML escaping, so neither
        // renders markup.
        rules.push(RuntimeLabelRule {
            matchers: vec!["c.HTML".into(), "c.HTMLBlob".into()],
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

    #[test]
    fn header_sink_is_response_side_and_value_only() {
        use crate::labels::{Cap, DataLabel, classify_all, classify_gated_sink};
        let header = |callee: &str| {
            classify_gated_sink("go", callee, |_| None, |_| None, |_| false)
                .into_iter()
                .filter(|g| g.label == DataLabel::Sink(Cap::HEADER_INJECTION))
                .map(|g| g.payload_args.to_vec())
                .collect::<Vec<_>>()
        };
        // `Header()` is a ResponseWriter method; only the value is a payload.
        assert_eq!(header("w.Header().Set"), vec![vec![1]]);
        assert_eq!(header("w.Header().Add"), vec![vec![1]]);
        assert_eq!(header("c.Writer.Header().Set"), vec![vec![1]]);
        // `Header` as a field belongs to *http.Request / *http.Response.
        assert!(header("r.Header.Set").is_empty());
        assert!(header("req.Header.Add").is_empty());
        assert!(
            !classify_all("go", "r.Header.Set", None)
                .contains(&DataLabel::Sink(Cap::HEADER_INJECTION))
        );
    }
}

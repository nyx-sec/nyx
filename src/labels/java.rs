use crate::labels::{
    Cap, DataLabel, GateActivation, Kind, LabelRule, ParamConfig, RuntimeLabelRule, SinkGate,
};
use crate::utils::project::FrameworkContext;
use phf::{Map, phf_map};

pub static RULES: &[LabelRule] = &[
    // ─────────── Sources ───────────
    LabelRule {
        matchers: &["System.getenv"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "getParameter",
            // Iterable/collection-returning request accessors.  `getParameter`
            // (word-boundary suffix match) does NOT cover `getParameterValues`
            // etc., and these are the dominant untrusted-input shapes inside
            // for-each loops (`for (String s : req.getParameterValues("v"))`).
            "getParameterValues",
            "getParameterMap",
            "getParameterNames",
            "getInputStream",
            "getHeader",
            "getHeaders",
            "getHeaderNames",
            "getCookies",
            "getReader",
            "getQueryString",
            "getPathInfo",
            "getRequestURI",
            "getRequestURL",
            "getServletPath",
            // `getContextPath` is deliberately absent: it is the container
            // mapped webapp prefix, fixed by deployment, not request text.
            // Multipart upload: the client-chosen file name of a
            // `request.getPart(..)` part.
            "getSubmittedFileName",
        ],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["readObject", "readLine", "ObjectMapper.readValue"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // Sensitive operator state: HTTP session attributes commonly carry
    // auth tokens / CSRF tokens / signed user ids.  Routed through the
    // `Cookie` source-kind heuristic so DATA_EXFIL fires when these
    // values leave the process via an outbound request body.
    LabelRule {
        matchers: &["HttpSession.getAttribute", "session.getAttribute"],
        label: DataLabel::Source(Cap::all()),
        case_sensitive: false,
    },
    // ───────── Sanitizers ──────────
    LabelRule {
        // The bare spellings cover `import static ...StringEscapeUtils.escapeHtml4;`.
        matchers: &[
            "HtmlUtils.htmlEscape",
            "StringEscapeUtils.escapeHtml4",
            "escapeHtml4",
            "escapeHtml3",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // OWASP ESAPI encoders.  The idiomatic call site is the fluent
    // `ESAPI.encoder().encodeForHTML(x)` chain, which Java's chain collapse
    // rewrites to the callee text `ESAPI.encodeForHTML` (the intermediate
    // `encoder()` call is dropped), so the class-qualified
    // `Encoder.encodeForHTML` matcher never fires on it.  Match the
    // `ESAPI.`- and `encoder.`-qualified forms so a value run through the
    // canonical XSS encoder has its HTML_ESCAPE cap cleared before it reaches
    // a `response.getWriter()` sink.  Deliberately NOT matched bare: the OWASP
    // Benchmark ships a decoy `Utils.encodeForHTML(...)` that returns the
    // string UNCHANGED to test whether a scanner is fooled by the method name,
    // so a bare `encodeForHTML` matcher would suppress real reflected-XSS.
    LabelRule {
        matchers: &[
            "Encoder.encodeForHTML",
            "Encoder.encodeForJavaScript",
            "ESAPI.encodeForHTML",
            "ESAPI.encodeForHTMLAttribute",
            "ESAPI.encodeForJavaScript",
            "ESAPI.encodeForCSS",
            "encoder.encodeForHTML",
            "encoder.encodeForHTMLAttribute",
            "encoder.encodeForJavaScript",
            "encoder.encodeForCSS",
        ],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Encoder.encodeForSQL"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["Encoder.encodeForURL"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // OWASP ESAPI input validator, validates and canonicalizes input
    LabelRule {
        matchers: &["Validator.getValidInput"],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    // Type-check sanitizers, parsing to a primitive erases taint
    LabelRule {
        matchers: &[
            "Integer.parseInt",
            "Long.parseLong",
            "Short.parseShort",
            "Double.parseDouble",
            "Integer.valueOf",
            "Boolean.parseBoolean",
        ],
        label: DataLabel::Sanitizer(Cap::all()),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &["URLEncoder.encode"],
        label: DataLabel::Sanitizer(Cap::URL_ENCODE),
        case_sensitive: false,
    },
    // Phase 15 — JPA / Hibernate `Query.setParameter(name, value)` /
    // `Query.setParameterList(...)` bind a positional / named parameter
    // and return the same query object.  The bind step does NOT inject
    // the value into the SQL string; the value is sent as a separate
    // parameter through the JDBC layer at execution.  Treating
    // `setParameter` / `setParameterList` as a SQL_QUERY sanitizer
    // clears any taint inadvertently smeared onto the chain return so
    // downstream `.getResultList()` / `.executeUpdate()` calls see a
    // clean value.  Case-sensitive: these are JPA-specific verb names
    // and the chain shape is canonical.
    LabelRule {
        matchers: &["setParameter", "setParameterList"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["Runtime.exec", "ProcessBuilder"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
    },
    // `ProcessBuilder.command(argList)` — the dominant OWASP Benchmark
    // command-injection shape builds an argument `List<String>`, attaches it
    // via `pb.command(argList)`, then runs `pb.start()`.  The argument list is
    // a separate channel from the constructor, so the flat `ProcessBuilder`
    // constructor sink above never sees the tainted args.  This rule fires
    // only via type-qualified resolution: the receiver `pb` must carry a
    // `TypeKind::ProcessBuilder` fact (set by `constructor_type` for
    // `new ProcessBuilder(...)`), so the resolver rewrites `pb.command(...)` →
    // `ProcessBuilder.command`.  Case-sensitive and receiver-typed to avoid
    // colliding with the many unrelated `.command(...)` methods (CLI builders,
    // JCommander, picocli, Swing actions).  The payload is restricted to arg 0
    // (the command list) via `type_qualified_sink_payload_args`.
    LabelRule {
        matchers: &["ProcessBuilder.command"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["executeQuery", "executeUpdate"],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // JDBC `Statement.execute(String)` / `executeBatch` / `executeLargeUpdate`.
    // Bare `execute` over-fires (Runnable.run callbacks, Executor.execute,
    // HttpClient.execute), so these only fire via type-qualified resolution
    // when the receiver's TypeKind is DatabaseConnection (the kind both
    // `Connection` and `Statement` map to in `class_name_to_type_kind`).
    // Surfaced by GHSA-h8cj-hpmg-636v (Appsmith FilterDataServiceCE.dropTable).
    LabelRule {
        matchers: &[
            "DatabaseConnection.execute",
            "DatabaseConnection.executeBatch",
            "DatabaseConnection.executeLargeUpdate",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    LabelRule {
        matchers: &["Class.forName"],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    // Phase 13 — java.nio.file path-traversal sinks.  `Files.<verb>` is
    // the modern stdlib API for read/write/copy/move/delete operations;
    // each takes a `Path` (or `Path` + payload) as arg 0.  Default
    // arg→return propagation smears taint through `Paths.get(...)`
    // (forwarder) so the path arg of these calls inherits any taint
    // present on the components.  `FileInputStream` / `FileOutputStream` /
    // `FileReader` / `FileWriter` / `RandomAccessFile` are constructor-style
    // sinks: `new FileInputStream(path)` reaches the FILE_IO sink at the
    // `object_creation_expression` level (mapped to `Kind::CallFn` in
    // Java's KINDS).  Receiver-typing already maps these classes to
    // `TypeKind::FileHandle` (see `class_name_to_type_kind`) so chained
    // method calls on the resulting handle resolve via type-qualified
    // labels, but the construction call itself is the canonical
    // path-traversal vector.
    LabelRule {
        matchers: &[
            "Files.readString",
            "Files.readAllBytes",
            "Files.readAllLines",
            "Files.write",
            "Files.writeString",
            "Files.lines",
            "Files.copy",
            "Files.move",
            "Files.delete",
            "Files.deleteIfExists",
            "Files.newInputStream",
            "Files.newOutputStream",
            "Files.newBufferedReader",
            "Files.newBufferedWriter",
            "FileInputStream",
            "FileOutputStream",
            "FileReader",
            "FileWriter",
            "RandomAccessFile",
            // Netty file-serving constructors: `new DefaultFileRegion(file,
            // pos, count)` and the chunked-write handlers open the file they
            // are given, so a request-chosen file is a path traversal.
            "DefaultFileRegion",
            "ChunkedFile",
            "ChunkedNioFile",
        ],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
    },
    // `Path.normalize()` is lexical: `base.resolve("../../x").normalize()` is
    // `/x`, so it does not confine a path and is not a sanitiser.  It is a
    // path primitive in the PathFact domain, cleared by a `startsWith(base)`
    // containment check.
    // HTTP response reflected-XSS sinks.  `println` / `print` / `write` are
    // the servlet response-writer output verbs; `write` is the dominant form
    // in real servlets (`response.getWriter().write(html)`).  All three are
    // matched bare because Java collapses the writer chain
    // `response.getWriter().write(x)` to the callee text `response.write`
    // (the intermediate `getWriter()` call is dropped), so a receiver-typed
    // `HttpResponse.write` rule never sees it.  The breadth is bounded two
    // ways: the `System.out` / `System.err` console streams are in
    // [`EXCLUDES`], and `receiver_incompatible_sink_caps`
    // strips `HTML_ESCAPE` whenever the receiver resolves to a non-response
    // type (a `FileWriter` / `FileOutputStream` typed `FileHandle`, a DB
    // connection, etc.), so genuine file/stream writes do not register as XSS.
    LabelRule {
        matchers: &["println", "print", "write"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // openConnection() is the standard java.net.URL API for initiating a connection.
    // It is the correct interception point, the URL is already set on the object.
    //
    // Phase 14 — additional SSRF entry points covered:
    //   * `URL.openStream` — equivalent of `URL.openConnection().getInputStream()`,
    //     fetches the resource at the URL directly.  Bare `openStream`
    //     suffix is unique to `java.net.URL` in the supported corpus.
    //   * `OkHttpClient.newCall(Request)` — Square OkHttp's request
    //     dispatch entry point.  The `Request` is built via a
    //     `Request.Builder().url(u).build()` chain whose default
    //     arg→return propagation smears URL taint through the chain.
    //   * `RestTemplate.getForEntity` / `RestTemplate.headForHeaders` —
    //     read-shaped Spring verbs that take the URL at arg 0.
    LabelRule {
        matchers: &[
            "openConnection",
            "openStream",
            "HttpClient.send",
            "HttpClient.sendAsync",
            // Phase 14 — `OkHttpClient.newCall(Request)` and the
            // generic `HttpClient.newCall` form OkHttp resolves to via
            // the JAVA_HIERARCHY (OkHttpClient → HttpClient).  Both
            // forms are covered so a constructor-typed receiver
            // (HttpClient) and a class-named receiver (OkHttpClient)
            // both fire.
            "HttpClient.newCall",
            "OkHttpClient.newCall",
            "getForObject",
            "getForEntity",
            "headForHeaders",
            "RestTemplate.exchange",
            "postForObject",
            "postForEntity",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
    },
    // Apache HttpClient request objects (`org.apache.http.client.methods.*` in
    // 4.x, `org.apache.hc.client5.http.classic.methods.*` in 5.x).  The target
    // URL is bound at construction — `new HttpGet(url)` / `new HttpOptions(url)`
    // — and later dispatched via `httpClient.execute(request)`.  `execute`
    // alone can't distinguish a tainted URL (SSRF) from a tainted request body
    // (DATA_EXFIL), and is gated to sensitive sources for the body case, so the
    // constructor is the correct SSRF interception point: it is exactly where
    // the attacker-controlled URL is set on the request object (same rationale
    // as `URL.openConnection` above).  Motivated by CVE-2024-39954 (Apache
    // EventMesh): a subscriber-supplied webhook URL reaches
    // `new HttpOptions(targetUrl)` → `httpClient.execute(builder)`.  The bare
    // request type names are HttpClient-specific and do not collide with any
    // labelled method in the supported corpus.
    LabelRule {
        matchers: &[
            "HttpGet",
            "HttpPost",
            "HttpPut",
            "HttpDelete",
            "HttpHead",
            "HttpOptions",
            "HttpTrace",
            "HttpPatch",
            "HttpUriRequestBase",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: true,
    },
    // ── Cross-boundary data exfiltration ──────────────────────────────────
    //
    // Outbound HTTP egress points where a Sensitive source (cookie, header,
    // env, session attribute, db read) reaching the request body / payload
    // is a cross-boundary disclosure distinct from SSRF.  The flat-rule
    // model relies on default arg → return propagation through builder
    // chains: `HttpRequest.newBuilder().uri(u).POST(BodyPublishers.ofString(p)).build()`
    // smears `p`-taint into the returned request, which then activates the
    // sink at `client.send(req)`.
    //
    // Type-qualified resolution maps `restTemplate.postForObject(...)` →
    // `HttpClient.postForObject` via the JAVA_HIERARCHY (RestTemplate,
    // OkHttpClient, WebClient, CloseableHttpClient all subtype HttpClient),
    // so a single set of `HttpClient.<method>` rules covers every framework
    // in scope.  Plain user input is silenced by the source-sensitivity
    // gate in `effective_sink_caps`, so this fires only on cookies / headers
    // / env / session / db.
    LabelRule {
        matchers: &[
            // java.net.http: client.send(req) consumes a request that
            // carries body-taint via BodyPublishers.ofString/ofByteArray/
            // ofInputStream through the builder chain.
            "HttpClient.send",
            "HttpClient.sendAsync",
            // Spring RestTemplate verbs that take a body / entity.
            "postForObject",
            "postForEntity",
            "RestTemplate.exchange",
            "RestTemplate.put",
            "RestTemplate.patchForObject",
            // Apache HttpClient: httpClient.execute(req) where req is an
            // HttpPost / HttpPut / HttpPatch with .setEntity(StringEntity(p)).
            // CloseableHttpClient subtypes HttpClient so type-qualified
            // resolution rewrites client.execute → HttpClient.execute.
            "HttpClient.execute",
            // Spring WebClient body-binding step:
            // webClient.post().uri(u).bodyValue(payload).retrieve().
            // bodyValue is the explicit body-bind verb; default propagation
            // carries the tainted body into the chain return so the sink
            // attaches at the body-bind site itself (no cross-call needed).
            "bodyValue",
            // Apache HttpClient body-binding: the `setEntity` step on
            // HttpPost / HttpPut / HttpPatch mutates the request rather
            // than returning the builder, so the receiver's SSA value at
            // the later `httpClient.execute(req)` does not carry body
            // taint via the default smear (which threads through return
            // values, not field mutations).  Firing DATA_EXFIL at the
            // setEntity call itself catches the body-binding directly.
            // The matcher is specific enough to avoid collisions —
            // `setEntity` is Apache-HttpClient-specific.
            "setEntity",
            // OkHttp builder body-binding shortcut: when the chain
            // doesn't roll through `.post(body).build()` (e.g. a helper
            // function returns the Builder mid-chain), `RequestBody`
            // is bound via `.post(body)` / `.put(body)` / `.patch(body)`
            // / `.delete(body)` directly on the Builder.  These methods
            // also exist on unrelated classes (NIO, Streams) but in the
            // OkHttp idiom the receiver type is `Request.Builder`; the
            // receiver-type widening from `Request.Builder` → HttpClient
            // isn't currently modeled, so we fall back to suffix-name
            // matchers and accept some receiver-agnostic firing risk.
            // Conservative: omit these for v1 to avoid over-fire on
            // non-OkHttp `post`/`put`/`patch` calls.
            // OkHttp two-step: client.newCall(req).execute() / .enqueue().
            // Chain normalization strips `()` between dots so the tree-
            // sitter callee text `client.newCall(req).execute` matches the
            // suffix `newCall.execute` after normalization.
            "newCall.execute",
            "newCall.enqueue",
        ],
        label: DataLabel::Sink(Cap::DATA_EXFIL),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "readObject",
            "readUnshared",
            "XMLDecoder.readObject",
            "ObjectMapper.readValue",
        ],
        label: DataLabel::Sink(Cap::DESERIALIZE),
        case_sensitive: false,
    },
    // ─── Spring / JPA / Hibernate SQL sinks ───
    //
    // Spring `JdbcTemplate` statement verbs.  Case-insensitive, so the
    // `JdbcTemplate.*` text that type-qualified resolution builds for a
    // receiver declared `JdbcTemplate` / `NamedParameterJdbcTemplate`
    // matches too, as does OWASP Benchmark's static
    // `DatabaseHelper.JDBCtemplate`.  `getJdbcTemplate()` is the
    // `JdbcDaoSupport` accessor.  The SQL is arg 0; the `sql_arg0_gate`
    // entries in `GATED_SINKS` keep bind values and row mappers out of the
    // sink.
    LabelRule {
        matchers: &[
            "jdbcTemplate.query",
            "jdbcTemplate.update",
            "jdbcTemplate.execute",
            "jdbcTemplate.queryForObject",
            "jdbcTemplate.queryForList",
            "jdbcTemplate.queryForMap",
            "jdbcTemplate.queryForRowSet",
            "jdbcTemplate.queryForStream",
            "jdbcTemplate.queryForInt",
            "jdbcTemplate.queryForLong",
            "jdbcTemplate.batchUpdate",
            "getJdbcTemplate.query",
            "getJdbcTemplate.update",
            "getJdbcTemplate.execute",
            "getJdbcTemplate.queryForObject",
            "getJdbcTemplate.queryForList",
            "getJdbcTemplate.queryForMap",
            "getJdbcTemplate.queryForRowSet",
            "getJdbcTemplate.queryForStream",
            "getJdbcTemplate.queryForInt",
            "getJdbcTemplate.queryForLong",
            "getJdbcTemplate.batchUpdate",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "entityManager.createNativeQuery",
            "entityManager.createQuery",
            "em.createNativeQuery",
            "em.createQuery",
            "session.createQuery",
            "session.createSQLQuery",
            "session.createNativeQuery",
            // Phase 15 — Spring Data JPA / Hibernate factory chains:
            // `getEntityManager().createNativeQuery(...)` /
            // `getSession().createQuery(...)` reduce to
            // `getEntityManager.createNativeQuery` /
            // `getSession.createQuery` after the chain-normalisation
            // strips parens.
            "getEntityManager.createNativeQuery",
            "getEntityManager.createQuery",
            "getSession.createQuery",
            "getSession.createSQLQuery",
            "getSession.createNativeQuery",
            // Type-qualified Hibernate Session matchers fire when the
            // receiver carries a `TypeKind::HibernateSession` fact (set
            // by `constructor_type` for `sessionFactory.openSession()` /
            // `sessionFactory.getCurrentSession()` /
            // `sessionFactory.openStatelessSession()` returns).  Closes
            // the arbitrary-receiver-name shape (`sess`,
            // `hibernateSession`, etc.) the flat `session.*` matchers
            // above only catch when receiver is literally named
            // `session`.
            "HibernateSession.createQuery",
            "HibernateSession.createSQLQuery",
            "HibernateSession.createNativeQuery",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: true,
    },
    // NOTE: Java logging (logger.info, log.warn, etc.) removed as sinks ,
    // logging format injection is not a real security vulnerability in Java.
    // String.format also removed, it builds strings in memory (not a sink);
    // the real sink is wherever the formatted string is used (SQL, HTTP, etc.).
    // ─── JNDI injection sinks ───
    LabelRule {
        matchers: &[
            "InitialContext.lookup",
            "ctx.lookup",
            "context.lookup",
            "dirContext.lookup",
        ],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: false,
    },
    // ─── LDAP injection sinks ───
    //
    // JNDI / Spring LDAP search APIs accept an attacker-influenceable filter
    // expression as either the second positional argument (`DirContext.search(name,
    // filter, controls)` / `LdapTemplate.search(base, filter, mapper)`).  Without
    // RFC 4515 escaping the filter can be rewritten to bypass authentication or
    // exfiltrate directory entries.  Type-qualified resolution rewrites
    // `ctx.search(...)` → `LdapClient.search` when the receiver carries a
    // `TypeKind::LdapClient` fact (set by `class_name_to_type_kind` for the
    // declared types `DirContext`, `InitialDirContext`, `LdapContext`,
    // `LdapTemplate`, or by `constructor_type` for `new InitialDirContext(...)`
    // / `new InitialLdapContext(...)`).  Direct flat matchers cover the
    // documentation-style class-qualified call forms that bypass receiver
    // typing.
    LabelRule {
        matchers: &[
            "LdapClient.search",
            "LdapClient.searchByEntity",
            "LdapClient.searchForObject",
            "LdapClient.searchForContext",
            "DirContext.search",
            "LdapTemplate.search",
            "LdapTemplate.searchByEntity",
            "LdapTemplate.searchForObject",
            "LdapTemplate.searchForContext",
            "ctx.search",
        ],
        label: DataLabel::Sink(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── LDAP-filter sanitizers ───
    //
    // Spring LDAP's `LdapEncoder.filterEncode(s)` applies RFC 4515 escaping to
    // metacharacters (`\`, `*`, `(`, `)`, ` `).  `nameEncode` performs the
    // companion DN-component escaping.  Both fully clear the LDAP_INJECTION
    // cap; downstream sinks see a sanitised value.
    LabelRule {
        matchers: &["LdapEncoder.filterEncode", "LdapEncoder.nameEncode"],
        label: DataLabel::Sanitizer(Cap::LDAP_INJECTION),
        case_sensitive: true,
    },
    // ─── XPath injection sinks ───
    //
    // `javax.xml.xpath.XPath.evaluate(expr, source, ...)` and the matching
    // `XPathExpression.evaluate(source)` accept an attacker-influenceable
    // expression string.  Without parameterisation via
    // `XPathVariableResolver` the expression can be rewritten to bypass
    // authentication or exfiltrate document subtrees.  `XPath.compile(expr)`
    // is the equivalent pre-compile entry point.  Direct flat matchers cover
    // the documentation-style class-qualified call forms.
    LabelRule {
        matchers: &[
            "XPath.evaluate",
            "XPath.compile",
            "XPathExpression.evaluate",
            "xpath.evaluate",
            "xpath.compile",
        ],
        label: DataLabel::Sink(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // ─── XPath escape sanitizers ───
    //
    // OWASP ESAPI's `Encoder.encodeForXPath(s)` escapes the XPath
    // metacharacters (`'`, `"`, `[`, `]`, `(`, `)`, `,`, `=`, `<`, `>`,
    // `*`).  Project-local `xpathEscape` / `escapeXpath` are the common
    // developer-named equivalents.
    LabelRule {
        matchers: &["Encoder.encodeForXPath", "xpathEscape", "escapeXpath"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
    // Parameterised XPath via `XPath.setXPathVariableResolver(resolver)`
    // suppression is implemented as a receiver-config sidecar in
    // [`crate::ssa::xpath_config::XPathConfigResult`]: a
    // `setXPathVariableResolver` call on a receiver carrying
    // `TypeKind::XPathClient` flips the receiver's `has_resolver` flag,
    // and the SSA sink-emission site strips `Cap::XPATH_INJECTION` from
    // any later `xpath.evaluate(taintedExpr, ...)` whose receiver is
    // provably bound.  No flat sanitizer rule is needed (and a
    // name-only rule would clear the wrong call site).
    // ─── Header / CRLF injection sinks ───
    //
    // `HttpServletResponse.setHeader(name, val)` / `addHeader(name, val)`
    // accept a single header value; tainted strings without `\r\n` stripping
    // let an attacker inject extra headers (response splitting).
    // `addCookie(c)` carries a `Cookie` whose constructor takes a value
    // string; track at the higher-level setHeader / addHeader entry points.
    LabelRule {
        matchers: &["setHeader", "addHeader", "addCookie"],
        label: DataLabel::Sink(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Header / CRLF sanitizers ───
    LabelRule {
        matchers: &["stripCRLF", "stripCrlf", "escapeHeader", "sanitizeHeader"],
        label: DataLabel::Sanitizer(Cap::HEADER_INJECTION),
        case_sensitive: false,
    },
    // ─── Open redirect sinks ───
    //
    // Servlet API: `HttpServletResponse.sendRedirect(url)`.  Spring MVC
    // controllers can also return a `"redirect:"` prefixed string but that
    // sink shape is not modelled here.
    LabelRule {
        matchers: &["sendRedirect"],
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
    // Apache FreeMarker `Template.process(model, writer)` renders an
    // already-parsed template; the SSTI vector is when the template source
    // is attacker-influenced (e.g. `new Template(name, new StringReader(src), cfg)`).
    // The flat matcher fires only when the receiver chain text resolves to
    // `Template.process` — typically through a `Template`-typed declared
    // receiver routed via type-qualified resolution.  Without a `Template`
    // TypeKind, idiomatic `Template tpl = new Template(...); tpl.process(...)`
    // shapes are not recognised; tracked under deferred phases.
    //
    // Apache Velocity `Velocity.evaluate(ctx, writer, tag, src)` is modelled
    // as a gated sink in `GATED_SINKS` below so only the template-source
    // arg (index 3) activates SSTI; tainted variables in the `ctx` arg
    // (data) stay clean.
    LabelRule {
        matchers: &["Template.process"],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: true,
    },
    // ─── XXE sinks ───
    //
    // Java's stock XML parsers (JAXP) are XXE-vulnerable by default: the
    // factories ship with external-entity / DTD resolution enabled and only
    // become safe after `setFeature(FEATURE_SECURE_PROCESSING, true)` /
    // disabling `external-general-entities` / `external-parameter-entities`.
    // Tainted XML reaching any of these parser entry points is treated as
    // an XXE flow; a config-check sanitizer pass (Phase XXE Layer 2) is
    // out of scope for this rule and is the follow-up listed in
    // `.pitboss/play/deferred.md`.
    //
    // Class-qualified suffix matching covers both the documentation-style
    // `javax.xml.parsers.DocumentBuilder.parse(...)` form and the bound-
    // receiver `XmlParser.parse(...)` form (when the receiver's TypeKind
    // resolves to `XmlParser`).  Bare `parse` is intentionally avoided to
    // prevent collisions with `Integer.parseInt`, `LocalDate.parse`,
    // generic JSON parsers, etc.
    //
    // StAX parses straight off the factory
    // (`xif.createXMLStreamReader(in)`) and dom4j through `SAXReader.read`.
    // A fluent chain off a factory reads as the factory class plus the last
    // method (`DocumentBuilderFactory.newInstance().newDocumentBuilder()
    // .parse(x)` is `DocumentBuilderFactory.parse`), and such a chain never
    // configures the factory.
    LabelRule {
        matchers: &[
            "DocumentBuilder.parse",
            "SAXParser.parse",
            "XMLReader.parse",
            "SAXBuilder.build",
            "SAXReader.read",
            "DocumentBuilderFactory.parse",
            "SAXParserFactory.parse",
            "XMLInputFactory.createXMLStreamReader",
            "XMLInputFactory.createXMLEventReader",
            "XmlParser.parse",
            "XmlParser.build",
            "XmlParser.read",
            "XmlParser.createXMLStreamReader",
            "XmlParser.createXMLEventReader",
        ],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
    },
    // ─── XXE config-setter sanitizers ───
    //
    // Phase 07: a JAXP `setFeature(...)` / `setExpandEntityReferences(...)`
    // call is itself a label-level Sanitizer for `Cap::XXE` so that the
    // *call's return value* (rare but exists for fluent factory APIs)
    // does not carry XXE through it.  The real load-bearing suppression
    // is the receiver-fact path in
    // [`crate::ssa::xml_config::XmlParserConfigResult`], which the SSA
    // sink emission consults at every parse-class sink site.  This rule
    // is conservative noise reduction for downstream sinks that consume
    // the setter call's value.
    LabelRule {
        matchers: &[
            "setFeature",
            "setExpandEntityReferences",
            "setXIncludeAware",
            "setValidating",
        ],
        label: DataLabel::Sanitizer(Cap::XXE),
        case_sensitive: true,
    },
];

/// Java gated sinks.  Argument-position-aware classification for callees
/// where the SSTI activation is restricted to the template-source arg
/// rather than every positional argument.
pub static GATED_SINKS: &[SinkGate] = &[
    // `java.nio.file.Files` verbs take the path first; the arguments after it
    // are a charset, the bytes or lines to write, or open options.  The flat
    // FILE_IO rule above lists every argument, so these gates narrow the
    // payload to the path: a request-chosen charset or request text written
    // into a fixed file does not choose which file is opened.
    SinkGate {
        callee_matcher: "Files.readString",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.readAllLines",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.lines",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.newBufferedReader",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.newBufferedWriter",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.newInputStream",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.newOutputStream",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.write",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "Files.writeString",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // Netty file constructors take the file first; the offset, length and
    // chunk size that follow do not choose which file is opened.
    SinkGate {
        callee_matcher: "DefaultFileRegion",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "ChunkedFile",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    SinkGate {
        callee_matcher: "ChunkedNioFile",
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::FILE_IO),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // Apache Velocity static API: `Velocity.evaluate(ctx, writer, logTag, src)`.
    // Arg 3 carries the inline template source; tainted text at that
    // position is SSTI.  Tainted data in the context (arg 0) is rendered
    // through Velocity's escape policy, not parsed as template source, so
    // those flows must not activate SSTI.  Activation is unconditional;
    // payload_args narrows the cap to the template-source position.
    SinkGate {
        callee_matcher: "Velocity.evaluate",
        arg_index: 3,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::SSTI),
        case_sensitive: true,
        payload_args: &[3],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    },
    // ── SQL execute payload-arg gating (Phase 15 deferred fix, Java) ──────
    //
    // Mirrors the Python resolution recorded in `python::GATED_SINKS`: the
    // flat rules above already classify these callees as `Sink(SQL_QUERY)`
    // on every argument.  The JDBC / JPA / Hibernate / Spring conventions
    // are that arg 0 is the SQL template (or HQL/JPQL string) and any
    // remaining arguments are bind values, RowMappers, result-set classes,
    // or other non-SQL payloads.  Tainted bind values are SAFE because the
    // driver / JPA layer escapes them; tainted SQL is the SQLi vector.
    //
    // These Destination-activation gates carry the same `Sink(SQL_QUERY)`
    // label as the flat rule (so cap dedupes against the flat label) but
    // propagate `payload_args: &[0]` into `sink_payload_args`, narrowing the
    // SSA sink scan to arg 0 only.  Receiver-typed `DatabaseConnection.*`
    // forms are case-sensitive, matching the flat rule.
    SinkGate {
        callee_matcher: "executeQuery",
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
        callee_matcher: "executeUpdate",
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
        callee_matcher: "DatabaseConnection.execute",
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
        callee_matcher: "DatabaseConnection.executeBatch",
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
        callee_matcher: "DatabaseConnection.executeLargeUpdate",
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
    // Spring JdbcTemplate verbs.  All take SQL at arg 0; remaining args are
    // bind values (`Object[]` / varargs) or `RowMapper` / `ResultSetExtractor`
    // / class hints — all non-SQL payloads.
    sql_arg0_gate("jdbcTemplate.query"),
    sql_arg0_gate("jdbcTemplate.update"),
    sql_arg0_gate("jdbcTemplate.execute"),
    sql_arg0_gate("jdbcTemplate.queryForObject"),
    sql_arg0_gate("jdbcTemplate.queryForList"),
    sql_arg0_gate("jdbcTemplate.queryForMap"),
    sql_arg0_gate("jdbcTemplate.queryForRowSet"),
    sql_arg0_gate("jdbcTemplate.queryForStream"),
    sql_arg0_gate("jdbcTemplate.queryForInt"),
    sql_arg0_gate("jdbcTemplate.queryForLong"),
    sql_arg0_gate("jdbcTemplate.batchUpdate"),
    sql_arg0_gate("getJdbcTemplate.query"),
    sql_arg0_gate("getJdbcTemplate.update"),
    sql_arg0_gate("getJdbcTemplate.execute"),
    sql_arg0_gate("getJdbcTemplate.queryForObject"),
    sql_arg0_gate("getJdbcTemplate.queryForList"),
    sql_arg0_gate("getJdbcTemplate.queryForMap"),
    sql_arg0_gate("getJdbcTemplate.queryForRowSet"),
    sql_arg0_gate("getJdbcTemplate.queryForStream"),
    sql_arg0_gate("getJdbcTemplate.queryForInt"),
    sql_arg0_gate("getJdbcTemplate.queryForLong"),
    sql_arg0_gate("getJdbcTemplate.batchUpdate"),
    // ── Spring RestTemplate ───────────────────────────────────────────────
    //
    // The flat SSRF / DATA_EXFIL rules above match every argument.  The URL
    // is arg 0 (or the `RequestEntity` of `exchange(entity, T.class)`); the
    // request body is arg 1 of the `post*` / `put` / `patchForObject`
    // verbs and arg 2 of `exchange(url, method, entity, T.class)`.  Trailing
    // `uriVariables` are expanded into the path or query of the template at
    // arg 0 and cannot move the host, so a tainted body or path variable
    // under a fixed origin is not SSRF.
    destination_gate("getForObject", Cap::SSRF, &[0]),
    destination_gate("getForEntity", Cap::SSRF, &[0]),
    destination_gate("headForHeaders", Cap::SSRF, &[0]),
    destination_gate("postForObject", Cap::SSRF, &[0]),
    destination_gate("postForEntity", Cap::SSRF, &[0]),
    destination_gate("RestTemplate.exchange", Cap::SSRF, &[0]),
    destination_gate("postForObject", Cap::DATA_EXFIL, &[1]),
    destination_gate("postForEntity", Cap::DATA_EXFIL, &[1]),
    destination_gate("RestTemplate.put", Cap::DATA_EXFIL, &[1]),
    destination_gate("RestTemplate.patchForObject", Cap::DATA_EXFIL, &[1]),
    destination_gate("RestTemplate.exchange", Cap::DATA_EXFIL, &[0, 2]),
    // ── Reflective dispatch by name ───────────────────────────────────────
    //
    // `cls.getMethod(name, paramTypes...)` / `getDeclaredMethod`: a
    // request-chosen `name` is the Struts DispatchAction / DMI style of
    // unsafe reflection (CWE-470), the method-level twin of
    // `Class.forName(tainted)`.  A literal name never fires; a call with no
    // arguments (`request.getMethod()`) has no name to be tainted.
    method_name_gate("getMethod"),
    method_name_gate("getDeclaredMethod"),
    // A template that puts a variable in the scheme or authority
    // (`"http://{host}/api"`) does let the uriVariables pick the host, so
    // every argument is SSRF payload there.
    host_template_gate("getForObject"),
    host_template_gate("getForEntity"),
    host_template_gate("headForHeaders"),
    host_template_gate("postForObject"),
    host_template_gate("postForEntity"),
    host_template_gate("RestTemplate.exchange"),
    // JPA / Hibernate factories.  `createQuery(sql)` / `createQuery(sql, ResultClass)`
    // both take the SQL/JPQL/HQL string at arg 0; the optional `ResultClass`
    // at arg 1 is metadata, not SQL.
    SinkGate {
        callee_matcher: "entityManager.createQuery",
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
        callee_matcher: "entityManager.createNativeQuery",
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
        callee_matcher: "em.createQuery",
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
        callee_matcher: "em.createNativeQuery",
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
        callee_matcher: "session.createQuery",
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
        callee_matcher: "session.createSQLQuery",
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
        callee_matcher: "session.createNativeQuery",
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
        callee_matcher: "getEntityManager.createQuery",
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
        callee_matcher: "getEntityManager.createNativeQuery",
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
        callee_matcher: "getSession.createQuery",
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
        callee_matcher: "getSession.createSQLQuery",
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
        callee_matcher: "getSession.createNativeQuery",
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
    // Type-qualified Hibernate Session gates.  Mirror the
    // `session.create*` family above so type-qualified resolution at
    // sink-firing time consults `payload_args = &[0]` and suppresses
    // tainted bind-arg shapes that route through `setParameter` /
    // `setString` rather than the raw query string.  Receivers carry
    // `TypeKind::HibernateSession` via `constructor_type`'s
    // `openSession` / `getCurrentSession` / `openStatelessSession`
    // arms.
    SinkGate {
        callee_matcher: "HibernateSession.createQuery",
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
        callee_matcher: "HibernateSession.createSQLQuery",
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
        callee_matcher: "HibernateSession.createNativeQuery",
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

/// Case-insensitive SQL sink gate whose statement is arg 0, for the Spring
/// `JdbcTemplate` verbs.
const fn sql_arg0_gate(callee_matcher: &'static str) -> SinkGate {
    SinkGate {
        callee_matcher,
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
    }
}

/// Case-insensitive gate that fires on taint at the `payload_args`
/// positions only.
const fn destination_gate(
    callee_matcher: &'static str,
    cap: Cap,
    payload_args: &'static [usize],
) -> SinkGate {
    SinkGate {
        callee_matcher,
        arg_index: payload_args[0],
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(cap),
        case_sensitive: false,
        payload_args,
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::Destination {
            object_destination_fields: &[],
        },
    }
}

/// `Sink(CODE_EXEC)` on a reflective lookup whose first argument is the
/// method name.  Value-match activation with no dangerous values: a string
/// literal name suppresses, a computed one fires, and a call with no first
/// argument stays inert.
const fn method_name_gate(callee_matcher: &'static str) -> SinkGate {
    SinkGate {
        callee_matcher,
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &[],
        label: DataLabel::Sink(Cap::CODE_EXEC),
        case_sensitive: true,
        payload_args: &[0],
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::ValueMatch,
    }
}

/// SSRF on every argument of a RestTemplate call whose literal URL template
/// starts with a template variable in the scheme or authority.
const fn host_template_gate(callee_matcher: &'static str) -> SinkGate {
    SinkGate {
        callee_matcher,
        arg_index: 0,
        dangerous_values: &[],
        dangerous_prefixes: &["{", "http://{", "https://{", "//{"],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
        payload_args: crate::labels::ALL_ARGS_PAYLOAD,
        keyword_name: None,
        dangerous_kwargs: &[],
        activation: GateActivation::LiteralOnly,
    }
}

pub static KINDS: Map<&'static str, Kind> = phf_map! {
    // control-flow
    "if_statement"                 => Kind::If,
    "while_statement"              => Kind::While,
    "for_statement"                => Kind::For,
    "enhanced_for_statement"       => Kind::For,
    "do_statement"                 => Kind::While,

    "return_statement"             => Kind::Return,
    "throw_statement"              => Kind::Throw,
    "break_statement"              => Kind::Break,
    "continue_statement"           => Kind::Continue,

    // structure
    "program"                      => Kind::SourceFile,
    "block"                        => Kind::Block,
    "class_declaration"            => Kind::Block,
    "class_body"                   => Kind::Block,
    "interface_declaration"        => Kind::Block,
    "interface_body"               => Kind::Block,
    "enum_declaration"             => Kind::Block,
    "enum_body"                    => Kind::Block,
    "enum_body_declarations"       => Kind::Block,
    "record_declaration"           => Kind::Block,
    "synchronized_statement"       => Kind::Block,
    "method_declaration"           => Kind::Function,
    "constructor_declaration"      => Kind::Function,
    "switch_expression"            => Kind::Switch,
    "switch_block"                 => Kind::Block,
    "switch_block_statement_group" => Kind::Block,
    // Arrow case `case X -> body`; `build_switch` lowers only the body.
    "switch_rule"                  => Kind::Block,
    // `outer: for (..) {..}`: walk the labeled statement instead of
    // collapsing it into one leaf node (mirrors go.rs / c.rs / cpp.rs).
    "labeled_statement"            => Kind::Block,
    "try_statement"                => Kind::Try,
    "try_with_resources_statement" => Kind::Try,
    "resource_specification"       => Kind::Block,
    "resource"                     => Kind::CallWrapper,
    "catch_clause"                 => Kind::Block,
    "finally_clause"               => Kind::Block,
    "lambda_expression"            => Kind::Function,
    "constructor_body"             => Kind::Block,
    "static_initializer"           => Kind::Block,

    // data-flow
    "method_invocation"            => Kind::CallMethod,
    "object_creation_expression"   => Kind::CallFn,
    "assignment_expression"        => Kind::Assignment,
    // `i++` / `--i`: read-modify-write, see `cfg::rmw_assignment`.
    "update_expression"            => Kind::Assignment,
    "local_variable_declaration"   => Kind::CallWrapper,
    "expression_statement"         => Kind::CallWrapper,
    "cast_expression"              => Kind::Seq,

    // trivia
    "line_comment"                 => Kind::Trivia,
    "block_comment"                => Kind::Trivia,
    ";"  => Kind::Trivia, ","  => Kind::Trivia,
    "("  => Kind::Trivia, ")"  => Kind::Trivia,
    "{"  => Kind::Trivia, "}"  => Kind::Trivia,
    "\n" => Kind::Trivia,
    "->" => Kind::Trivia,
    "import_declaration"           => Kind::Trivia,
    "package_declaration"          => Kind::Trivia,
};

/// Callee patterns that must never be classified as source/sanitizer/sink.
/// The bare `println` / `print` / `write` response-writer sink would
/// otherwise match the process console streams.  Excluding them at label
/// time keeps the sink off the CFG node, so the taint engine, callee
/// summaries (a `log(msg)` helper that prints) and the structural
/// `cfg-unguarded-sink` rule all agree.
pub static EXCLUDES: &[&str] = &[
    "System.out.print",
    "System.out.println",
    "System.out.printf",
    "System.out.format",
    "System.out.write",
    "System.out.append",
    "System.err.print",
    "System.err.println",
    "System.err.printf",
    "System.err.format",
    "System.err.write",
    "System.err.append",
];

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["formal_parameter", "spread_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Java.  None today: a Spring project used
/// to get a bare `send` SSRF sink, which matched `KafkaTemplate.send`,
/// `SseEmitter.send`, `JavaMailSender.send` and every service `send(..)`.
/// The JDK client is covered by the type-qualified `HttpClient.send` /
/// `sendAsync` rules, reached through `constructor_type` for
/// `HttpClient.newHttpClient()` and through the declared type of a field,
/// formal or local (`cfg::java_declared_receiver_kind`).
pub fn framework_rules(_ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::KINDS;
    use crate::labels::Kind;

    #[test]
    fn container_declarations_are_walkable_blocks() {
        // interface_declaration must be mapped so its (already-mapped)
        // interface_body is reachable; enum/record/synchronized bodies
        // must be walked instead of collapsing to a leaf Seq node.
        for kind in [
            "interface_declaration",
            "interface_body",
            "enum_declaration",
            "enum_body",
            "enum_body_declarations",
            "record_declaration",
            "synchronized_statement",
        ] {
            assert_eq!(
                KINDS.get(kind),
                Some(&Kind::Block),
                "{kind} should map to Kind::Block so the CFG builder walks its body"
            );
        }
    }

    #[test]
    fn console_streams_are_not_response_sinks() {
        use crate::labels::{Cap, DataLabel, classify};
        for callee in [
            "System.out.println",
            "System.out.print",
            "System.err.println",
            "System.out.write",
            "java.lang.System.out.println",
        ] {
            assert_eq!(classify("java", callee, None), None, "{callee}");
        }
        for callee in ["out.println", "response.write", "writer.print"] {
            assert_eq!(
                classify("java", callee, None),
                Some(DataLabel::Sink(Cap::HTML_ESCAPE)),
                "{callee}"
            );
        }
    }

    #[test]
    fn prepare_statement_is_not_a_sanitizer() {
        use crate::labels::classify;
        assert_eq!(classify("java", "conn.prepareStatement", None), None);
    }

    fn has_sink(labels: &[crate::labels::DataLabel], cap: crate::labels::Cap) -> bool {
        labels
            .iter()
            .any(|l| matches!(l, crate::labels::DataLabel::Sink(c) if c.contains(cap)))
    }

    #[test]
    fn spring_projects_get_no_bare_send_sink() {
        use crate::labels::{Cap, classify_all};
        use crate::utils::project::{DetectedFramework, FrameworkContext};
        let ctx = FrameworkContext {
            frameworks: vec![DetectedFramework::Spring],
            ..Default::default()
        };
        let rules = super::framework_rules(&ctx);
        for callee in [
            "kafkaTemplate.send",
            "emitter.send",
            "mailSender.send",
            "notificationService.send",
        ] {
            let labels = classify_all("java", callee, Some(&rules));
            assert!(!has_sink(&labels, Cap::SSRF), "{callee}: {labels:?}");
        }
        let labels = classify_all("java", "HttpClient.send", Some(&rules));
        assert!(
            has_sink(&labels, Cap::SSRF),
            "typed JDK client stays an SSRF sink"
        );
    }

    #[test]
    fn file_reader_and_writer_constructors_are_file_sinks() {
        use crate::labels::{Cap, classify_all};
        for callee in [
            "FileReader",
            "FileWriter",
            "java.io.FileWriter",
            "DefaultFileRegion",
            "io.netty.handler.stream.ChunkedFile",
            "ChunkedNioFile",
        ] {
            let labels = classify_all("java", callee, None);
            assert!(has_sink(&labels, Cap::FILE_IO), "{callee}: {labels:?}");
        }
    }

    #[test]
    fn jdbc_template_verbs_match_any_receiver_through_the_declared_type() {
        use crate::labels::{Cap, classify_all, classify_gated_sink};
        for callee in [
            "JdbcTemplate.query",
            "JdbcTemplate.queryForMap",
            "JdbcTemplate.queryForRowSet",
            "JdbcTemplate.queryForStream",
            "JdbcTemplate.batchUpdate",
            "getJdbcTemplate.update",
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate",
        ] {
            let labels = classify_all("java", callee, None);
            assert!(has_sink(&labels, Cap::SQL_QUERY), "{callee}: {labels:?}");
            let gates = classify_gated_sink("java", callee, |_| None, |_| None, |_| true);
            assert!(
                gates.iter().any(|g| g.payload_args == [0]),
                "{callee} gates the SQL text at arg 0 only: {gates:?}"
            );
        }
        assert!(classify_all("java", "map.query", None).is_empty());
    }

    #[test]
    fn rest_template_gates_split_url_and_body() {
        use crate::labels::{ALL_ARGS_PAYLOAD, Cap, DataLabel, classify_gated_sink};
        let payloads = |callee: &str, cap: Cap, first_arg: Option<&str>| -> Vec<Vec<usize>> {
            let first = first_arg.map(str::to_string);
            classify_gated_sink(
                "java",
                callee,
                |i| if i == 0 { first.clone() } else { None },
                |_| None,
                |_| true,
            )
            .into_iter()
            .filter(|g| matches!(g.label, DataLabel::Sink(c) if c == cap))
            .map(|g| g.payload_args.to_vec())
            .collect()
        };
        // A fixed template: the URL is SSRF payload, the body is DATA_EXFIL
        // payload, and uriVariables are neither.
        let url = "https://api.example.com/users/{id}";
        assert_eq!(
            payloads("restTemplate.postForObject", Cap::SSRF, Some(url)),
            vec![vec![0]]
        );
        assert_eq!(
            payloads("restTemplate.postForObject", Cap::DATA_EXFIL, Some(url)),
            vec![vec![1]]
        );
        assert_eq!(
            payloads("rt.getForObject", Cap::SSRF, Some(url)),
            vec![vec![0]]
        );
        assert!(payloads("rt.getForObject", Cap::DATA_EXFIL, Some(url)).is_empty());
        assert_eq!(
            payloads("RestTemplate.exchange", Cap::DATA_EXFIL, Some(url)),
            vec![vec![0, 2]]
        );
        // A variable in the scheme or authority lets uriVariables pick the host.
        let hosted = payloads("rt.getForObject", Cap::SSRF, Some("http://{host}/api"));
        assert!(
            hosted.iter().any(|p| p == ALL_ARGS_PAYLOAD),
            "host template widens SSRF to every argument: {hosted:?}"
        );
        assert!(
            !payloads("rt.getForObject", Cap::SSRF, Some(url))
                .iter()
                .any(|p| p == ALL_ARGS_PAYLOAD)
        );
    }

    #[test]
    fn xml_factory_and_dom4j_parsers_are_xxe_sinks() {
        use crate::labels::{Cap, classify_all};
        for callee in [
            "XmlParser.createXMLStreamReader",
            "XmlParser.createXMLEventReader",
            "XmlParser.read",
            "XMLInputFactory.createXMLStreamReader",
            "DocumentBuilderFactory.parse",
            "SAXParserFactory.parse",
            "SAXReader.read",
        ] {
            let labels = classify_all("java", callee, None);
            assert!(has_sink(&labels, Cap::XXE), "{callee}: {labels:?}");
        }
        assert!(classify_all("java", "reader.read", None).is_empty());
    }

    #[test]
    fn servlet_get_reader_is_user_input_and_read_line_is_file_data() {
        use crate::labels::{Cap, SourceKind, infer_source_kind};
        assert_eq!(
            infer_source_kind(Cap::all(), "req.getReader"),
            SourceKind::UserInput
        );
        assert_eq!(
            infer_source_kind(Cap::all(), "br.readLine"),
            SourceKind::FileSystem
        );
    }

    #[test]
    fn reflective_lookup_by_name_is_a_gated_code_exec_sink() {
        use crate::labels::{Cap, DataLabel, classify_gated_sink_with_presence};
        let fires = |callee: &str, first: Option<&str>, has_arg: bool| {
            let first = first.map(str::to_string);
            classify_gated_sink_with_presence(
                "java",
                callee,
                |i| if i == 0 { first.clone() } else { None },
                |_| None,
                |_| false,
                |i| has_arg && i == 0,
            )
            .iter()
            .any(|g| matches!(g.label, DataLabel::Sink(c) if c.contains(Cap::CODE_EXEC)))
        };
        assert!(fires("this.getMethod", None, true), "computed name");
        assert!(fires("cls.getDeclaredMethod", None, true), "computed name");
        assert!(!fires("cls.getMethod", Some("list"), true), "literal name");
        assert!(
            !fires("request.getMethod", None, false),
            "servlet getMethod() has no name"
        );
    }
}

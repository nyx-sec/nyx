use crate::labels::{Cap, DataLabel, Kind, LabelRule, ParamConfig, RuntimeLabelRule};
use crate::utils::project::{DetectedFramework, FrameworkContext};
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
            "getInputStream",
            "getHeader",
            "getCookies",
            "getReader",
            "getQueryString",
            "getPathInfo",
            "getRequestURI",
            "getRequestURL",
            "getServletPath",
            "getContextPath",
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
        matchers: &["HtmlUtils.htmlEscape", "StringEscapeUtils.escapeHtml4"],
        label: DataLabel::Sanitizer(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // OWASP ESAPI encoders
    LabelRule {
        matchers: &["Encoder.encodeForHTML", "Encoder.encodeForJavaScript"],
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
    // Parameterized queries prevent SQL injection
    LabelRule {
        matchers: &["prepareStatement"],
        label: DataLabel::Sanitizer(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    // ─────────── Sinks ─────────────
    LabelRule {
        matchers: &["Runtime.exec", "ProcessBuilder"],
        label: DataLabel::Sink(Cap::SHELL_ESCAPE),
        case_sensitive: false,
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
    // HTTP response sinks, println/print are broad (also match System.out)
    // but necessary to catch response.getWriter().println() via suffix matching.
    LabelRule {
        matchers: &["println", "print"],
        label: DataLabel::Sink(Cap::HTML_ESCAPE),
        case_sensitive: false,
    },
    // openConnection() is the standard java.net.URL API for initiating a connection.
    // It is the correct interception point, the URL is already set on the object.
    LabelRule {
        matchers: &[
            "openConnection",
            "HttpClient.send",
            "HttpClient.sendAsync",
            "getForObject",
            "RestTemplate.exchange",
            "postForObject",
            "postForEntity",
        ],
        label: DataLabel::Sink(Cap::SSRF),
        case_sensitive: false,
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
    LabelRule {
        matchers: &[
            "jdbcTemplate.query",
            "jdbcTemplate.update",
            "jdbcTemplate.execute",
            "jdbcTemplate.queryForObject",
            "jdbcTemplate.queryForList",
        ],
        label: DataLabel::Sink(Cap::SQL_QUERY),
        case_sensitive: false,
    },
    LabelRule {
        matchers: &[
            "entityManager.createNativeQuery",
            "entityManager.createQuery",
            "session.createQuery",
            "session.createSQLQuery",
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
    // Parameterised XPath via `XPath.setXPathVariableResolver(resolver)` is
    // the RFC-correct binding: the resolver carries user values as named
    // variables and the expression contains `$name` references rather than
    // string concatenation.  Treating the resolver argument as a sanitizer
    // clears XPATH_INJECTION on values routed through the resolver
    // construction so any later `evaluate(...)` on the bound XPath instance
    // stays clean.
    LabelRule {
        matchers: &["setXPathVariableResolver"],
        label: DataLabel::Sanitizer(Cap::XPATH_INJECTION),
        case_sensitive: false,
    },
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
        matchers: &["validateRedirectUrl", "isSafeRedirect", "stripScheme"],
        label: DataLabel::Sanitizer(Cap::OPEN_REDIRECT),
        case_sensitive: false,
    },
    // ─── SSTI sinks ───
    //
    // Apache FreeMarker: `freemarker.template.Template.process(model, writer)`
    // renders an already-parsed template.  The SSTI vector is when the
    // template *source* is attacker-influenced (loaded via
    // `new Template(name, new StringReader(src), cfg)` /
    // `Configuration.getTemplate(attackerName)`); tainted data reaching
    // `process` indicates the source-influenced template is being rendered.
    // Suffix matching on `Template.process` covers the documentation-style
    // class-qualified call form and bound-receiver `template.process(...)`.
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
    LabelRule {
        matchers: &[
            "DocumentBuilder.parse",
            "SAXParser.parse",
            "XMLReader.parse",
            "SAXBuilder.build",
            "XmlParser.parse",
            "XmlParser.build",
        ],
        label: DataLabel::Sink(Cap::XXE),
        case_sensitive: true,
    },
];

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
    "interface_body"               => Kind::Block,
    "method_declaration"           => Kind::Function,
    "constructor_declaration"      => Kind::Function,
    "switch_expression"            => Kind::Switch,
    "switch_block"                 => Kind::Block,
    "switch_block_statement_group" => Kind::Block,
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
    "import_declaration"           => Kind::Trivia,
    "package_declaration"          => Kind::Trivia,
};

pub static PARAM_CONFIG: ParamConfig = ParamConfig {
    params_field: "parameters",
    param_node_kinds: &["formal_parameter", "spread_parameter"],
    self_param_kinds: &[],
    ident_fields: &["name"],
};

/// Framework-conditional rules for Java.
pub fn framework_rules(ctx: &FrameworkContext) -> Vec<RuntimeLabelRule> {
    let mut rules = Vec::new();

    if ctx.has(DetectedFramework::Spring) {
        // When Spring is detected, bare "send" is likely HttpClient.send()
        rules.push(RuntimeLabelRule {
            matchers: vec!["send".into()],
            label: DataLabel::Sink(Cap::SSRF),
            case_sensitive: false,
        });
    }

    rules
}

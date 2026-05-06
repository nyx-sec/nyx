## Deferred items

- [ ] Java parameterised-XPath sanitizer is name-only and does not actually suppress taint at the sink. The `setXPathVariableResolver` Sanitizer rule added in phase 03 (`src/labels/java.rs`) fires on the resolver-binding call but has no effect on a separate `xpath.evaluate(taintedExpr, ...)` later in the same flow — taint clearing happens on the wrong call site. The phase-03 fixture `tests/fixtures/xpath_injection/java/ParameterizedXpath.java` only passes because its expression argument is a constant literal `"//user[name=$u]"` (same reason `BaselineConstantXpath.java` passes); a fixture with a tainted expression and a preceding `setXPathVariableResolver` would still fire. Real fix needs a `XPath` TypeKind with a "has resolver" receiver fact (TypeFacts) that suppresses the sink when the bound instance is later used by `evaluate` — same engine shape as the deferred Java `setFeature` XXE config-check pattern.
- [ ] Open-redirect sanitizer recognition is name-only: `validateRedirectUrl` / `ensureRelativeUrl` / `is_safe_redirect` (and snake_case mirrors) clear `Cap::OPEN_REDIRECT` purely by callee identifier. The phase-05 deliverable also lists structural recognition — `URL parse + host allowlist comparison` and `url.starts_with("/")` followed by no-scheme check. That requires the abstract-string-domain / TypeFacts pattern hook to track URL parse calls (`new URL(...)`, `urllib.parse.urlparse`, `url::Url::parse`, `net/url.Parse`) plus the host-equality / leading-slash pattern; a fixture that performs the same allowlist inline (without delegating to a named helper) currently falls through to the sink.

## Deferred phases

### From phase 01: XXE detection — Layer 1 landed; Layer 2 deferred

**Scope.** `Cap::XXE` detection in two layers:
1. ~~Sink label rules for parser entry points~~ — landed:
   * Java flat sinks: `DocumentBuilder.parse`, `SAXParser.parse`, `XMLReader.parse`, `SAXBuilder.build`, `XmlParser.parse`/`build` (class-qualified suffix).
   * Python flat sinks: `xml.sax.parseString`/`parse`, `xml.dom.minidom.parseString`/`parse`, `xml.dom.pulldom.parseString`/`parse`; sanitizers cover the full `defusedxml.*` namespace.
   * PHP gated sinks (`GATED_SINKS` in `labels/php.rs`): `simplexml_load_string`/`load_file` and `loadXML` activate only when arg-2 / arg-1 includes `LIBXML_NOENT` / `LIBXML_DTDLOAD` / `LIBXML_DTDATTR`. Integer literal `0` now suppresses the gate (added integer-literal extraction to `extract_const_macro_arg`). Sanitizers: `libxml_disable_entity_loader`, `libxml_set_external_entity_loader`.
   * JS/TS gated sinks: `xml2js.parseString` activates on `processEntities: true` / `explicitEntities: true` / `strict: false` kwargs. Flat: `libxmljs.parseXmlString`/`parseXml`.
   * Ruby flat sink: `REXML::Document.new`.
   * Test coverage: `tests/xxe_tests.rs` + `tests/fixtures/xxe/{java,python,php,javascript,ruby}/`.
2. Config-check pattern that suppresses XXE when the parser is provably configured with secure-processing on (e.g. Java `setFeature(FEATURE_SECURE_PROCESSING, true)`, Python `defusedxml`, Ruby `Nokogiri::XML::ParseOptions::DEFAULT_XML`).
   * Python `defusedxml` is covered today via name-only Sanitizer rules; the parser-instance hardening pattern (`factory.setFeature(...)` then later `builder.parse(...)` clean) is **still deferred** and needs TypeFacts (`XmlParser` TypeKind + secure-config carry) plus an abstract-interp pattern hook.
   * fast-xml-parser `new XMLParser({ processEntities: true }).parse(xml)` is also deferred until constructor-options are tracked at the receiver (no flat-rule equivalent without TypeFacts).
   * ~~Nokogiri default-safe gate (option-flagged `Nokogiri::XML(xml, opts, ParseOptions::NOENT)`) is deferred until Ruby gets a `GATED_SINKS` table.~~ — **landed**: Ruby `GATED_SINKS` table added in `labels/ruby.rs` and registered in `GATED_REGISTRY`; Nokogiri gates cover `Nokogiri.XML(xml, ..., opts)`, `Nokogiri::XML::Document.parse(xml, ..., opts)`, and `Nokogiri.HTML(...)` with `dangerous_values: ["NOENT", "DTDLOAD", "DTDATTR"]`. `extract_const_macro_arg` extended for tree-sitter-ruby `scope_resolution` / `constant` nodes (returns the leaf `name` field so a fully-qualified `Nokogiri::XML::ParseOptions::NOENT` matches `NOENT`); `cfg::push_node` enables the macro-arg fallback for `lang == "ruby" / "rb"`. Default-arg semantics: when the option arg is absent the gate falls into the same conservative-fire branch as PHP `simplexml_load_string($xml)` (callers can suppress by passing a non-dangerous scope-qualified constant such as `Nokogiri::XML::ParseOptions::DEFAULT_XML`). Fixtures under `tests/fixtures/xxe/ruby/{unsafe,safe}_xxe_nokogiri.rb` plus `xxe_tests::ruby_nokogiri_xml_*` cover both paths.

**Deliverables (remaining).** TypeFacts `XmlParser` kind with config carry; abstract-interp config-check pattern; Nokogiri / fast-xml-parser gated detection; Log4Shell XXE-leg CVE fixture.

**Acceptance.** Layer-1 acceptance met; Layer-2 acceptance is "secure-by-config fixtures stay clean even when the parser entry point is reached".

### From phase 01: Prototype pollution Stage 2 (dynamic-key sink)

**Scope.** Stage 1 (library-mediated `_.merge` / `Object.assign`) landed; this is the engine-work follow-up. Hook into the existing pointer-analysis `__index_set__` synthetic node so a tainted *key* in `obj[userKey] = val` triggers a sink classification when the key can reach `__proto__` / `constructor`.

**Deliverables.** Stage 2 dynamic-key sink classifier wired through pointer analysis W5 subscript synthesis; CVE fixtures (lodash, immer, etc.); TypeKind / receiver-fact propagation so `Object.create(null)` produces a `NullPrototypeObject` fact that suppresses the sink.

**Acceptance.** Stage 2 fires on direct-subscript fixtures; benign `obj[knownKey] = ...` patterns stay clean; reject-list guards (`if (k === "__proto__") return`) suppress the finding.

### From phase 04: Header / CRLF injection follow-ups

- ~~Go (`Header().Set`)~~, ~~Rust (`headers_mut().insert`)~~, ~~Ruby (`response.headers[]=`)~~ — landed (Go suffix `Header.Set`/`Header.Add`; Rust suffix `headers_mut.insert`/`headers_mut.append`; Ruby `set_header`/`add_header`).
- ~~Bare subscript-set form `response.headers["X"] = v`~~ — landed for Ruby via the LHS-subscript classification path in `cfg/mod.rs::push_node` (`element_reference` / `subscript_expression` / `subscript`) plus a new `response.headers` / `res.headers` / `self.response.headers` flat sink rule in `labels/ruby.rs`.
- ~~JS/TS / Python mirror the same path with their own `res.headers` / `response.headers` rule additions~~ — landed: `labels/javascript.rs`, `labels/typescript.rs`, and `labels/python.rs` each carry a flat `Sink(HEADER_INJECTION)` rule with `res.headers` / `response.headers` / `self.response.headers` (Python also `resp.headers`); subscript-set fixtures + tests added for all three under `tests/fixtures/header_injection/{javascript,typescript,python}/{unsafe,safe}_subscript_set.*`.
- ~~Go + Rust positive/sanitised fixtures + tests~~ — landed in phase 04: `tests/fixtures/header_injection/{go,rust}/{unsafe,safe}_set_header.{go,rs}` cover `w.Header().Set` (Go) and `response.headers_mut().insert` (Rust), with project-local `stripCRLF` / `strip_crlf` helpers as the sanitizer; tests `go_set_header_with_tainted_value_fires` / `rust_set_header_with_tainted_value_fires` (+ clean counterparts) wired into `tests/header_injection_tests.rs`.
- ~~PHP `header("Location: " . $url)` co-fire of `taint-header-injection` and `taint-open-redirect`~~ — verified by phase 04 integration test `php_header_location_cofires_header_injection_and_open_redirect` (asserts both rule prefixes surface on `tests/fixtures/open_redirect/php/unsafe_redirect.php`); back-end already wired via PHP `GATED_SINKS` in `labels/php.rs` with `dedup_by_key` / `events_to_findings` carrying `effective_sink_caps`.

### From phase 05: Open redirect follow-ups

- ~~Go (`http.Redirect`)~~, ~~Rust (`Redirect::to`)~~, ~~Ruby (`redirect_to`)~~ — landed.
- ~~PHP gated `header("Location: " . $url)`~~ — landed via `GATED_SINKS` in `labels/php.rs` (HEADER_INJECTION + OPEN_REDIRECT co-emit through multi-gate dispatch; `extract_const_string_arg` now handles PHP `encapsed_string` and the leading literal of a concat `binary_expression`; `dedup_by_key` in `taint/mod.rs` and `events_to_findings` in `taint/ssa_transfer/events.rs` extended with `effective_sink_caps` so co-tagged sinks survive dedup).
- ~~Rust `Redirect::permanent` / `Redirect::temporary` (axum)~~, ~~Ruby `redirect` (Sinatra)~~, ~~JS/TS `router.navigate` / `window.location` / `window.location.href` / `location.href`~~ — landed in phase 05 sweep: `labels/{rust,ruby,javascript,typescript}.rs` extended; `cfg::push_node` LHS member-expression classification path picks up `window.location = url` / `location.href = url` assignment shapes via the existing `member_expr_text` lookup. Phase-05 fixtures use the call-form (`res.redirect`/`Redirect::permanent`/`redirect_to`) for the integration assertions; LHS-assignment shapes are covered structurally but not exercised by a dedicated fixture.
- Spring MVC `"redirect:" + url` controller-return string is **still deferred**. The phase-05 deliverable lists it as best-effort. Real recognition needs the abstract-string-domain prefix-fact to detect a return whose value has prefix `redirect:` and whose suffix is tainted, then emit OPEN_REDIRECT on the return point. No flat-matcher equivalent exists because `return` is the structural shape, not a callee.
- Actix `HttpResponse::Found().header("Location", x)` is **still deferred**. The chain text after suffix-stripping is `HttpResponse.Found.header`, which already surfaces as a `Cap::HEADER_INJECTION` sink (the Phase-04 `header` matcher), but the OPEN_REDIRECT co-tag fires only when arg-0 is a constant string starting with `Location:` — which actix splits across two args (`name`, `value`). Needs either a new gate keyed on `arg_index: 0, dangerous_values: &["Location"]` plus `payload_args: &[1]` for actix specifically, or an abstract-string pattern hook that recognises `header("Location", _)` shape.
- Inline structural sanitizer recognition (URL parse + host allowlist, leading-slash check without a developer-named helper) tracked under `## Deferred items` above.

### From phase 06: SSTI follow-ups

- ~~PHP (`$twig->createTemplate(...)`)~~, ~~Ruby (`ERB.new`, `Liquid::Template.parse`)~~, ~~Java (Freemarker `Template.process`)~~, ~~Go (`text/template.Parse`)~~ — landed.
- ~~`nunjucks.renderString(src, ctx)` gated SSTI classifier~~ — landed for JS and TS via `GATED_SINKS` (Destination activation, `payload_args: &[0]`); tainted-`ctx`-only flows now suppressed.

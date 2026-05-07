#![allow(clippy::if_same_then_else)]

use std::collections::{BTreeMap, HashMap};

use super::const_prop::ConstLattice;
use super::ir::*;
use crate::cfg::{BinOp, Cfg};
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Inferred type kind for an SSA value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)] // All variants are part of the public API
pub enum TypeKind {
    String,
    Int,
    Bool,
    Object,
    Array,
    Null,
    Unknown,
    // Security-relevant abstract types.
    HttpResponse,
    DatabaseConnection,
    FileHandle,
    Url,
    HttpClient,
    /// A pre-network HTTP request builder produced by `Client::post(url)`,
    /// `surf::post(url)`, `Request::builder()`, `ureq::post(url)`, etc.
    /// The body-bind methods (`body`, `json`, `form`, `multipart`,
    /// `body_string`, `body_json`, `body_bytes`) and terminal verbs
    /// (`send`, `send_string`, `send_json`, `send_form`) are sinks for
    /// `DATA_EXFIL` when receiver-typed.  Distinct from `HttpClient` so
    /// type-qualified resolution can attach builder-only rules without
    /// over-firing on plain client objects.
    RequestBuilder,
    /// A local, in-memory collection (HashMap, HashSet, Vec, etc.).
    /// The auth sink gate uses this so calls like `map.insert(...)`
    /// are treated as bookkeeping rather than cross-tenant sinks. No
    /// `label_prefix`, never participates in label-based callee
    /// resolution.
    LocalCollection,
    /// A JPA / Hibernate Criteria API query object (`CriteriaQuery<T>`,
    /// `CriteriaUpdate<T>`, `CriteriaDelete<T>`, `Subquery<T>`,
    /// `TypedQuery<T>`).  These objects are produced by the
    /// `CriteriaBuilder` and emit parameterized SQL when handed to
    /// `Session.createQuery(cq)` / `EntityManager.createQuery(cq)`.  The
    /// argument is structural (predicate AST), not a string, so SQL
    /// injection cannot flow through it.  Used to suppress the
    /// `cfg-unguarded-sink` finding on `session.createQuery(cq)` shapes
    /// where openmrs / xwiki / keycloak Hibernate DAOs build queries
    /// via `cb.createQuery(Foo.class)` + `Root` / `Predicate` API.
    JpaCriteriaQuery,
    /// An LDAP directory-service client / connection (`DirContext`,
    /// `LdapTemplate`, `Net::LDAP`, `ldap3.Connection`, `ldap.createClient`,
    /// `ldap.DialURL`, etc.).  Distinct from `DatabaseConnection` so the
    /// type-qualified `LdapClient.search` rule fires only on directory
    /// search APIs rather than every DB receiver with a `search` method.
    LdapClient,
    /// An XPath query / evaluation client (`DOMXPath`, `XPath`,
    /// `XPathExpression`, `lxml.etree.XPath`, etc.).  Distinct from
    /// `DatabaseConnection` so the type-qualified `XPathClient.query` /
    /// `XPathClient.evaluate` rules fire only on XPath APIs rather than
    /// every receiver with a generic `query` / `evaluate` method (avoids
    /// collision with PHP `$pdo->query` SQL_QUERY sink).
    XPathClient,
    /// A pre-parsed template object whose `process` / `merge` /
    /// `render` method renders bound data through an already-compiled
    /// template body.  The SSTI vector is when the template *source*
    /// fed to the constructor / factory was attacker-influenced; the
    /// render-time call site is the sink.  Currently populated by
    /// `new freemarker.template.Template(...)`; the type-qualified
    /// resolver rewrites `tpl.process(...)` → `Template.process` so
    /// the existing flat SSTI rule fires on idiomatic
    /// `Template tpl = new Template(...); tpl.process(model, out)`
    /// shapes.
    Template,
    /// An XML parser instance produced by a JAXP factory call
    /// (`DocumentBuilderFactory.newDocumentBuilder()`,
    /// `SAXParserFactory.newSAXParser()`, `XMLReaderFactory.createXMLReader()`).
    /// `DOMXPath` and friends keep their own `XPathClient` tag.  Used so
    /// the type-qualified `XmlParser.parse` rule fires on instance-style
    /// calls (`builder.parse(input)`) without needing a flat-rule
    /// matcher per concrete subclass.  Also gates the XXE config-fact
    /// suppression: only XmlParser-typed receivers consult the
    /// [`crate::ssa::xml_config::XmlParserConfigResult`] sidecar.
    XmlParser,
    /// A framework-injected DTO body whose field types are known.
    /// Populated when a parameter is recognised as a typed extractor and
    /// the DTO class / struct / Pydantic model is resolvable in scope.
    /// Strictly additive, without a DTO definition, callers fall back
    /// to name-only resolution.
    Dto(DtoFields),
    /// The `node:fs/promises` namespace. Receivers typed as
    /// `FileSystemPromisesNs` resolve method calls (`recv.readFile(...)`,
    /// `recv.open(...)`, ...) through the type-qualified rewrite to
    /// `FileSystemPromisesNs.<method>`, which the Phase 05 FILE_IO
    /// matcher list covers without an [`crate::labels::LabelGate`]
    /// (the receiver type is itself the import witness). Populated by
    /// [`constructor_type`] for `fs.promises` and
    /// `require('fs').promises`; further refinement (FieldProj-driven
    /// narrowing for `const fsp = fs.promises`) tracked in
    /// `deferred.md`.
    FileSystemPromisesNs,
    /// An object created with `Object.create(null)` — has no prototype
    /// chain, so subscript-write keys cannot pollute `Object.prototype`.
    /// Populated for JS/TS values whose constructor call is
    /// `Object.create(null)`. The PROTOTYPE_POLLUTION suppression at the
    /// synthetic `__index_set__` sink consults this fact (via SSA receiver
    /// value) so the suppression is flow-sensitive: if a phi join leaves
    /// the receiver only sometimes null-prototyped, the fact widens to
    /// `Unknown` and the sink fires on the unsafe path.
    NullPrototypeObject,
    /// A Sequelize ORM instance produced by `new Sequelize(...)`. The
    /// type-qualified resolver rewrites `sequelize.literal(x)` →
    /// `Sequelize.literal` against a flat SQL_QUERY rule, so user-supplied
    /// strings flowing into Sequelize raw-SQL helpers are caught.
    Sequelize,
    /// A TypeORM `Repository<T>` instance, produced by
    /// `getRepository(Entity)` / `manager.getRepository(Entity)`.
    /// `repo.query(sql)` and `repo.createQueryBuilder().query` etc. are
    /// SQL_QUERY sinks — type-qualified callees match flat
    /// `TypeOrmRepo.<method>` rules.
    TypeOrmRepo,
    /// A TypeORM `EntityManager` produced by `getManager()` /
    /// `connection.manager`. Same sink shape as `Repository<T>`.
    TypeOrmManager,
    /// A MikroORM `EntityManager` produced by `orm.em.fork()` /
    /// `createEntityManager()`. `em.execute(sql)` is the raw-SQL sink.
    MikroOrmEm,
    /// A Drizzle `sql` template-tag builder imported from `drizzle-orm`.
    /// `sqlBuilder.raw(x)` is a SQL_QUERY sink (raw escape hatch).  The
    /// imported `sql` symbol receives this type via the file-level
    /// import-aware tagging in [`infer_call_return_type_with_args`] so
    /// type-qualified `DrizzleSqlBuilder.raw` resolution fires.
    DrizzleSqlBuilder,
}

/// structural carrier for a recognised DTO type.  Maps
/// declared field names to their inferred [`TypeKind`].  Nested DTOs
/// use [`TypeKind::Dto`] recursively.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DtoFields {
    pub class_name: String,
    /// Sorted-by-key map for stable iteration / serialisation.
    pub fields: BTreeMap<String, TypeKind>,
}

impl DtoFields {
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            fields: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, field: impl Into<String>, kind: TypeKind) {
        self.fields.insert(field.into(), kind);
    }

    pub fn get(&self, field: &str) -> Option<&TypeKind> {
        self.fields.get(field)
    }
}

impl TypeKind {
    /// Returns the label prefix for constructing type-qualified callee names.
    /// E.g., `HttpClient` → `"HttpClient"` so `client.send()` resolves to `"HttpClient.send"`.
    pub fn label_prefix(&self) -> Option<&'static str> {
        match self {
            Self::HttpClient => Some("HttpClient"),
            Self::HttpResponse => Some("HttpResponse"),
            Self::DatabaseConnection => Some("DatabaseConnection"),
            Self::FileHandle => Some("FileHandle"),
            Self::Url => Some("URL"),
            Self::RequestBuilder => Some("RequestBuilder"),
            Self::JpaCriteriaQuery => Some("JpaCriteriaQuery"),
            Self::LdapClient => Some("LdapClient"),
            Self::XPathClient => Some("XPathClient"),
            Self::XmlParser => Some("XmlParser"),
            Self::Template => Some("Template"),
            Self::FileSystemPromisesNs => Some("FileSystemPromisesNs"),
            Self::Sequelize => Some("Sequelize"),
            Self::TypeOrmRepo => Some("TypeOrmRepo"),
            Self::TypeOrmManager => Some("TypeOrmManager"),
            Self::MikroOrmEm => Some("MikroOrmEm"),
            Self::DrizzleSqlBuilder => Some("DrizzleSqlBuilder"),
            _ => None,
        }
    }

    /// Container name used by typed call-graph devirtualisation ,
    /// the class / impl / module under which a receiver of this type
    /// would be looked up. Returns the DTO class name for `Dto`
    /// receivers, label prefixes for known abstract types, `None` for
    /// scalars.
    pub fn container_name(&self) -> Option<String> {
        if let Some(prefix) = self.label_prefix() {
            return Some(prefix.to_string());
        }
        if let Self::Dto(d) = self {
            return Some(d.class_name.clone());
        }
        None
    }

    /// convenience accessor for the inner `DtoFields` if this
    /// type is a recognised DTO.
    pub fn as_dto(&self) -> Option<&DtoFields> {
        match self {
            Self::Dto(d) => Some(d),
            _ => None,
        }
    }
}

/// A type fact about an SSA value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeFact {
    pub kind: TypeKind,
    pub nullable: bool,
}

impl TypeFact {
    fn unknown() -> Self {
        TypeFact {
            kind: TypeKind::Unknown,
            nullable: false,
        }
    }

    fn from_kind(kind: TypeKind) -> Self {
        let nullable = matches!(kind, TypeKind::Null);
        TypeFact { kind, nullable }
    }

    /// Meet two type facts (for phi nodes).
    fn meet(&self, other: &Self) -> Self {
        let nullable = self.nullable || other.nullable;
        let kind = if self.kind == other.kind {
            self.kind.clone()
        } else {
            TypeKind::Unknown
        };
        TypeFact { kind, nullable }
    }

    /// factory used by the field-access propagation rule.
    pub(crate) fn from_dto_field(receiver: &TypeKind, field: &str) -> Option<Self> {
        let dto = receiver.as_dto()?;
        let kind = dto.get(field)?.clone();
        Some(Self::from_kind(kind))
    }
}

/// Result of type fact analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeFactResult {
    pub facts: HashMap<SsaValue, TypeFact>,
}

impl TypeFactResult {
    /// Check if an SSA value is known to be an integer type.
    /// Useful for suppressing SQL injection findings on integer-typed values.
    pub fn is_int(&self, v: SsaValue) -> bool {
        self.facts
            .get(&v)
            .is_some_and(|f| matches!(f.kind, TypeKind::Int))
    }

    /// Get the inferred type kind for an SSA value.
    pub fn get_type(&self, v: SsaValue) -> Option<&TypeKind> {
        self.facts.get(&v).map(|f| &f.kind)
    }

    /// Check if an SSA value has a specific type kind.
    pub fn is_type(&self, v: SsaValue, kind: &TypeKind) -> bool {
        self.facts.get(&v).is_some_and(|f| f.kind == *kind)
    }
}

/// Check whether the given sink-operand SSA values are all type-safe for
/// the sink's capability set.  Returns `false` when `sink_caps` carries
/// no type-suppressible bits, when `values` is empty, or when any value
/// is not known to be a payload-incompatible scalar type.  Shared by
/// the SSA taint engine and the structural `cfg-unguarded-sink`
/// analysis so both agree on when a sink's arguments are provably
/// non-injectable.
///
/// Suppression policy:
/// * [`TypeKind::Int`] (and float, treated as numeric): suppresses
///   `SQL_QUERY`, `FILE_IO`, `SHELL_ESCAPE`, `HTML_ESCAPE`, `SSRF`,
///   `DATA_EXFIL`, numeric values cannot carry the metacharacters
///   required to drive any of these injection classes, nor can they
///   encode credentials/tokens that meaningfully constitute leakage.
/// * [`TypeKind::Bool`]: suppresses every type-suppressible bit ,
///   `true`/`false` cannot carry a payload of any kind.
pub fn is_type_safe_for_sink(
    values: &[SsaValue],
    sink_caps: crate::labels::Cap,
    type_facts: &TypeFactResult,
) -> bool {
    use crate::labels::Cap;
    let type_suppressible = Cap::SQL_QUERY
        | Cap::FILE_IO
        | Cap::SHELL_ESCAPE
        | Cap::HTML_ESCAPE
        | Cap::SSRF
        | Cap::DATA_EXFIL;
    if !sink_caps.intersects(type_suppressible) {
        return false;
    }
    if values.is_empty() {
        return false;
    }
    values.iter().all(|v| {
        let Some(kind) = type_facts.get_type(*v) else {
            return false;
        };
        matches!(kind, TypeKind::Int | TypeKind::Bool)
    })
}

/// Check whether any of the sink-arg SSA values is a structural query
/// object that emits parameterized SQL by construction (currently the
/// JPA / Hibernate Criteria API: `CriteriaQuery`, `CriteriaUpdate`,
/// `CriteriaDelete`, `Subquery`, `TypedQuery`).
///
/// Used by both the SSA taint engine and the structural
/// `cfg-unguarded-sink` analysis to suppress the SQL-injection finding
/// on `session.createQuery(cq)` / `em.createQuery(cq)` / `executeUpdate`
/// shapes where the argument is a Criteria object built via
/// `CriteriaBuilder` rather than a string.
///
/// Returns `false` when `sink_caps` does not include `SQL_QUERY`, when
/// `values` is empty, or when no value carries the
/// [`TypeKind::JpaCriteriaQuery`] tag.  Receiver values should be
/// excluded by the caller, the receiver of a JPA query method is the
/// `Session` / `EntityManager` channel, never the payload.
pub fn is_safe_query_object_arg(
    values: &[SsaValue],
    sink_caps: crate::labels::Cap,
    type_facts: &TypeFactResult,
) -> bool {
    use crate::labels::Cap;
    if !sink_caps.intersects(Cap::SQL_QUERY) {
        return false;
    }
    if values.is_empty() {
        return false;
    }
    values
        .iter()
        .any(|v| type_facts.is_type(*v, &TypeKind::JpaCriteriaQuery))
}

/// Receiver-text-aware return-type inference for methods whose
/// constructor mapping cannot be determined from the callee suffix
/// alone.
///
/// The JPA `createQuery` suffix is overloaded between
/// `CriteriaBuilder.createQuery(Class)` (returns `CriteriaQuery`, our
/// safe-by-construction structural query object) and
/// `Session.createQuery(String|Query)` (the executable-query
/// constructor whose string overload IS a SQL sink).  Class-literal
/// arg shape (e.g. `Foo.class`) doesn't surface in `arg_uses` at the
/// CFG layer, so we fall back to the receiver-text hint: if the
/// callee path includes a `CriteriaBuilder` cast or a receiver
/// variable named `cb` / `criteriaBuilder` / `builder`, treat the
/// call as the criteria-builder overload.
///
/// Conservative: returns `None` for any other shape so
/// [`constructor_type`] / `is_int_producing_callee` stay
/// authoritative, and consumers see Unknown instead of a wrong
/// type tag.
///
/// `_args` and `_consts` allow arg-shape narrowing when an arg's
/// constant value distinguishes overloads.  Reserved for future Java
/// `createQuery(Foo.class)` shape (the `Object.create(null)` case is
/// driven by the `produces_null_proto` CFG flag instead, since a
/// literal `null` arg leaves no SSA value to inspect).
fn arg_aware_call_type(
    lang: Lang,
    callee: &str,
    _args: &[SmallVec<[SsaValue; 2]>],
    _consts: &HashMap<SsaValue, ConstLattice>,
) -> Option<TypeKind> {
    if !matches!(lang, Lang::Java) {
        return None;
    }
    let after_colons = callee.rsplit("::").next().unwrap_or(callee);
    let suffix = after_colons.rsplit('.').next().unwrap_or(after_colons);
    if suffix != "createQuery" {
        return None;
    }
    // Strip the trailing `.createQuery` segment and inspect the
    // receiver text for the criteria-builder hints.  Conservative
    // text-level match, the SSA layer doesn't expose receiver-type
    // facts here yet.
    let prefix = callee.rsplit_once('.').map(|(p, _)| p).unwrap_or(callee);
    if prefix.contains("CriteriaBuilder") || receiver_is_criteria_builder(prefix) {
        Some(TypeKind::JpaCriteriaQuery)
    } else {
        None
    }
}

/// True when the receiver text identifies a CriteriaBuilder by
/// idiomatic naming (`cb`, `criteriaBuilder`, `builder`,
/// `getCriteriaBuilder()`), modulo casts and chained accesses.
fn receiver_is_criteria_builder(receiver_text: &str) -> bool {
    // Drop trailing parenthesized portions and chained cast/syntax noise.
    let cleaned = receiver_text
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .unwrap_or(receiver_text)
        .trim();
    let cleaned = cleaned.trim_start_matches('.');
    let last_segment = cleaned
        .rsplit(['.', ':', ' '])
        .next()
        .unwrap_or(cleaned)
        .trim_matches(|c: char| c == '(' || c == ')');
    matches!(
        last_segment,
        "cb" | "criteriaBuilder" | "criteria_builder" | "builder" | "getCriteriaBuilder"
    ) || receiver_text.contains("getCriteriaBuilder()")
        || receiver_text.contains(".cb.")
}

/// Infer a type from a constructor, factory, or allocator call.
///
/// Maps known constructor/factory/allocator patterns to security-relevant
/// types. Covers `new Foo()` constructors, factory methods like
/// `HttpClient.newHttpClient()`, and allocator functions like `curl_init()`.
/// Uses suffix matching consistent with the label classification system.
pub(crate) fn constructor_type(lang: Lang, callee: &str) -> Option<TypeKind> {
    // Normalize: last segment after "::" (Rust/Ruby) then "." (method calls).
    // Mirrors callee_leaf_name() in callgraph.rs.
    let after_colons = callee.rsplit("::").next().unwrap_or(callee);
    let suffix = after_colons.rsplit('.').next().unwrap_or(after_colons);
    match lang {
        Lang::Java => match suffix {
            "URL" | "URI" => Some(TypeKind::Url),
            "newHttpClient" | "newBuilder" if callee.contains("HttpClient") => {
                Some(TypeKind::HttpClient)
            }
            // Apache HttpClient idiomatic factory:
            // `CloseableHttpClient client = HttpClients.createDefault();`
            // `HttpClients` contains the substring `HttpClient` so this
            // doesn't widen to unrelated `createDefault` calls.
            "createDefault" | "custom" if callee.contains("HttpClient") => {
                Some(TypeKind::HttpClient)
            }
            "OkHttpClient" | "WebClient" | "RestTemplate" => Some(TypeKind::HttpClient),
            "getConnection" => Some(TypeKind::DatabaseConnection),
            "MongoClient" => Some(TypeKind::DatabaseConnection),
            // JDBC `conn.createStatement()` / `conn.prepareCall()` produce a
            // `Statement` / `CallableStatement` whose `.execute(sql)` is a
            // first-class SQL sink.  Mapped to `DatabaseConnection` so the
            // type-qualified label `DatabaseConnection.execute` (in
            // `labels/java.rs`) fires for `s.execute(query)` calls without
            // widening the bare `execute` matcher.  Surfaced by
            // GHSA-h8cj-hpmg-636v (Appsmith FilterDataServiceCE.dropTable).
            "createStatement" | "prepareCall" => Some(TypeKind::DatabaseConnection),
            "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "BufferedReader" | "BufferedWriter" => Some(TypeKind::FileHandle),
            "getWriter" | "getOutputStream" => Some(TypeKind::HttpResponse),
            // JPA / Hibernate Criteria API factory methods.  These are
            // unambiguous: `createCriteriaUpdate` / `createCriteriaDelete`
            // / `createTupleQuery` / `subquery` exist only on
            // `CriteriaBuilder` / `CriteriaQuery` and always return a
            // structural query object.  `createQuery` is overloaded
            // (`CriteriaBuilder.createQuery(Class)` returns
            // `CriteriaQuery`; `Session.createQuery(String)` returns
            // `Query`), so it's gated below in
            // [`infer_call_return_type_with_args`] on the arg-0 shape
            // (a class literal) so we don't conflate the executable-
            // query overload with the criteria builder.
            "createCriteriaUpdate" | "createCriteriaDelete" | "createTupleQuery" | "subquery" => {
                Some(TypeKind::JpaCriteriaQuery)
            }
            // LDAP directory-service clients.  `new InitialDirContext(env)` /
            // `new InitialLdapContext(env, ctls)` instantiate the JNDI LDAP
            // provider; `new LdapTemplate(...)` / `LdapTemplate.<init>` is the
            // Spring LDAP wrapper.  Both expose `search` / `searchByEntity`
            // /`searchForObject` overloads where filter/DN strings are LDAP
            // injection sinks.
            "InitialDirContext" | "InitialLdapContext" | "LdapTemplate" => {
                Some(TypeKind::LdapClient)
            }
            // JAXP factory-produced XML parser instances.  Each is
            // XXE-vulnerable by default until hardened with
            // `setFeature(FEATURE_SECURE_PROCESSING, true)` (or
            // disallow-doctype-decl, etc.). The
            // [`crate::ssa::xml_config::XmlParserConfigResult`] sidecar
            // suppresses the XXE bit at the type-qualified `XmlParser.parse`
            // sink when the receiver carries a hardening fact.
            "newDocumentBuilder" | "newSAXParser" | "getXMLReader" | "newXMLReader"
            | "createXMLReader" => Some(TypeKind::XmlParser),
            // `XPathFactory.newXPath()` returns a JAXP `XPath` instance.
            // Mapping it to `XPathClient` lets the type-qualified resolver
            // pick up `xpath.evaluate(...)` against the existing
            // `XPathClient.evaluate` rule and lets the
            // [`crate::ssa::xpath_config::XPathConfigResult`] sidecar
            // suppress XPATH_INJECTION when the receiver was bound to an
            // `XPathVariableResolver`.
            "newXPath" => Some(TypeKind::XPathClient),
            // Apache FreeMarker `new Template(name, reader, cfg)` /
            // `cfg.getTemplate(name)`.  The `Template` instance's
            // `.process(model, out)` is an SSTI sink when the
            // constructor source / template body came from tainted
            // input.  Type-qualified resolution rewrites
            // `tpl.process(...)` → `Template.process` against the
            // existing flat rule in `labels/java.rs`.
            "Template" | "getTemplate" => Some(TypeKind::Template),
            _ => None,
        },
        Lang::JavaScript | Lang::TypeScript => {
            // Phase 05 — `const fsp = require('fs').promises;` and the
            // bare `fs.promises` member-access form. Recognised here so
            // `fsp.readFile(p)` resolves through receiver-type
            // qualification to `FileSystemPromisesNs.readFile`. Match
            // the full callee text (not just the `promises` suffix) so
            // unrelated `.promises` accessors don't collide.
            if callee == "fs.promises"
                || callee == "require('fs').promises"
                || callee == "require(\"fs\").promises"
                || callee == "require('node:fs').promises"
                || callee == "require(\"node:fs\").promises"
            {
                return Some(TypeKind::FileSystemPromisesNs);
            }
            match suffix {
            "URL" => Some(TypeKind::Url),
            "Request" | "XMLHttpRequest" => Some(TypeKind::HttpClient),
            // Phase 07 — ORM constructors / factory functions. Coverage:
            // `new Sequelize(...)`           → Sequelize
            // `getRepository(Entity)`        → TypeOrmRepo  (typeorm)
            // `getManager()`                 → TypeOrmManager (typeorm)
            // `createEntityManager()`        → MikroOrmEm (@mikro-orm/core)
            // The leaf-suffix names are distinctive enough that user code
            // is unlikely to collide; if a fixture surfaces a misfire,
            // gate via `local_imports` (see deferred.md follow-up).
            "Sequelize" => Some(TypeKind::Sequelize),
            "getRepository" => Some(TypeKind::TypeOrmRepo),
            "getManager" => Some(TypeKind::TypeOrmManager),
            "createEntityManager" => Some(TypeKind::MikroOrmEm),
            // JS built-in collection constructors. `new Map()` / `new Set()`
            // / `new WeakMap()` / `new WeakSet()` / `new Array()` produce
            // in-memory collections; downstream `m.get(k)` / `m.set(k, v)`
            // / `s.add(x)` / `s.has(x)` / `arr.find(p)` are container ops,
            // not data-layer reads. Without this mapping the bare verb
            // dispatch in `auth_analysis::config::classify_sink_class`
            // matches the `get` / `find` / `add` read/mutation indicators
            // and over-fires `js.auth.missing_ownership_check` on every
            // Map lookup in pure data-manipulation code (excalidraw's
            // `elementsMap.get(id)`, `origIdToDuplicateId.get(...)`,
            // `groupIdMapForOperation.set(...)` shapes).
            "Map" | "Set" | "WeakMap" | "WeakSet" | "Array" => Some(TypeKind::LocalCollection),
            // ldapjs client factory: `ldap.createClient({ url: '…' })` returns
            // a Client whose `search(base, opts, cb)` is an LDAP injection
            // sink.  Match the qualified callee text rather than the bare
            // `createClient` suffix to avoid widening to unrelated factories
            // with the same verb name.
            "createClient" if callee.contains("ldap") => Some(TypeKind::LdapClient),
            _ => None,
            }
        }
        Lang::Python => {
            // Python uses qualified names: requests.get, sqlite3.connect, etc.
            if callee.starts_with("requests.")
                || callee == "urlopen"
                || callee == "aiohttp.ClientSession"
                || callee.starts_with("httpx.")
                || callee == "urllib3.PoolManager"
            {
                Some(TypeKind::HttpClient)
            } else if suffix == "connect"
                && (callee.contains("sqlite3")
                    || callee.contains("psycopg2")
                    || callee.contains("mysql"))
            {
                Some(TypeKind::DatabaseConnection)
            } else if suffix == "open" && !callee.contains('.') {
                // Bare `open()` is file I/O in Python
                Some(TypeKind::FileHandle)
            } else if callee == "ldap.initialize"
                || callee == "ldap3.Connection"
                || callee.ends_with(".initialize") && callee.contains("ldap")
            {
                // python-ldap: `conn = ldap.initialize(url)` returns an
                // LDAPObject whose `search_s` / `search_ext_s` methods are
                // LDAP-injection sinks.  ldap3: `Connection(server, ...)`
                // returns a Connection with a `search()` method.
                Some(TypeKind::LdapClient)
            } else {
                None
            }
        }
        Lang::Go => {
            if callee.contains("http.") && matches!(suffix, "NewRequest" | "Get" | "Post") {
                Some(TypeKind::HttpClient)
            } else if callee.contains("sql.") && suffix == "Open" {
                Some(TypeKind::DatabaseConnection)
            } else if callee.contains("os.") && matches!(suffix, "Open" | "Create" | "OpenFile") {
                Some(TypeKind::FileHandle)
            } else if callee.contains("url.") && suffix == "Parse" {
                Some(TypeKind::Url)
            } else if callee.contains("ldap.") && matches!(suffix, "Dial" | "DialURL" | "DialTLS") {
                // go-ldap (`github.com/go-ldap/ldap/v3`): `conn, _ := ldap.DialURL(url)`
                // returns `*ldap.Conn` whose `Search(req)` is an LDAP-injection sink.
                Some(TypeKind::LdapClient)
            } else {
                None
            }
        }
        Lang::Php => match suffix {
            "PDO" | "mysqli" => Some(TypeKind::DatabaseConnection),
            "curl_init" => Some(TypeKind::HttpClient),
            "fopen" => Some(TypeKind::FileHandle),
            "SplFileObject" => Some(TypeKind::FileHandle),
            // DOMXPath: `$xp = new DOMXPath($doc)`.  `$xp->query($expr)` /
            // `$xp->evaluate($expr)` are XPath-injection sinks; without a
            // distinct TypeKind they collide with the bare `query` SQL sink.
            "DOMXPath" => Some(TypeKind::XPathClient),
            _ => None,
        },
        Lang::C => match suffix {
            "fopen" => Some(TypeKind::FileHandle),
            "curl_easy_init" => Some(TypeKind::HttpClient),
            "mysql_real_connect" | "PQconnectdb" => Some(TypeKind::DatabaseConnection),
            _ => None,
        },
        Lang::Cpp => match suffix {
            "fopen" | "ifstream" | "ofstream" | "fstream" => Some(TypeKind::FileHandle),
            "curl_easy_init" => Some(TypeKind::HttpClient),
            "mysql_real_connect" | "PQconnectdb" => Some(TypeKind::DatabaseConnection),
            _ => None,
        },
        Lang::Rust => {
            // Rust callees are full scoped_identifiers: "reqwest::Client::new".
            // Because the CFG records an entire chained call (e.g.
            // `Connection::open("app.db").unwrap()`) as one Call node, the raw
            // callee ends with `.unwrap`/`.expect`/etc.  Peel trailing identity
            // methods (including their paren groups) so exact suffix matching
            // sees the underlying constructor segment.
            let base = peel_identity_suffix(callee);
            let base = base.as_str();
            if base.ends_with("reqwest::Client::new") || base.ends_with("reqwest::get") {
                Some(TypeKind::HttpClient)
            } else if base.contains("HttpResponse::") || base.ends_with("Response::builder") {
                Some(TypeKind::HttpResponse)
            } else if base.ends_with("File::open") || base.ends_with("File::create") {
                Some(TypeKind::FileHandle)
            } else if base.ends_with("Url::parse") {
                Some(TypeKind::Url)
            } else if base.ends_with("rusqlite::Connection::open")
                || base.ends_with("Connection::open")
                || base.ends_with("postgres::Client::connect")
                || base.ends_with("sqlx::PgPool::connect")
                || base.ends_with("sqlx::SqlitePool::connect")
                || base.ends_with("sqlx::MySqlPool::connect")
            {
                Some(TypeKind::DatabaseConnection)
            } else if base.ends_with("diesel::PgConnection::establish")
                || base.ends_with("diesel::SqliteConnection::establish")
                || base.ends_with("PgConnection::establish")
                || base.ends_with("SqliteConnection::establish")
            {
                Some(TypeKind::DatabaseConnection)
            } else if is_rust_local_collection_constructor(base) {
                // Rust std/indexmap/smallvec/dashmap collection
                // constructors map to a generic "local collection" type
                // so the auth sink gate recognises
                // `let x = factory_fn(); x.insert(..)`.
                Some(TypeKind::LocalCollection)
            } else if is_rust_request_builder_constructor(base) {
                // HTTP request-builder constructors across reqwest, surf,
                // ureq, hyper.  See [`is_rust_request_builder_constructor`].
                Some(TypeKind::RequestBuilder)
            } else {
                None
            }
        }
        Lang::Ruby => {
            // Ruby uses CallMethod for ALL calls → callee is "receiver.method".
            // Suffix alone is too generic (new, get, open); match on full callee.
            if callee.contains("Net::HTTP") || after_colons.starts_with("HTTParty") {
                Some(TypeKind::HttpClient)
            } else if after_colons.starts_with("URI") && matches!(suffix, "parse" | "URI") {
                Some(TypeKind::Url)
            } else if after_colons == "PG.connect"
                || (after_colons.starts_with("Sequel") && suffix == "connect")
                || callee.contains("Mysql2")
            {
                Some(TypeKind::DatabaseConnection)
            } else if after_colons.starts_with("File.") && matches!(suffix, "open" | "new") {
                Some(TypeKind::FileHandle)
            } else if callee.contains("Net::LDAP") && matches!(suffix, "new" | "open") {
                // net-ldap gem: `Net::LDAP.new(host: ...)` / `Net::LDAP.open`
                // returns a connection whose `search(base:, filter:)` accepts
                // an attacker-influenceable filter expression.
                Some(TypeKind::LdapClient)
            } else {
                None
            }
        }
    }
}

/// Check if a callee is a known integer/numeric-producing function.
///
/// Conservative list: only includes functions whose return type is unambiguously
/// numeric across supported languages. Excludes overloaded or collection-returning
/// functions (valueOf, count, length, size, abs).
/// Check if a callee is an identity-preserving method that returns the
/// receiver's (inner) type unchanged for taint-analysis purposes.
///
/// Covers Rust's `Result::unwrap`/`expect`/`ok`, `Option::unwrap`/`expect`,
/// `.clone()`, `.await`, `.as_ref()`, plus generic no-op conversions
/// (`into`, `to_owned`) used across languages.  Used by type-fact analysis
/// so that `Connection::open(p).unwrap()` keeps the `DatabaseConnection`
/// type fact through the unwrap call.
/// Strip trailing identity-preserving method calls so constructor/factory
/// matchers can anchor on the base segment.  Normalizes the callee first
/// (stripping `(...)` groups between `.` segments), then repeatedly removes
/// trailing identity-method segments (`unwrap`, `expect`, `clone`, etc.).
/// For `Connection::open("app.db").unwrap` the pipeline is:
/// normalize → `Connection::open.unwrap` → peel → `Connection::open`.
pub fn peel_identity_suffix(callee: &str) -> String {
    let mut cur = crate::labels::normalize_chained_call_for_classify(callee);
    // Also strip any trailing paren group (e.g. `Connection::open("app.db")`
    // with no subsequent segment) so the base text ends at the constructor.
    if let Some(p) = cur.find('(') {
        cur.truncate(p);
    }
    while let Some(dot_idx) = cur.rfind('.') {
        let tail = &cur[dot_idx + 1..];
        if !is_identity_method(tail) {
            break;
        }
        cur.truncate(dot_idx);
    }
    cur
}

/// Does the peeled callee match a known Rust constructor for a
/// local/in-memory collection type?  Covers std collections plus common
/// third-party crates (indexmap, smallvec, dashmap).  Matches tail
/// segments only so `crate::Foo::HashMap::new` also resolves.
fn is_rust_local_collection_constructor(base: &str) -> bool {
    const TYPES: &[&str] = &[
        "HashMap",
        "HashSet",
        "BTreeMap",
        "BTreeSet",
        "VecDeque",
        "BinaryHeap",
        "LinkedList",
        "Vec",
        "IndexMap",
        "IndexSet",
        "SmallVec",
        "FxHashMap",
        "FxHashSet",
        "DashMap",
        "DashSet",
        // `roaring` crate, RoaringBitmap / RoaringTreemap are
        // in-memory bitset / bitmap containers (set-of-u32 /
        // set-of-u64).  Used heavily by indexing systems
        // (meilisearch's index-scheduler) for `task_ids`,
        // `docids`, and similar local-collection bookkeeping.
        // Mutations (`insert` / `remove` / `clear`) are container
        // ops, not data-layer writes.
        "RoaringBitmap",
        "RoaringTreemap",
    ];
    const VERBS: &[&str] = &[
        "new",
        "with_capacity",
        "with_capacity_and_hasher",
        "with_hasher",
        "from",
        "from_iter",
        "new_in",
        "default",
    ];
    TYPES.iter().any(|ty| {
        VERBS
            .iter()
            .any(|verb| base.ends_with(&format!("{ty}::{verb}")))
    })
}

/// Does the peeled Rust callee correspond to a known HTTP request-builder
/// constructor / factory?  Covers:
/// * surf free verbs (`surf::post`, `surf::get`, ...) ,
/// * ureq free verbs (`ureq::post`, ...) ,
/// * hyper `Request::builder` ,
/// * reqwest `Client::post(url)` / `Client::get(url)` etc. (the `Client`
///   instance is itself an `HttpClient` but the verb call on it returns a
///   `RequestBuilder` whose chained methods bind body/json/form/etc.).
///
/// reqwest's `Client::new` keeps its existing `HttpClient` mapping ,
/// it produces the client, not a builder.
fn is_rust_request_builder_constructor(base: &str) -> bool {
    // surf free verbs that return Request (acts as a builder).
    const SURF_VERBS: &[&str] = &[
        "post", "get", "put", "delete", "patch", "head", "connect", "trace",
    ];
    if SURF_VERBS
        .iter()
        .any(|v| base.ends_with(&format!("surf::{v}")))
    {
        return true;
    }
    // ureq free verbs that return Request.
    const UREQ_VERBS: &[&str] = &["post", "get", "put", "delete", "patch", "head"];
    if UREQ_VERBS
        .iter()
        .any(|v| base.ends_with(&format!("ureq::{v}")))
    {
        return true;
    }
    // hyper request builder.
    if base.ends_with("Request::builder") || base.ends_with("hyper::Request::builder") {
        return true;
    }
    // reqwest Client verb-on-instance.  `Client::post(url)` /
    // `Client::get(url)` chained-form returns a RequestBuilder.  We match
    // the constructor-style segment used by chain text after CFG receiver
    // collapse (`reqwest::Client::new.post`, `Client::post`, etc.).
    const REQWEST_CLIENT_VERBS: &[&str] =
        &["post", "get", "put", "delete", "patch", "head", "request"];
    if REQWEST_CLIENT_VERBS.iter().any(|v| {
        base.ends_with(&format!("Client::new.{v}")) || base.ends_with(&format!("Client::{v}"))
    }) {
        return true;
    }
    false
}

pub fn is_identity_method(callee: &str) -> bool {
    let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);
    matches!(
        suffix,
        "unwrap" | "expect" | "clone" | "to_owned" | "into" | "as_ref" | "as_mut" | "ok" | "await"
    )
}

pub fn is_int_producing_callee(callee: &str) -> bool {
    // Peel trailing identity methods (e.g. `.unwrap()`/`.expect("...")` after
    // `.parse()`) so the underlying numeric-producing verb is exposed.
    let base = peel_identity_suffix(callee);
    let suffix = base.rsplit(['.', ':']).next().unwrap_or(&base);
    matches!(
        suffix,
        "parseInt" | "parseFloat" | "Number"        // JS/TS
        | "int" | "float" | "ord"                    // Python
        | "parseLong" | "parseDouble" | "parseShort" // Java
        | "Atoi" | "ParseInt" | "ParseFloat"         // Go
        | "intval" | "floatval"                       // PHP
        | "to_i" | "to_f"                             // Ruby
        | "parse" // Rust: `.parse::<N>()` / `.parse().unwrap()`, conservative
                  // (most Rust .parse() calls target numeric types)
    )
}

/// Polarity hint for a generic input-validator callee.
///
/// Most validation idioms route attacker-controlled input through a
/// helper whose result the caller branches on:
///
/// ```text
/// const err = validateUrlSsrf(child.webhookUrl);  // ErrorReturning
/// if (err) throw new Error(err);                  // false branch → success
///
/// if (isValid(input)) { use(input); }             // BooleanTrueIsValid
///                                                 // true branch → success
/// ```
///
/// Without modeling this pattern, a one-statement rewrite of a
/// `validate(x); if(x) ...` guard hides the semantic equivalence to
/// `if (validate(x)) ...` (already classified as ValidationCall).  The
/// classifier discriminates only on the textual head of the bare call
///, strict-additive: callees that don't match any pattern return
/// `None` and the engine falls through to its existing behaviour.
///
/// Motivated by Novu CVE GHSA-4x48-cgf9-q33f
/// (`const ssrfError = await validateUrlSsrf(child.webhookUrl); if (ssrfError) throw`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputValidatorPolarity {
    /// Returns boolean, truthy means "valid".
    BooleanTrueIsValid,
    /// Returns null/undefined on success, error/message on failure ,
    /// truthy means "rejected".
    ErrorReturning,
}

pub fn classify_input_validator_callee(callee: &str) -> Option<InputValidatorPolarity> {
    let base = peel_identity_suffix(callee);
    let suffix = base.rsplit(['.', ':']).next().unwrap_or(&base);
    let lower = suffix.to_ascii_lowercase();

    // Boolean returners, name typically reads as a predicate
    // (`isValid…`, `is_valid_…`, `is_safe…`, `has_valid…`).  Truthy
    // result → input is valid → TRUE branch carries the validation.
    if lower.starts_with("isvalid")
        || lower.starts_with("is_valid")
        || lower.starts_with("issafe")
        || lower.starts_with("is_safe")
        || lower.starts_with("hasvalid")
        || lower.starts_with("has_valid")
    {
        return Some(InputValidatorPolarity::BooleanTrueIsValid);
    }

    // Error-returning validators, name reads as a verb whose return
    // value carries the error description.  `validateXxx`, `verifyXxx`
    // are the dominant idioms; we deliberately do NOT match `check…`
    // here because a name like `checkPermissions` overlaps with auth
    // checks (different semantic) and the suppression payoff isn't
    // worth the precision risk.
    if lower.starts_with("validate") || lower.starts_with("verify") {
        return Some(InputValidatorPolarity::ErrorReturning);
    }

    None
}

/// Analyze types for all SSA values.
///
/// Uses constant propagation results to seed types from known constants,
/// then propagates through copies and phi nodes. Constructor/factory calls
/// are mapped to security-relevant types when `lang` is provided.
pub fn analyze_types(
    body: &SsaBody,
    cfg: &Cfg,
    consts: &HashMap<SsaValue, ConstLattice>,
    lang: Option<Lang>,
) -> TypeFactResult {
    analyze_types_with_param_types(body, cfg, consts, lang, &[])
}

/// Same as [`analyze_types`] but seeds [`SsaOp::Param`] values with
/// per-position [`TypeKind`] facts from `param_types` (parallel-vec to
/// the function's BodyMeta.params).  An entry of `None` (or an out-of-
/// range index) leaves the value at the default Param fact (Unknown).
pub fn analyze_types_with_param_types(
    body: &SsaBody,
    cfg: &Cfg,
    consts: &HashMap<SsaValue, ConstLattice>,
    lang: Option<Lang>,
    param_types: &[Option<TypeKind>],
) -> TypeFactResult {
    let mut facts: HashMap<SsaValue, TypeFact> = HashMap::new();

    // First pass: direct type inference from instruction kind and constant values
    for block in &body.blocks {
        for inst in block.phis.iter().chain(block.body.iter()) {
            // A CFG-level read of a numeric-length property (`arr.length`,
            // `map.size`, `buf.byteLength`, `list.count`, `vec.len()`) yields
            // an integer regardless of SSA op shape: a pure property access
            // lowers to `Assign`, a zero-arg method call lowers to `Call`.
            // Inspect the attached CFG node first so both shapes pick up the
            // `TypeKind::Int` fact without duplicating logic per branch.
            if cfg
                .node_weight(inst.cfg_node)
                .is_some_and(|ni| ni.is_numeric_length_access)
            {
                facts.insert(inst.value, TypeFact::from_kind(TypeKind::Int));
                continue;
            }
            let fact = match &inst.op {
                SsaOp::Const(_) => {
                    // Use constant propagation result if available
                    match consts.get(&inst.value) {
                        Some(ConstLattice::Str(_)) => TypeFact::from_kind(TypeKind::String),
                        Some(ConstLattice::Int(_)) => TypeFact::from_kind(TypeKind::Int),
                        Some(ConstLattice::Bool(_)) => TypeFact::from_kind(TypeKind::Bool),
                        Some(ConstLattice::Null) => TypeFact::from_kind(TypeKind::Null),
                        _ => TypeFact::unknown(),
                    }
                }
                SsaOp::Source => TypeFact::from_kind(TypeKind::String),
                SsaOp::Param { index } => {
                    // Seed from the function's BodyMeta.param_types when
                    // a TypeKind was recovered at CFG construction time.
                    // Out-of-range / None entries fall back to Unknown.
                    match param_types.get(*index).and_then(|t| t.clone()) {
                        Some(tk) => TypeFact::from_kind(tk),
                        None => TypeFact::unknown(),
                    }
                }
                SsaOp::SelfParam => TypeFact::from_kind(TypeKind::Object),
                SsaOp::CatchParam => TypeFact::from_kind(TypeKind::Object),
                SsaOp::Call { callee, args, .. } => {
                    // CFG marks `Object.create(null)` (and future
                    // null-prototype constructors) at lowering time.
                    // Honour it ahead of generic constructor / arg-aware
                    // dispatch so the returned SsaValue carries
                    // `NullPrototypeObject` for prototype-pollution
                    // suppression.
                    let null_proto = cfg
                        .node_weight(inst.cfg_node)
                        .map(|ni| ni.call.produces_null_proto)
                        .unwrap_or(false);
                    if null_proto {
                        TypeFact::from_kind(TypeKind::NullPrototypeObject)
                    } else if let Some(ty) = lang.and_then(|l| constructor_type(l, callee)) {
                        TypeFact::from_kind(ty)
                    } else if let Some(ty) =
                        lang.and_then(|l| arg_aware_call_type(l, callee, args, consts))
                    {
                        TypeFact::from_kind(ty)
                    } else if is_int_producing_callee(callee) {
                        TypeFact::from_kind(TypeKind::Int)
                    } else {
                        // Identity-preserving methods propagated in second pass.
                        TypeFact::unknown()
                    }
                }
                SsaOp::Nop => TypeFact::unknown(),
                SsaOp::Assign(uses) if uses.len() == 1 => {
                    // Defer: will be filled in second pass
                    TypeFact::unknown()
                }
                SsaOp::Assign(_uses) => {
                    // Binary operations: check if the CFG node has a numeric BinOp.
                    // All bitwise, arithmetic (except Add which may be string concat),
                    // and comparison operators always produce integers.
                    let bin_op = cfg.node_weight(inst.cfg_node).and_then(|ni| ni.bin_op);
                    match bin_op {
                        Some(
                            BinOp::Sub
                            | BinOp::Mul
                            | BinOp::Div
                            | BinOp::Mod
                            | BinOp::BitAnd
                            | BinOp::BitOr
                            | BinOp::BitXor
                            | BinOp::LeftShift
                            | BinOp::RightShift
                            | BinOp::Eq
                            | BinOp::NotEq
                            | BinOp::Lt
                            | BinOp::LtEq
                            | BinOp::Gt
                            | BinOp::GtEq,
                        ) => TypeFact::from_kind(TypeKind::Int),
                        // Add could be string concatenation, defer to operand types
                        _ => TypeFact::unknown(),
                    }
                }
                SsaOp::Phi(_) => {
                    // Defer: will be filled in second pass
                    TypeFact::unknown()
                }
                // FieldProj: when the projection carries an inferred type
                // (set during lowering or by future field-type analysis),
                // honour it; otherwise the field type is unknown until a
                // points-to / heap query resolves it.
                SsaOp::FieldProj { projected_type, .. } => match projected_type {
                    Some(tk) => TypeFact::from_kind(tk.clone()),
                    None => TypeFact::unknown(),
                },
                // Undef contributes no type information, phi joins
                // pick up the type from the other (defined) operand.
                SsaOp::Undef => TypeFact::unknown(),
            };
            facts.insert(inst.value, fact);
        }
    }

    // Second pass: propagate through copies, phi nodes, and identity-preserving
    // method calls (unwrap/expect/clone, etc.).
    // Simple fixed-point: iterate until no changes (typically 1-2 rounds)
    for _ in 0..10 {
        let mut changed = false;

        for block in &body.blocks {
            // Identity-preserving method calls: pass through receiver's type.
            // E.g. `Connection::open(p).unwrap()`, the `.unwrap()` call's type
            // fact should mirror the receiver (Result<Connection>).  Only applies
            // when the current fact is still Unknown so explicit constructor
            // mappings win.
            for inst in &block.body {
                if let SsaOp::Call {
                    callee,
                    receiver: Some(recv),
                    ..
                } = &inst.op
                {
                    if !is_identity_method(callee) {
                        continue;
                    }
                    // A numeric-length accessor pinned by the first pass is
                    // load-bearing for sink suppression, do not let identity-
                    // method receiver propagation overwrite the Int fact.
                    if cfg
                        .node_weight(inst.cfg_node)
                        .is_some_and(|ni| ni.is_numeric_length_access)
                    {
                        continue;
                    }
                    let current_kind = facts
                        .get(&inst.value)
                        .map(|f| f.kind.clone())
                        .unwrap_or(TypeKind::Unknown);
                    if !matches!(current_kind, TypeKind::Unknown) {
                        continue;
                    }
                    let recv_fact = facts.get(recv).cloned().unwrap_or_else(TypeFact::unknown);
                    if matches!(recv_fact.kind, TypeKind::Unknown) {
                        continue;
                    }
                    if facts.get(&inst.value) != Some(&recv_fact) {
                        facts.insert(inst.value, recv_fact);
                        changed = true;
                    }
                }
            }

            // FieldProj receiver-driven type narrowing.  When
            // SSA lowering decomposed `a.b.c()` into a FieldProj chain,
            // intermediate FieldProj insts default to `projected_type =
            // None`.  If the receiver value carries a Dto fact and the
            // projected field name is in its `fields` map, route the
            // FieldProj's type fact to the field's declared TypeKind.
            for inst in &block.body {
                let SsaOp::FieldProj {
                    receiver,
                    field,
                    projected_type,
                } = &inst.op
                else {
                    continue;
                };
                // If the lowering already pinned a type, keep it.
                if projected_type.is_some() {
                    continue;
                }
                let Some(recv_fact) = facts.get(receiver).cloned() else {
                    continue;
                };
                let field_name = body.field_name(*field).to_string();
                let Some(new_fact) = TypeFact::from_dto_field(&recv_fact.kind, &field_name) else {
                    continue;
                };
                if facts.get(&inst.value) != Some(&new_fact) {
                    facts.insert(inst.value, new_fact);
                    changed = true;
                }
            }

            // Phi nodes
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut result: Option<TypeFact> = None;
                    for (_, val) in operands {
                        let operand_fact =
                            facts.get(val).cloned().unwrap_or_else(TypeFact::unknown);
                        result = Some(match result {
                            None => operand_fact,
                            Some(acc) => acc.meet(&operand_fact),
                        });
                    }
                    if let Some(new_fact) = result {
                        let old = facts.get(&inst.value);
                        if old != Some(&new_fact) {
                            facts.insert(inst.value, new_fact);
                            changed = true;
                        }
                    }
                }
            }

            // Copy assignments and binary arithmetic
            for inst in &block.body {
                // Preserve the Int fact pinned by the numeric-length-access
                // detector in the first pass, copy propagation would replace
                // it with the receiver's (usually Unknown) type and defeat the
                // whole point of the accessor rule.
                if cfg
                    .node_weight(inst.cfg_node)
                    .is_some_and(|ni| ni.is_numeric_length_access)
                {
                    continue;
                }
                if let SsaOp::Assign(uses) = &inst.op {
                    if uses.len() == 1 {
                        // when the RHS is a single member-access
                        // expression and the receiver value carries a
                        // `TypeKind::Dto(fields)` fact, route the assignment's
                        // type to the field's declared `TypeKind`.  Strictly
                        // additive, falls through to copy-prop when the
                        // receiver isn't a DTO or the field isn't recorded.
                        let dto_field_fact = cfg
                            .node_weight(inst.cfg_node)
                            .and_then(|ni| ni.member_field.as_deref())
                            .and_then(|field| {
                                let recv_kind = facts.get(&uses[0])?.kind.clone();
                                TypeFact::from_dto_field(&recv_kind, field)
                            });
                        let new_fact = match dto_field_fact {
                            Some(f) => f,
                            None => facts
                                .get(&uses[0])
                                .cloned()
                                .unwrap_or_else(TypeFact::unknown),
                        };
                        let old = facts.get(&inst.value);
                        if old != Some(&new_fact) {
                            facts.insert(inst.value, new_fact);
                            changed = true;
                        }
                    } else if uses.len() == 2 {
                        // Binary assignments: if both operands are Int, result is Int.
                        // This ensures `parseInt(x) * 10` is typed as Int (Int * Int = Int).
                        let lhs = facts
                            .get(&uses[0])
                            .cloned()
                            .unwrap_or_else(TypeFact::unknown);
                        let rhs = facts
                            .get(&uses[1])
                            .cloned()
                            .unwrap_or_else(TypeFact::unknown);
                        if matches!(lhs.kind, TypeKind::Int) && matches!(rhs.kind, TypeKind::Int) {
                            let new_fact = TypeFact::from_kind(TypeKind::Int);
                            if facts.get(&inst.value) != Some(&new_fact) {
                                facts.insert(inst.value, new_fact);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    TypeFactResult { facts }
}

// ── Java Type Hierarchy (bounded, sink-relevant) ─────────────────────────

/// Minimal Java type hierarchy for subtype queries.
///
/// Scope: **sink-relevant framework types only** (Servlet API, JDBC, HTTP
/// clients, I/O streams). NOT a general Java class hierarchy.
/// Used for `instanceof` resolution and type-qualified method dispatch.
pub struct TypeHierarchy;

/// (subtype, &[supertypes]), sink-relevant framework types only.
static JAVA_HIERARCHY: &[(&str, &[&str])] = &[
    ("HttpServletResponse", &["ServletResponse"]),
    ("HttpServletRequest", &["ServletRequest"]),
    ("HttpURLConnection", &["URLConnection"]),
    ("CloseableHttpClient", &["HttpClient"]),
    ("FileInputStream", &["InputStream"]),
    ("FileOutputStream", &["OutputStream"]),
    ("BufferedReader", &["Reader"]),
    ("BufferedWriter", &["Writer"]),
    ("PreparedStatement", &["Statement"]),
    ("ArrayList", &["List", "Collection"]),
    ("HashMap", &["Map"]),
    ("StringBuilder", &["CharSequence"]),
    ("StringBuffer", &["CharSequence"]),
    // Framework types.
    ("OkHttpClient", &["HttpClient"]),
    ("WebClient", &["HttpClient"]),
    ("RestTemplate", &["HttpClient"]),
    ("MongoClient", &["DatabaseConnection"]),
    ("RedisTemplate", &["DatabaseConnection"]),
    ("JmsTemplate", &["DatabaseConnection"]),
    // Spring, Servlet, and I/O framework types.
    ("ResponseEntity", &["HttpResponse"]),
    (
        "HttpServletRequestWrapper",
        &["HttpServletRequest", "ServletRequest"],
    ),
    ("PrintWriter", &["Writer"]),
    ("FileReader", &["Reader"]),
    ("FileWriter", &["Writer"]),
    ("InputStreamReader", &["Reader"]),
    ("OutputStreamWriter", &["Writer"]),
];

impl TypeHierarchy {
    /// Check if `sub` is a subtype of `super_type` in the bounded Java
    /// framework hierarchy. Returns `true` for identity (`sub == super_type`).
    pub fn is_subtype_of(sub: &str, super_type: &str) -> bool {
        if sub == super_type {
            return true;
        }
        JAVA_HIERARCHY
            .iter()
            .any(|(s, supers)| *s == sub && supers.contains(&super_type))
    }

    /// Resolve a class name through the hierarchy to a [`TypeKind`].
    ///
    /// Tries the class name directly first (via `class_name_to_type_kind`
    /// in the constraint solver), then checks if any registered supertype
    /// maps to a `TypeKind`.
    pub fn resolve_kind(class_name: &str) -> Option<TypeKind> {
        // Direct resolution via the class-name table in solver.rs
        crate::constraint::solver::class_name_to_type_kind(class_name).or_else(|| {
            // Hierarchy fallback: check supertypes
            for (sub, supers) in JAVA_HIERARCHY.iter() {
                if *sub == class_name {
                    for s in *supers {
                        if let Some(k) = crate::constraint::solver::class_name_to_type_kind(s) {
                            return Some(k);
                        }
                    }
                }
            }
            None
        })
    }
}

// ── Go Interface Satisfaction (bounded, conservative) ────────────────────

/// Go interface satisfaction table for **sink-relevant interfaces only**.
///
/// Conservative: unknown interfaces → `true` (could satisfy).
/// Only [`definitely_not`](GoInterfaceTable::definitely_not) is used for
/// suppression, it returns `true` only when the type provably cannot
/// implement the interface.
pub struct GoInterfaceTable;

impl GoInterfaceTable {
    /// Check if a [`TypeKind`] is known to satisfy a Go interface.
    pub fn satisfies(kind: &TypeKind, interface: &str) -> bool {
        match interface {
            "http.ResponseWriter" | "ResponseWriter" => {
                matches!(kind, TypeKind::HttpResponse)
            }
            "io.Writer" | "Writer" => {
                matches!(kind, TypeKind::HttpResponse | TypeKind::FileHandle)
            }
            "io.Reader" | "Reader" => matches!(kind, TypeKind::FileHandle),
            "io.ReadCloser" | "ReadCloser" => {
                matches!(kind, TypeKind::FileHandle | TypeKind::HttpResponse)
            }
            // Database and extended I/O interfaces.
            "sql.DB" | "sql.Conn" | "sql.Tx" | "DB" => {
                matches!(kind, TypeKind::DatabaseConnection)
            }
            "io.WriteCloser" | "WriteCloser" => {
                matches!(kind, TypeKind::HttpResponse | TypeKind::FileHandle)
            }
            "io.ReadWriteCloser" | "ReadWriteCloser" => {
                matches!(kind, TypeKind::HttpResponse | TypeKind::FileHandle)
            }
            _ => true, // Unknown interface → conservative (could satisfy)
        }
    }

    /// Check if a [`TypeKind`] is known to NOT satisfy a specific interface.
    ///
    /// Returns `true` only when we are confident the type cannot implement
    /// the interface. Used for sink suppression.
    pub fn definitely_not(kind: &TypeKind, interface: &str) -> bool {
        match interface {
            "http.ResponseWriter" | "ResponseWriter" => matches!(
                kind,
                TypeKind::Int
                    | TypeKind::Bool
                    | TypeKind::String
                    | TypeKind::FileHandle
                    | TypeKind::DatabaseConnection
                    | TypeKind::Url
                    | TypeKind::HttpClient
            ),
            "io.ReadCloser" | "ReadCloser" => matches!(
                kind,
                TypeKind::Int
                    | TypeKind::Bool
                    | TypeKind::String
                    | TypeKind::DatabaseConnection
                    | TypeKind::Url
                    | TypeKind::HttpClient
            ),
            // Database and extended I/O interfaces.
            "sql.DB" | "sql.Conn" | "sql.Tx" | "DB" => matches!(
                kind,
                TypeKind::Int
                    | TypeKind::Bool
                    | TypeKind::String
                    | TypeKind::HttpResponse
                    | TypeKind::FileHandle
                    | TypeKind::HttpClient
                    | TypeKind::Url
            ),
            "io.WriteCloser" | "WriteCloser" | "io.ReadWriteCloser" | "ReadWriteCloser" => {
                matches!(
                    kind,
                    TypeKind::Int
                        | TypeKind::Bool
                        | TypeKind::String
                        | TypeKind::DatabaseConnection
                        | TypeKind::Url
                )
            }
            _ => false, // Unknown interface → conservative
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::Graph;
    use petgraph::graph::NodeIndex;
    use smallvec::SmallVec;

    #[test]
    fn const_types_inferred() {
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let n2 = NodeIndex::new(2);

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Const(Some("42".into())),
                        cfg_node: n0,
                        var_name: Some("x".into()),
                        span: (0, 2),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Const(Some("\"hello\"".into())),
                        cfg_node: n1,
                        var_name: Some("y".into()),
                        span: (3, 10),
                    },
                    SsaInst {
                        value: SsaValue(2),
                        op: SsaOp::Source,
                        cfg_node: n2,
                        var_name: Some("z".into()),
                        span: (11, 15),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("x".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("y".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("z".into()),
                    cfg_node: n2,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1)), (n2, SsaValue(2))]
                .into_iter()
                .collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let consts = HashMap::from([
            (SsaValue(0), ConstLattice::Int(42)),
            (SsaValue(1), ConstLattice::Str("hello".into())),
        ]);

        let cfg: crate::cfg::Cfg = Graph::new();
        let result = analyze_types(&body, &cfg, &consts, None);

        assert!(result.is_int(SsaValue(0)));
        assert_eq!(
            result.facts.get(&SsaValue(1)).unwrap().kind,
            TypeKind::String
        );
        assert_eq!(
            result.facts.get(&SsaValue(2)).unwrap().kind,
            TypeKind::String
        ); // Source
    }

    #[test]
    fn security_type_variants_distinct() {
        // New security-relevant types are distinct from each other and meet() collapses
        // mismatched types to Unknown.
        let http_client = TypeFact::from_kind(TypeKind::HttpClient);
        let url = TypeFact::from_kind(TypeKind::Url);
        let http_response = TypeFact::from_kind(TypeKind::HttpResponse);
        let db_conn = TypeFact::from_kind(TypeKind::DatabaseConnection);
        let file_handle = TypeFact::from_kind(TypeKind::FileHandle);

        // Same-type meet preserves
        assert_eq!(http_client.meet(&http_client).kind, TypeKind::HttpClient);
        assert_eq!(url.meet(&url).kind, TypeKind::Url);

        // Cross-type meet collapses to Unknown
        assert_eq!(http_client.meet(&url).kind, TypeKind::Unknown);
        assert_eq!(http_response.meet(&db_conn).kind, TypeKind::Unknown);
        assert_eq!(file_handle.meet(&http_client).kind, TypeKind::Unknown);
    }

    #[test]
    fn label_prefix_mappings() {
        assert_eq!(TypeKind::HttpClient.label_prefix(), Some("HttpClient"));
        assert_eq!(TypeKind::HttpResponse.label_prefix(), Some("HttpResponse"));
        assert_eq!(TypeKind::Url.label_prefix(), Some("URL"));
        assert_eq!(
            TypeKind::DatabaseConnection.label_prefix(),
            Some("DatabaseConnection")
        );
        assert_eq!(TypeKind::FileHandle.label_prefix(), Some("FileHandle"));
        // Primitive types have no label prefix
        assert_eq!(TypeKind::String.label_prefix(), None);
        assert_eq!(TypeKind::Int.label_prefix(), None);
        assert_eq!(TypeKind::Unknown.label_prefix(), None);
    }

    #[test]
    fn constructor_type_inference() {
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);

        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Call {
                            callee: "URL".into(),
                            callee_text: None,
                            args: vec![],
                            receiver: None,
                        },
                        cfg_node: n0,
                        var_name: Some("url".into()),
                        span: (0, 5),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Call {
                            callee: "HttpClient.newHttpClient".into(),
                            callee_text: None,
                            args: vec![],
                            receiver: None,
                        },
                        cfg_node: n1,
                        var_name: Some("client".into()),
                        span: (6, 20),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("url".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("client".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let consts = HashMap::new();
        let cfg: crate::cfg::Cfg = Graph::new();
        let result = analyze_types(&body, &cfg, &consts, Some(Lang::Java));

        assert_eq!(result.get_type(SsaValue(0)), Some(&TypeKind::Url));
        assert_eq!(result.get_type(SsaValue(1)), Some(&TypeKind::HttpClient));

        // JS also infers URL
        let result_js = analyze_types(&body, &cfg, &consts, Some(Lang::JavaScript));
        assert_eq!(result_js.get_type(SsaValue(0)), Some(&TypeKind::Url));
        // JS doesn't know HttpClient.newHttpClient
        assert_eq!(result_js.get_type(SsaValue(1)), Some(&TypeKind::Unknown));
    }

    #[test]
    fn get_type_and_is_type() {
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::HttpClient));
        facts.insert(SsaValue(1), TypeFact::from_kind(TypeKind::Int));
        let result = TypeFactResult { facts };

        assert_eq!(result.get_type(SsaValue(0)), Some(&TypeKind::HttpClient));
        assert!(result.is_type(SsaValue(0), &TypeKind::HttpClient));
        assert!(!result.is_type(SsaValue(0), &TypeKind::Url));
        assert!(result.is_int(SsaValue(1)));
        assert_eq!(result.get_type(SsaValue(99)), None);
    }

    /// Int-typed values must suppress every type-suppressible
    /// cap, including the freshly-added `SSRF` and `DATA_EXFIL` bits.
    /// Numeric IDs cannot rewrite a URL host, cannot form path
    /// traversal sequences, cannot carry SQL/HTML/shell metacharacters,
    /// and do not encode credentials worth exfiltrating.
    #[test]
    fn int_suppresses_every_type_suppressible_cap() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Int));
        let result = TypeFactResult { facts };

        for cap in [
            Cap::SQL_QUERY,
            Cap::FILE_IO,
            Cap::SHELL_ESCAPE,
            Cap::HTML_ESCAPE,
            Cap::SSRF,
            Cap::DATA_EXFIL,
        ] {
            assert!(
                is_type_safe_for_sink(&[SsaValue(0)], cap, &result),
                "Int must suppress {cap:?}",
            );
        }
        // Caps outside the type-suppressible set never qualify.
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::CODE_EXEC,
            &result
        ));
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::DESERIALIZE,
            &result
        ));
    }

    /// Bool-typed values are even safer than ints, `true` /
    /// `false` cannot carry any payload and must suppress every
    /// type-suppressible cap.
    #[test]
    fn bool_suppresses_every_type_suppressible_cap() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Bool));
        let result = TypeFactResult { facts };

        for cap in [
            Cap::SQL_QUERY,
            Cap::FILE_IO,
            Cap::SHELL_ESCAPE,
            Cap::HTML_ESCAPE,
            Cap::SSRF,
            Cap::DATA_EXFIL,
        ] {
            assert!(
                is_type_safe_for_sink(&[SsaValue(0)], cap, &result),
                "Bool must suppress {cap:?}",
            );
        }
    }

    /// String-typed values must NOT trigger suppression, they are the
    /// canonical injection carrier.  Regression guard so a future
    /// change to `is_type_safe_for_sink` does not silently silence
    /// real String-payload findings.
    #[test]
    fn string_does_not_trigger_sink_suppression() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::String));
        let result = TypeFactResult { facts };
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::SQL_QUERY,
            &result
        ));
        assert!(!is_type_safe_for_sink(&[SsaValue(0)], Cap::SSRF, &result));
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::SHELL_ESCAPE,
            &result
        ));
    }

    /// Audit A3: The full `(TypeKind, Cap)` suppression matrix.  Encoded
    /// as a single table-driven test so any future change to
    /// `is_type_safe_for_sink` requires an intentional matrix edit + a
    /// test update.  Truth values:
    ///
    /// | TypeKind  | SQL | FILE | SHELL | HTML | SSRF | DATA_EXFIL | CODE_EXEC | DESERIALIZE |
    /// |-----------|-----|------|-------|------|------|------------|-----------|-------------|
    /// | Int       |  Y  |  Y   |   Y   |  Y   |  Y   |     Y      |     N     |      N      |
    /// | Bool      |  Y  |  Y   |   Y   |  Y   |  Y   |     Y      |     N     |      N      |
    /// | String    |  N  |  N   |   N   |  N   |  N   |     N      |     N     |      N      |
    /// | Url       |  N  |  N   |   N   |  N   |  N   |     N      |     N     |      N      |
    /// | Object    |  N  |  N   |   N   |  N   |  N   |     N      |     N     |      N      |
    /// | Unknown   |  N  |  N   |   N   |  N   |  N   |     N      |     N     |      N      |
    #[test]
    fn type_kind_cap_suppression_matrix() {
        use crate::labels::Cap;
        let caps = [
            ("SQL_QUERY", Cap::SQL_QUERY),
            ("FILE_IO", Cap::FILE_IO),
            ("SHELL_ESCAPE", Cap::SHELL_ESCAPE),
            ("HTML_ESCAPE", Cap::HTML_ESCAPE),
            ("SSRF", Cap::SSRF),
            ("DATA_EXFIL", Cap::DATA_EXFIL),
            ("CODE_EXEC", Cap::CODE_EXEC),
            ("DESERIALIZE", Cap::DESERIALIZE),
        ];
        // (kind_name, kind, [suppress for each cap in `caps` order])
        let rows: &[(&str, TypeKind, [bool; 8])] = &[
            (
                "Int",
                TypeKind::Int,
                [true, true, true, true, true, true, false, false],
            ),
            (
                "Bool",
                TypeKind::Bool,
                [true, true, true, true, true, true, false, false],
            ),
            (
                "String",
                TypeKind::String,
                [false, false, false, false, false, false, false, false],
            ),
            (
                "Url",
                TypeKind::Url,
                [false, false, false, false, false, false, false, false],
            ),
            (
                "Object",
                TypeKind::Object,
                [false, false, false, false, false, false, false, false],
            ),
            (
                "Unknown",
                TypeKind::Unknown,
                [false, false, false, false, false, false, false, false],
            ),
        ];
        for (kind_name, kind, expected) in rows {
            let mut facts = HashMap::new();
            facts.insert(SsaValue(0), TypeFact::from_kind(kind.clone()));
            let result = TypeFactResult { facts };
            for (i, (cap_name, cap)) in caps.iter().enumerate() {
                let got = is_type_safe_for_sink(&[SsaValue(0)], *cap, &result);
                assert_eq!(
                    got, expected[i],
                    "matrix mismatch for ({kind_name}, {cap_name}): expected {}, got {got}",
                    expected[i]
                );
            }
        }
    }

    /// Audit A3 (companion): empty `values` slice never suppresses,
    /// regardless of cap or per-value type facts.
    #[test]
    fn empty_values_never_suppress() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Int));
        let result = TypeFactResult { facts };
        for cap in [
            Cap::SQL_QUERY,
            Cap::FILE_IO,
            Cap::SHELL_ESCAPE,
            Cap::HTML_ESCAPE,
            Cap::SSRF,
            Cap::DATA_EXFIL,
            Cap::CODE_EXEC,
            Cap::DESERIALIZE,
        ] {
            assert!(
                !is_type_safe_for_sink(&[], cap, &result),
                "empty values must never suppress {cap:?}",
            );
        }
    }

    /// Audit A3 (companion): a Cap with NO type-suppressible bits never
    /// suppresses, even when the value's type kind is otherwise
    /// suppression-eligible.
    #[test]
    fn caps_without_type_suppressible_bits_never_fire() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Int));
        let result = TypeFactResult { facts };
        for cap in [
            Cap::CODE_EXEC,
            Cap::DESERIALIZE,
            Cap::CRYPTO,
            Cap::URL_ENCODE,
        ] {
            assert!(
                !is_type_safe_for_sink(&[SsaValue(0)], cap, &result),
                "Int must NOT suppress non-type-suppressible {cap:?}",
            );
        }
    }

    /// Audit A3 (companion): mixed-type operand list, only one Int
    /// among operands of unknown type, must NOT suppress.  The
    /// suppression rule requires every operand to be payload-incompatible.
    #[test]
    fn mixed_type_operands_do_not_suppress() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Int));
        facts.insert(SsaValue(1), TypeFact::from_kind(TypeKind::String));
        let result = TypeFactResult { facts };
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0), SsaValue(1)],
            Cap::SQL_QUERY,
            &result
        ));
    }

    /// Param values seeded from `param_types` must surface
    /// the right TypeKind for downstream sink suppression.  An out-of-
    /// range index falls back to Unknown.
    #[test]
    fn param_types_seed_param_value_facts() {
        use crate::cfg::Cfg;
        let n0 = NodeIndex::new(0);
        let n1 = NodeIndex::new(1);
        let body = SsaBody {
            blocks: vec![SsaBlock {
                id: BlockId(0),
                phis: vec![],
                body: vec![
                    SsaInst {
                        value: SsaValue(0),
                        op: SsaOp::Param { index: 0 },
                        cfg_node: n0,
                        var_name: Some("user_id".into()),
                        span: (0, 7),
                    },
                    SsaInst {
                        value: SsaValue(1),
                        op: SsaOp::Param { index: 99 },
                        cfg_node: n1,
                        var_name: Some("oob".into()),
                        span: (8, 11),
                    },
                ],
                terminator: Terminator::Return(None),
                preds: SmallVec::new(),
                succs: SmallVec::new(),
            }],
            entry: BlockId(0),
            value_defs: vec![
                ValueDef {
                    var_name: Some("user_id".into()),
                    cfg_node: n0,
                    block: BlockId(0),
                },
                ValueDef {
                    var_name: Some("oob".into()),
                    cfg_node: n1,
                    block: BlockId(0),
                },
            ],
            cfg_node_map: [(n0, SsaValue(0)), (n1, SsaValue(1))].into_iter().collect(),
            exception_edges: vec![],
            field_interner: crate::ssa::ir::FieldInterner::default(),
            field_writes: std::collections::HashMap::new(),

            synthetic_externals: std::collections::HashSet::new(),
        };

        let consts = HashMap::new();
        let cfg: Cfg = petgraph::Graph::new();
        let param_types = vec![Some(TypeKind::Int)];

        let result =
            analyze_types_with_param_types(&body, &cfg, &consts, Some(Lang::Java), &param_types);
        assert_eq!(result.get_type(SsaValue(0)), Some(&TypeKind::Int));
        // Index 99 is out of range → falls back to Unknown.
        assert_eq!(result.get_type(SsaValue(1)), Some(&TypeKind::Unknown));

        // Empty slice = type-unaware fallback (analyze_types path).
        let result2 = analyze_types(&body, &cfg, &consts, Some(Lang::Java));
        assert_eq!(result2.get_type(SsaValue(0)), Some(&TypeKind::Unknown));
    }

    // ── TypeHierarchy::is_subtype_of ─────────────────────────────────────

    #[test]
    fn hierarchy_http_servlet_response_is_servlet_response() {
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletResponse",
            "ServletResponse"
        ));
    }

    #[test]
    fn hierarchy_string_is_not_servlet_response() {
        assert!(!TypeHierarchy::is_subtype_of("String", "ServletResponse"));
    }

    #[test]
    fn hierarchy_identity_subtype() {
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletResponse",
            "HttpServletResponse"
        ));
    }

    // ── TypeHierarchy::resolve_kind ──────────────────────────────────────

    #[test]
    fn resolve_closeable_http_client() {
        assert_eq!(
            TypeHierarchy::resolve_kind("CloseableHttpClient"),
            Some(TypeKind::HttpClient)
        );
    }

    #[test]
    fn resolve_string_builder() {
        assert_eq!(
            TypeHierarchy::resolve_kind("StringBuilder"),
            Some(TypeKind::String)
        );
    }

    // ── GoInterfaceTable::definitely_not ─────────────────────────────────

    #[test]
    fn go_file_handle_definitely_not_response_writer() {
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::FileHandle,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_http_response_not_definitely_not_response_writer() {
        assert!(!GoInterfaceTable::definitely_not(
            &TypeKind::HttpResponse,
            "http.ResponseWriter"
        ));
    }

    // ── GoInterfaceTable::satisfies ──────────────────────────────────────

    #[test]
    fn go_http_response_satisfies_response_writer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_file_handle_does_not_satisfy_response_writer() {
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::FileHandle,
            "http.ResponseWriter"
        ));
    }

    #[test]
    fn go_http_response_satisfies_io_writer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "io.Writer"
        ));
    }

    // ── constructor_type() expansions ────────────────────────────────────

    #[test]
    fn constructor_type_php() {
        assert_eq!(
            constructor_type(Lang::Php, "PDO"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Php, "mysqli"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Php, "curl_init"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Php, "fopen"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Php, "SplFileObject"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(constructor_type(Lang::Php, "array_map"), None);
    }

    #[test]
    fn constructor_type_c() {
        assert_eq!(
            constructor_type(Lang::C, "fopen"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::C, "curl_easy_init"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::C, "mysql_real_connect"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::C, "PQconnectdb"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(constructor_type(Lang::C, "printf"), None);
    }

    #[test]
    fn constructor_type_cpp() {
        assert_eq!(
            constructor_type(Lang::Cpp, "fopen"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Cpp, "curl_easy_init"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Cpp, "ifstream"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Cpp, "ofstream"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Cpp, "fstream"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(constructor_type(Lang::Cpp, "printf"), None);
    }

    #[test]
    fn constructor_type_javascript_typescript_local_collections() {
        // `new Map()` / `new Set()` / `new WeakMap()` / `new WeakSet()` /
        // `new Array()` produce in-memory collections.  Excalidraw's
        // `elementsMap.get(id)` shape (which dominates the
        // `js.auth.missing_ownership_check` cluster on JS data-manipulation
        // libraries) is suppressed once the receiver type is known.
        for lang in [Lang::JavaScript, Lang::TypeScript] {
            assert_eq!(
                constructor_type(lang, "Map"),
                Some(TypeKind::LocalCollection)
            );
            assert_eq!(
                constructor_type(lang, "Set"),
                Some(TypeKind::LocalCollection)
            );
            assert_eq!(
                constructor_type(lang, "WeakMap"),
                Some(TypeKind::LocalCollection)
            );
            assert_eq!(
                constructor_type(lang, "WeakSet"),
                Some(TypeKind::LocalCollection)
            );
            assert_eq!(
                constructor_type(lang, "Array"),
                Some(TypeKind::LocalCollection)
            );
            // Existing pre-fix mappings still resolve.
            assert_eq!(constructor_type(lang, "URL"), Some(TypeKind::Url));
            assert_eq!(
                constructor_type(lang, "XMLHttpRequest"),
                Some(TypeKind::HttpClient)
            );
            // Negative: unrelated identifiers stay None.
            assert_eq!(constructor_type(lang, "Object"), None);
            assert_eq!(constructor_type(lang, "Promise"), None);
            assert_eq!(constructor_type(lang, "Foo"), None);
        }
    }

    #[test]
    fn constructor_type_ruby() {
        // HttpClient
        assert_eq!(
            constructor_type(Lang::Ruby, "Net::HTTP.new"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "Net::HTTP.get"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "HTTParty.get"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "HTTParty.post"),
            Some(TypeKind::HttpClient)
        );
        // Url
        assert_eq!(
            constructor_type(Lang::Ruby, "URI.parse"),
            Some(TypeKind::Url)
        );
        // DatabaseConnection
        assert_eq!(
            constructor_type(Lang::Ruby, "PG.connect"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "Sequel.connect"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "Mysql2::Client.new"),
            Some(TypeKind::DatabaseConnection)
        );
        // FileHandle
        assert_eq!(
            constructor_type(Lang::Ruby, "File.open"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "File.new"),
            Some(TypeKind::FileHandle)
        );
        // Negative
        assert_eq!(constructor_type(Lang::Ruby, "puts"), None);
        assert_eq!(constructor_type(Lang::Ruby, "Array.new"), None);
    }

    #[test]
    fn constructor_type_rust_exact() {
        assert_eq!(
            constructor_type(Lang::Rust, "reqwest::Client::new"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "reqwest::get"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "File::open"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "File::create"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "std::fs::File::open"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "Url::parse"),
            Some(TypeKind::Url)
        );
        // Namespace-qualified database connections
        assert_eq!(
            constructor_type(Lang::Rust, "rusqlite::Connection::open"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "diesel::PgConnection::establish"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Rust, "diesel::SqliteConnection::establish"),
            Some(TypeKind::DatabaseConnection)
        );
        // Bare `Connection::open` is accepted, Rust idiom
        // `use rusqlite::Connection; Connection::open(…)` is common, and the
        // scanner sees the unqualified callee text after import resolution.
        // Accepting this matches the benchmark fixture `rs-sqli-001`.
        assert_eq!(
            constructor_type(Lang::Rust, "Connection::open"),
            Some(TypeKind::DatabaseConnection)
        );
        // Raw callee with trailing `.unwrap()` still maps correctly because
        // `peel_identity_suffix` normalizes the callee before matching.
        assert_eq!(
            constructor_type(Lang::Rust, "Connection::open(\"app.db\").unwrap"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(constructor_type(Lang::Rust, "println!"), None);
    }

    #[test]
    fn constructor_type_java_expanded() {
        assert_eq!(
            constructor_type(Lang::Java, "OkHttpClient"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Java, "WebClient"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Java, "RestTemplate"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Java, "MongoClient"),
            Some(TypeKind::DatabaseConnection)
        );
    }

    #[test]
    fn constructor_type_go_url() {
        assert_eq!(constructor_type(Lang::Go, "url.Parse"), Some(TypeKind::Url));
    }

    #[test]
    fn constructor_type_python_aiohttp() {
        assert_eq!(
            constructor_type(Lang::Python, "aiohttp.ClientSession"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Python, "httpx.Client"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Python, "urllib3.PoolManager"),
            Some(TypeKind::HttpClient)
        );
    }

    #[test]
    fn java_hierarchy_expansion() {
        assert!(TypeHierarchy::is_subtype_of("OkHttpClient", "HttpClient"));
        assert!(TypeHierarchy::is_subtype_of("WebClient", "HttpClient"));
        assert!(TypeHierarchy::is_subtype_of("RestTemplate", "HttpClient"));
        assert!(TypeHierarchy::is_subtype_of(
            "MongoClient",
            "DatabaseConnection"
        ));
        assert!(TypeHierarchy::is_subtype_of(
            "RedisTemplate",
            "DatabaseConnection"
        ));
        assert!(TypeHierarchy::is_subtype_of(
            "JmsTemplate",
            "DatabaseConnection"
        ));
        assert_eq!(
            TypeHierarchy::resolve_kind("OkHttpClient"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            TypeHierarchy::resolve_kind("RestTemplate"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            TypeHierarchy::resolve_kind("MongoClient"),
            Some(TypeKind::DatabaseConnection)
        );
    }

    #[test]
    fn go_interface_read_closer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::FileHandle,
            "io.ReadCloser"
        ));
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "io.ReadCloser"
        ));
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::Int,
            "io.ReadCloser"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::Int,
            "io.ReadCloser"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::DatabaseConnection,
            "io.ReadCloser"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::HttpClient,
            "io.ReadCloser"
        ));
        assert!(!GoInterfaceTable::definitely_not(
            &TypeKind::FileHandle,
            "io.ReadCloser"
        ));
    }

    #[test]
    fn go_http_client_definitely_not_response_writer() {
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::HttpClient,
            "http.ResponseWriter"
        ));
    }

    // ── Hierarchy expansion ────────────────────────────────────────────

    #[test]
    fn java_hierarchy_resolve_response_entity() {
        // ResponseEntity → HttpResponse via hierarchy tier 3
        assert_eq!(
            TypeHierarchy::resolve_kind("ResponseEntity"),
            Some(TypeKind::HttpResponse)
        );
    }

    #[test]
    fn java_hierarchy_resolve_print_writer() {
        // PrintWriter → Writer (hierarchy) → FileHandle (class_name_to_type_kind)
        assert_eq!(
            TypeHierarchy::resolve_kind("PrintWriter"),
            Some(TypeKind::FileHandle)
        );
        assert!(TypeHierarchy::is_subtype_of("PrintWriter", "Writer"));
    }

    #[test]
    fn java_hierarchy_io_subtypes() {
        assert!(TypeHierarchy::is_subtype_of("FileReader", "Reader"));
        assert!(TypeHierarchy::is_subtype_of("FileWriter", "Writer"));
        assert!(TypeHierarchy::is_subtype_of("InputStreamReader", "Reader"));
        assert!(TypeHierarchy::is_subtype_of("OutputStreamWriter", "Writer"));
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletRequestWrapper",
            "HttpServletRequest"
        ));
        assert!(TypeHierarchy::is_subtype_of(
            "HttpServletRequestWrapper",
            "ServletRequest"
        ));
    }

    // ── Go interface expansion ──────────────────────────────────────────

    #[test]
    fn go_interface_sql_db_definitely_not_response() {
        // Key assertion for FP suppression: DatabaseConnection is definitely
        // NOT http.ResponseWriter → HTML_ESCAPE stripped on sql.DB first arg.
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::DatabaseConnection,
            "http.ResponseWriter"
        ));
        // Also definitely not for sql.DB interface entries
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::HttpResponse,
            "sql.DB"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::FileHandle,
            "sql.DB"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::HttpClient,
            "sql.DB"
        ));
    }

    #[test]
    fn go_interface_sql_db_satisfies() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::DatabaseConnection,
            "sql.DB"
        ));
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::DatabaseConnection,
            "sql.Conn"
        ));
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::DatabaseConnection,
            "sql.Tx"
        ));
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "sql.DB"
        ));
        assert!(!GoInterfaceTable::satisfies(&TypeKind::Int, "sql.DB"));
    }

    #[test]
    fn go_interface_write_closer() {
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::HttpResponse,
            "io.WriteCloser"
        ));
        assert!(GoInterfaceTable::satisfies(
            &TypeKind::FileHandle,
            "io.WriteCloser"
        ));
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::Int,
            "io.WriteCloser"
        ));
        assert!(!GoInterfaceTable::satisfies(
            &TypeKind::DatabaseConnection,
            "io.WriteCloser"
        ));
        assert!(GoInterfaceTable::definitely_not(
            &TypeKind::DatabaseConnection,
            "io.WriteCloser"
        ));
        assert!(!GoInterfaceTable::definitely_not(
            &TypeKind::FileHandle,
            "io.WriteCloser"
        ));
    }

    #[test]
    fn colon_normalization_in_constructor_type() {
        // Verify :: normalization doesn't break existing Java/JS/Python/Go patterns
        assert_eq!(constructor_type(Lang::Java, "URL"), Some(TypeKind::Url));
        assert_eq!(
            constructor_type(Lang::JavaScript, "URL"),
            Some(TypeKind::Url)
        );
        assert_eq!(
            constructor_type(Lang::Python, "requests.get"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            constructor_type(Lang::Go, "http.Get"),
            Some(TypeKind::HttpClient)
        );
    }

    // ── DTO field-level taint ─────────────────────────────────────────────

    /// `TypeFact::from_dto_field` returns `Some(field_kind)`
    /// for a DTO receiver whose `fields` map contains the requested
    /// field, and `None` otherwise.
    #[test]
    fn dto_field_lookup_returns_field_type_kind() {
        let mut dto = DtoFields::new("CreateUser");
        dto.insert("age", TypeKind::Int);
        dto.insert("email", TypeKind::String);
        let recv = TypeKind::Dto(dto);
        let age = TypeFact::from_dto_field(&recv, "age").expect("age field present");
        assert_eq!(age.kind, TypeKind::Int);
        let email = TypeFact::from_dto_field(&recv, "email").expect("email field present");
        assert_eq!(email.kind, TypeKind::String);
        assert!(TypeFact::from_dto_field(&recv, "missing").is_none());
    }

    /// a non-DTO receiver kind never produces a field fact ,
    /// `from_dto_field` falls through to the legacy copy-prop path.
    #[test]
    fn dto_field_lookup_on_non_dto_returns_none() {
        for k in [
            TypeKind::Int,
            TypeKind::String,
            TypeKind::Object,
            TypeKind::Unknown,
            TypeKind::HttpClient,
        ] {
            assert!(
                TypeFact::from_dto_field(&k, "any_field").is_none(),
                "non-DTO {k:?} must not produce a field fact",
            );
        }
    }

    /// Nested DTO, the parent DTO's field type is `TypeKind::Dto`,
    /// and `from_dto_field` returns that nested DTO fact directly.
    /// Callers can recurse via `as_dto()`.
    #[test]
    fn dto_field_lookup_supports_nested_dto() {
        let mut inner = DtoFields::new("Address");
        inner.insert("zip", TypeKind::String);
        let mut outer = DtoFields::new("CreateUser");
        outer.insert("address", TypeKind::Dto(inner.clone()));
        outer.insert("age", TypeKind::Int);
        let recv = TypeKind::Dto(outer);
        let addr = TypeFact::from_dto_field(&recv, "address").expect("address present");
        assert_eq!(addr.kind, TypeKind::Dto(inner));
    }

    /// an empty DTO (class declared but with no inferred
    /// fields) never resolves field reads.  Documents the safe-fallback
    /// invariant so the legacy path runs when class fields couldn't be
    /// classified.
    #[test]
    fn empty_dto_never_resolves_fields() {
        let recv = TypeKind::Dto(DtoFields::new("EmptyDto"));
        assert!(TypeFact::from_dto_field(&recv, "anything").is_none());
    }

    /// An `Int`-typed DTO field survives the type-suppression matrix
    /// the same way a freestanding `Int` does.
    #[test]
    fn dto_int_field_suppresses_sql_query_via_matrix() {
        use crate::labels::Cap;
        let mut dto = DtoFields::new("CreateUser");
        dto.insert("age", TypeKind::Int);
        let field = TypeFact::from_dto_field(&TypeKind::Dto(dto), "age").unwrap();
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), field);
        let result = TypeFactResult { facts };
        assert!(is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::SQL_QUERY,
            &result
        ));
        assert!(!is_type_safe_for_sink(
            &[SsaValue(0)],
            Cap::CODE_EXEC,
            &result
        ));
    }

    // ── JPA Criteria query suppression (real-repo openmrs FP) ─────────
    //
    // These tests pin the `TypeKind::JpaCriteriaQuery` variant + the
    // `is_safe_query_object_arg` predicate + the
    // `arg_aware_call_type` receiver-text recogniser.  Together they
    // close the openmrs HibernateDAO `session.createQuery(cq)` FP
    // cluster (216 → 24 cfg-unguarded-sink in openmrs).

    /// `JpaCriteriaQuery` carries a label_prefix so type-qualified
    /// callee resolution can attach future rules.
    #[test]
    fn jpa_criteria_query_label_prefix() {
        assert_eq!(
            TypeKind::JpaCriteriaQuery.label_prefix(),
            Some("JpaCriteriaQuery")
        );
    }

    /// `is_safe_query_object_arg` suppresses SQL_QUERY when any
    /// supplied value is a `JpaCriteriaQuery`.  Receiver inclusion is
    /// the caller's responsibility, here we just verify the predicate.
    #[test]
    fn safe_query_object_arg_suppresses_sql_query() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::JpaCriteriaQuery));
        let result = TypeFactResult { facts };
        assert!(is_safe_query_object_arg(
            &[SsaValue(0)],
            Cap::SQL_QUERY,
            &result
        ));
        // Other caps stay untouched.
        assert!(!is_safe_query_object_arg(
            &[SsaValue(0)],
            Cap::CODE_EXEC,
            &result
        ));
        // Unknown-typed values do not trigger.
        let mut facts2 = HashMap::new();
        facts2.insert(SsaValue(0), TypeFact::from_kind(TypeKind::Unknown));
        let result2 = TypeFactResult { facts: facts2 };
        assert!(!is_safe_query_object_arg(
            &[SsaValue(0)],
            Cap::SQL_QUERY,
            &result2
        ));
        // Empty slice never suppresses.
        assert!(!is_safe_query_object_arg(&[], Cap::SQL_QUERY, &result));
    }

    /// `is_safe_query_object_arg` fires when a Criteria value is mixed
    /// in with other types — the predicate is `any`, not `all`, since
    /// the criteria-object arg is the only injection-bearing slot for a
    /// `createQuery(cq)` sink.
    #[test]
    fn safe_query_object_arg_fires_with_mixed_args() {
        use crate::labels::Cap;
        let mut facts = HashMap::new();
        facts.insert(SsaValue(0), TypeFact::from_kind(TypeKind::JpaCriteriaQuery));
        facts.insert(SsaValue(1), TypeFact::from_kind(TypeKind::String));
        facts.insert(SsaValue(2), TypeFact::from_kind(TypeKind::Unknown));
        let result = TypeFactResult { facts };
        assert!(is_safe_query_object_arg(
            &[SsaValue(0), SsaValue(1), SsaValue(2)],
            Cap::SQL_QUERY,
            &result
        ));
    }

    /// `arg_aware_call_type` maps the JPA `cb.createQuery(...)` /
    /// `criteriaBuilder.createQuery(...)` / `((CriteriaBuilder)
    /// x).createQuery(...)` shapes to `JpaCriteriaQuery`, distinct
    /// from the overloaded `session.createQuery(...)` /
    /// `em.createQuery(...)` which stays `None` (the
    /// executable-query overload).
    #[test]
    fn arg_aware_call_type_jpa_criteria_builder_recogniser() {
        let no_args: Vec<SmallVec<[SsaValue; 2]>> = vec![];
        let consts: HashMap<SsaValue, ConstLattice> = HashMap::new();
        // Receiver hint: bare `cb` ident.
        assert_eq!(
            arg_aware_call_type(Lang::Java, "cb.createQuery", &no_args, &consts),
            Some(TypeKind::JpaCriteriaQuery)
        );
        // Receiver hint: bare `criteriaBuilder` ident.
        assert_eq!(
            arg_aware_call_type(Lang::Java, "criteriaBuilder.createQuery", &no_args, &consts),
            Some(TypeKind::JpaCriteriaQuery)
        );
        // Cast in receiver text.
        assert_eq!(
            arg_aware_call_type(
                Lang::Java,
                "((CriteriaBuilder) cb).createQuery",
                &no_args,
                &consts
            ),
            Some(TypeKind::JpaCriteriaQuery)
        );
        // Chained accessor: getCriteriaBuilder().createQuery
        assert_eq!(
            arg_aware_call_type(
                Lang::Java,
                "session.getCriteriaBuilder().createQuery",
                &no_args,
                &consts
            ),
            Some(TypeKind::JpaCriteriaQuery)
        );
        // The executable-query overload (`session.createQuery`) does
        // NOT match — receiver-text doesn't carry a CriteriaBuilder
        // hint, so we leave the type as Unknown and let the
        // suppression decide based on the arg-0 type fact.
        assert_eq!(
            arg_aware_call_type(Lang::Java, "session.createQuery", &no_args, &consts),
            None
        );
        assert_eq!(
            arg_aware_call_type(Lang::Java, "em.createQuery", &no_args, &consts),
            None
        );
        // Non-Java langs return None.
        assert_eq!(
            arg_aware_call_type(Lang::Python, "cb.createQuery", &no_args, &consts),
            None
        );
        // Other suffixes return None.
        assert_eq!(
            arg_aware_call_type(Lang::Java, "cb.createCriteriaUpdate", &no_args, &consts),
            None
        );
    }

    /// Unique-suffix Criteria API methods land on
    /// `TypeKind::JpaCriteriaQuery` directly via [`constructor_type`]
    /// without the receiver hint, since `createCriteriaUpdate` /
    /// `createCriteriaDelete` / `createTupleQuery` / `subquery` exist
    /// only on `CriteriaBuilder` / `CriteriaQuery` and have no
    /// overload conflict.
    #[test]
    fn constructor_type_unique_jpa_criteria_methods() {
        for suffix in &[
            "createCriteriaUpdate",
            "createCriteriaDelete",
            "createTupleQuery",
            "subquery",
        ] {
            assert_eq!(
                constructor_type(Lang::Java, suffix),
                Some(TypeKind::JpaCriteriaQuery),
                "suffix `{suffix}` must map to JpaCriteriaQuery"
            );
            // Same suffix prefixed by an arbitrary receiver still maps.
            assert_eq!(
                constructor_type(Lang::Java, &format!("cb.{suffix}")),
                Some(TypeKind::JpaCriteriaQuery)
            );
        }
        // Non-criteria methods unaffected.
        assert_eq!(
            constructor_type(Lang::Java, "session.createQuery"),
            None,
            "createQuery is overloaded — must not map at constructor_type level"
        );
    }
}

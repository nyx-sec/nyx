#![allow(clippy::if_same_then_else)]

//! Lightweight type inference for SSA values.
//!
//! Derives [`TypeKind`] facts (ints, URLs, HTTP clients/responses, DB
//! connections, file handles) from constructors, factories, and literals, used
//! to suppress type-safe sinks and to resolve receiver-qualified callees.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use super::const_prop::{ConstLattice, ConstValues};
use super::ir::*;
use crate::cfg::{BinOp, Cfg};
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

thread_local! {
    /// Per-file local import view (local-name → source-module specifier),
    /// set by [`with_file_imports`] around every per-body SSA pass that
    /// needs to gate ORM TypeKind assignment in [`constructor_type`].
    /// `None` (default) preserves prior un-gated behaviour for legacy /
    /// test paths that build SSA without a surrounding file context.
    static FILE_IMPORTS_TLS: RefCell<Option<HashMap<String, String>>> = const { RefCell::new(None) };
}

/// Run `f` with `imports` published to the per-thread file-imports view.
/// Restores the prior value on drop so nested calls compose; pass `None`
/// to suppress gating for callers that lack a file context.
pub fn with_file_imports<R>(imports: Option<&HashMap<String, String>>, f: impl FnOnce() -> R) -> R {
    let prev = FILE_IMPORTS_TLS.with(|cell| {
        cell.borrow_mut()
            .replace(imports.cloned().unwrap_or_default())
    });
    let restore_to = if imports.is_some() { prev } else { None };
    struct Guard(Option<HashMap<String, String>>);
    impl Drop for Guard {
        fn drop(&mut self) {
            FILE_IMPORTS_TLS.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }
    let _guard = Guard(restore_to);
    f()
}

/// Returns true iff any local-import in the active file-imports view maps
/// to a module specifier whose canonical form satisfies `pred`.  When the
/// view has not been published (legacy / test paths) the predicate is
/// considered satisfied so prior behaviour is preserved.
fn file_imports_match(pred: impl Fn(&str) -> bool) -> bool {
    FILE_IMPORTS_TLS.with(|cell| {
        let borrowed = cell.borrow();
        let Some(map) = borrowed.as_ref() else {
            return true;
        };
        map.values().any(|spec| pred(spec.as_str()))
    })
}

/// Dotted path the active file-imports view binds `name` to. Only Python
/// files publish this shape (`from M import n [as a]` maps to `M.n`,
/// `import M as a` to `M`); label classification uses it to also try the
/// module-qualified spelling of a bare imported callee. `None` when no view
/// is published or `name` is not a recorded binding.
pub(crate) fn file_import_path(name: &str) -> Option<String> {
    FILE_IMPORTS_TLS.with(|cell| cell.borrow().as_ref().and_then(|m| m.get(name).cloned()))
}

/// Strip a leading `node:` prefix from a module specifier so gates can
/// match `import x from "fs"` and `import x from "node:fs"` uniformly.
fn strip_node_prefix(spec: &str) -> &str {
    spec.strip_prefix("node:").unwrap_or(spec)
}

/// Returns true iff the active file-imports view satisfies the
/// import-gate for an ORM TypeKind.  When the TLS view is unset (legacy
/// callers without file context) the gate is treated as satisfied so
/// prior behaviour is preserved.
fn orm_typekind_import_satisfied(tk: &TypeKind) -> bool {
    let predicate: fn(&str) -> bool = match tk {
        TypeKind::Sequelize => |spec| {
            let s = strip_node_prefix(spec);
            s == "sequelize" || s.starts_with("sequelize/")
        },
        TypeKind::TypeOrmRepo | TypeKind::TypeOrmManager => |spec| {
            let s = strip_node_prefix(spec);
            s == "typeorm" || s.starts_with("typeorm/")
        },
        TypeKind::MikroOrmEm => |spec| {
            let s = strip_node_prefix(spec);
            s.starts_with("@mikro-orm/")
        },
        _ => return true,
    };
    file_imports_match(predicate)
}

/// Small helper used inside [`constructor_type`] to fold the ORM import
/// gate into the JS/TS arm without restructuring the surrounding
/// `match`.  Returns `Some(tk)` only when the gate is satisfied.
fn orm_gate(tk: TypeKind) -> Option<TypeKind> {
    if orm_typekind_import_satisfied(&tk) {
        Some(tk)
    } else {
        None
    }
}

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
    /// (the receiver type is itself the import witness). The TypeKind
    /// is reached today via the gated-import path in
    /// `crate::cfg::apply_gated_label_rules`; SSA-time tagging from
    /// `constructor_type` is intentionally not wired (member-of-call
    /// shapes like `fs.promises` decompose into Call + FieldProj ops,
    /// so the full expression text never reaches the constructor table).
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
    /// A Web-platform `Request` object passed as the first argument to a
    /// Next.js App Router HTTP-method handler (`GET`, `POST`, ...).
    /// Phase 10 seeds the formal at function entry so receiver-method
    /// reads (`req.json()`, `req.formData()`, `req.text()`,
    /// `req.headers.get(...)`, `req.url`) carry their parameter's
    /// taint through `Request.<method>` label rewrites without
    /// requiring a caller-side flow.
    Request,
    /// A SQLAlchemy `Session` / `Connection` produced by
    /// `sessionmaker()()`, `Session(engine)`, `engine.connect()`,
    /// `scoped_session()()`.  Type-qualified resolution rewrites
    /// `session.execute(sql)` → `SqlAlchemySession.execute` against
    /// the flat SQL_QUERY rule so Python ORM raw-SQL passthrough is
    /// caught even when the receiver name shadows another `execute`
    /// method.
    SqlAlchemySession,
    /// A Django ORM `QuerySet` / `Manager` produced by
    /// `Model.objects` access or `Model.objects.filter(...)`-shaped
    /// chains.  Receiver type for `qs.raw(sql)` and `qs.extra(...)`
    /// raw-SQL passthrough sinks.
    DjangoQuerySet,
    /// An ActiveRecord `Relation` produced by `Model.where(...)` /
    /// `Model.all` / `Model.find_by_sql(...)`-shaped chains, or by
    /// the model class itself when used as a class-method receiver.
    /// Used so `relation.find_by_sql(sql)` and chained raw-SQL
    /// methods resolve to receiver-typed sinks instead of bare verbs.
    ActiveRecordRelation,
    /// A GORM `*gorm.DB` produced by `gorm.Open(dialector, &gorm.Config{})`.
    /// Receiver for `db.Raw(sql)` / `db.Exec(sql)` raw-SQL passthrough
    /// sinks.  Distinct from `DatabaseConnection` so the Go
    /// type-qualified rules fire only on GORM receivers and don't
    /// collide with stdlib `*sql.DB` or `*sqlx.DB`.
    GormDb,
    /// A `*sqlx.DB` / `*sqlx.Tx` produced by `sqlx.Connect(driver, dsn)`
    /// / `sqlx.Open(...)` / `sqlx.MustConnect(...)`.  Receiver for
    /// `sqlxDb.NamedExec(sql, ...)` / `sqlxDb.NamedQuery(sql, ...)` /
    /// `sqlxDb.Select(dest, sql, ...)` etc. raw-SQL passthrough sinks.
    SqlxDb,
    /// A Hibernate `org.hibernate.Session` produced by
    /// `sessionFactory.openSession()` / `sessionFactory.getCurrentSession()`
    /// or via a declared field/local of type `Session`.  Receiver for
    /// `sess.createQuery(sql)` / `sess.createSQLQuery(sql)` /
    /// `sess.createNativeQuery(sql)` raw-SQL passthrough sinks.  The
    /// flat `session.create*` matchers in `labels/java.rs` only fire on
    /// receivers literally named `session`; this TypeKind closes the
    /// arbitrary-receiver-name shape (`sess`, `hibernateSession`, etc.)
    /// via type-qualified resolution.
    HibernateSession,
    /// A `java.lang.ProcessBuilder` instance produced by
    /// `new ProcessBuilder(...)`.  The dominant OWASP Benchmark
    /// command-injection shape builds an argument `List<String>`, attaches
    /// it via `pb.command(argList)`, then runs it with `pb.start()`.  The
    /// argument list is a separate channel from the constructor, so the
    /// flat `ProcessBuilder` constructor sink never sees the tainted args.
    /// Mapping the receiver to this TypeKind lets the type-qualified
    /// resolver rewrite `pb.command(argList)` → `ProcessBuilder.command`
    /// against the flat SHELL_ESCAPE rule in `labels/java.rs`, so tainted
    /// list contents reaching the command builder are caught at the
    /// `command(...)` call site.
    ProcessBuilder,
    /// A `java.lang.StringBuilder` / `StringBuffer` instance, produced by
    /// `new StringBuilder(...)` or a declared receiver of that type.  Its
    /// `append` / `insert` calls mutate the receiver, so the taint engine
    /// writes the argument taint into the builder only for receivers of
    /// this kind; an unrelated user type with an `append` method keeps the
    /// default call propagation.
    StringBuilder,
    /// A `java.lang.Runtime` instance produced by the static factory
    /// `Runtime.getRuntime()`.  The dominant OWASP Benchmark
    /// command-injection shape splits the receiver across statements:
    /// `Runtime r = Runtime.getRuntime(); ... r.exec(args, argsEnv)`.  The
    /// callee text at the sink is `r.exec`, which does not suffix-match the
    /// flat `Runtime.exec` rule in `labels/java.rs` (the chained
    /// `Runtime.getRuntime().exec(...)` form fires only because its callee
    /// text literally contains `Runtime`).  Mapping the receiver `r` to
    /// this TypeKind lets the type-qualified resolver rewrite `r.exec(...)`
    /// → `Runtime.exec` against the flat SHELL_ESCAPE rule, so tainted data
    /// reaching the split-receiver exec is caught.  No payload-arg
    /// restriction: `Runtime.exec` overloads place the tainted data in
    /// either the command (arg 0) or the environment array (arg 1), so the
    /// default all-args sink scan must cover every position.
    Runtime,
    /// A Spring `JdbcTemplate` / `NamedParameterJdbcTemplate` (or their
    /// `JdbcOperations` interfaces).  Only reached through a declared
    /// field, parameter or local type, since Spring injects the template
    /// rather than building it in the method.  The `JdbcTemplate.*` SQL
    /// rules in `labels/java.rs` take the statement at arg 0 and treat the
    /// rest as bind values, row mappers or result classes.
    JdbcTemplate,
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
            Self::Request => Some("Request"),
            Self::SqlAlchemySession => Some("SqlAlchemySession"),
            Self::DjangoQuerySet => Some("DjangoQuerySet"),
            Self::ActiveRecordRelation => Some("ActiveRecordRelation"),
            Self::GormDb => Some("GormDb"),
            Self::SqlxDb => Some("SqlxDb"),
            Self::HibernateSession => Some("HibernateSession"),
            Self::ProcessBuilder => Some("ProcessBuilder"),
            Self::Runtime => Some("Runtime"),
            Self::JdbcTemplate => Some("JdbcTemplate"),
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
///   `DATA_EXFIL`, `HEADER_INJECTION`, `OPEN_REDIRECT`. Numeric values
///   cannot carry the metacharacters required to drive any of these
///   injection classes, nor can they encode credentials/tokens that
///   meaningfully constitute leakage.  HEADER_INJECTION needs CRLF;
///   OPEN_REDIRECT needs a `://` scheme followed by an attacker host
///   ,  numeric scalars and the safe-string upgrades that share this
///   tag (see [`is_safe_string_producing_callee`]) cannot encode
///   either.
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
        | Cap::DATA_EXFIL
        | Cap::HEADER_INJECTION
        | Cap::OPEN_REDIRECT;
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
    _consts: &ConstValues,
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

/// True when `callee` is a single-argument URL/URI factory whose first
/// argument carries the resulting URL's full spec (so a leading literal
/// prefix on that arg locks the constructed URL's host).  Used by the
/// abstract-string transfer in
/// `taint::ssa_transfer::transfer_abstract` to gate the single-arg URL
/// constructor StringFact passthrough alongside the
/// `constructor_type(...) == TypeKind::Url` check.  Currently covers
/// Java's static `URI.create(spec)` and `URL.of(spec)` factories
/// (`URL.of` introduced in Java 23, returns a `URL` from a single
/// string spec).  Bare-leaf forms (`URI.create`, `URL.of`) and
/// fully-qualified prefixes (`java.net.URI.create`) are both accepted.
pub(crate) fn is_url_single_arg_factory(lang: Lang, callee: &str) -> bool {
    matches!(lang, Lang::Java)
        && (callee == "URI.create"
            || callee.ends_with(".URI.create")
            || callee == "URL.of"
            || callee.ends_with(".URL.of"))
}

/// True when `field_name` reads off a WHATWG `URL` instance as a logical
/// alias of the same URL value: `searchParams` is the mutable view (any
/// `.set` / `.append` on it mutates the underlying URL), the others are
/// pure-string projections of the same URL.  Used by the FieldProj
/// type-aliasing rule so a `.set(k, v)` on the searchParams view dispatches
/// to the URL receiver-type rule rather than as an opaque Object.
pub(crate) fn is_url_identity_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "searchParams" | "host" | "hostname" | "pathname" | "href" | "origin"
    )
}

/// Classes whose instance is the string or path value of its constructor
/// arguments rather than an opaque wrapper object: `java.io.File` is the
/// path, and `String` / `StringBuilder` / `StringBuffer` are the text.  The
/// constructor cap narrowing in the SSA call transfer keeps string-shaped
/// caps (FILE_IO, ...) on these, so `new File(base, name)` still carries the
/// traversal into `new FileInputStream(f)`.  Stream classes such as
/// `FileInputStream` are not values and are not listed.
pub(crate) fn constructor_is_value_wrapper(lang: Lang, class: &str) -> bool {
    let leaf = class.rsplit("::").next().unwrap_or(class);
    let leaf = leaf.split('<').next().unwrap_or(leaf);
    let leaf = leaf.rsplit('.').next().unwrap_or(leaf).trim();
    match lang {
        Lang::Java => matches!(leaf, "File" | "String" | "StringBuilder" | "StringBuffer"),
        Lang::JavaScript | Lang::TypeScript => leaf == "String",
        _ => false,
    }
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
            // JDBC `conn.createStatement()` / `conn.prepareStatement(sql)` /
            // `conn.prepareCall(sql)` produce a `Statement` /
            // `PreparedStatement` / `CallableStatement` whose `.execute*`
            // calls are first-class SQL sinks.  Mapped to
            // `DatabaseConnection` so the type-qualified label
            // `DatabaseConnection.execute` (in `labels/java.rs`) fires for
            // `s.execute(query)` calls without widening the bare `execute`
            // matcher.  A prepared statement carries the taint of the SQL
            // text it was prepared from, so `conn.prepareStatement("..'" + p
            // + "'")` followed by `ps.execute()` is reported; bind values set
            // with `ps.setString(..)` never reach the SQL text, and a literal
            // template carries no taint.  Surfaced by GHSA-h8cj-hpmg-636v
            // (Appsmith FilterDataServiceCE.dropTable) and the OWASP
            // Benchmark prepareStatement SQLi cases.
            "createStatement" | "prepareStatement" | "prepareCall" => {
                Some(TypeKind::DatabaseConnection)
            }
            "FileInputStream" | "FileOutputStream" | "FileReader" | "FileWriter"
            | "BufferedReader" | "BufferedWriter" => Some(TypeKind::FileHandle),
            // Phase 13 — `java.nio.file.Paths.get(...)` returns a `Path`,
            // and `java.io.File(...)` is the legacy stdlib path handle.
            // Tagging the receiver as `FileHandle` lets the type-qualified
            // resolver rewrite chained ops like `.normalize()` /
            // `.toAbsolutePath()` on the returned value via the new
            // `FileHandle.*` matchers.  `get` matched on its own would
            // over-fire (Map.get / List.get / etc.); the qualified
            // `Paths.get` form is unambiguous.
            "get" if callee == "Paths.get" || callee.ends_with(".Paths.get") => {
                Some(TypeKind::FileHandle)
            }
            "File" => Some(TypeKind::FileHandle),
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
            // The parser factories themselves: StAX parses straight off the
            // `XMLInputFactory`, and `dbf.newDocumentBuilder().parse(x)`
            // reads as `dbf.parse`, so the factory is the receiver the
            // config sidecar and the `XmlParser.*` sinks see.  dom4j's
            // `new SAXReader()` is the parser.
            "newInstance" | "newFactory" | "newDefaultFactory"
                if callee.contains("DocumentBuilderFactory")
                    || callee.contains("SAXParserFactory")
                    || callee.contains("XMLInputFactory") =>
            {
                Some(TypeKind::XmlParser)
            }
            "SAXReader" => Some(TypeKind::XmlParser),
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
            // Hibernate `SessionFactory.openSession()` /
            // `SessionFactory.getCurrentSession()` produce an
            // `org.hibernate.Session` instance whose `createQuery(sql)` /
            // `createSQLQuery(sql)` / `createNativeQuery(sql)` are SQL
            // sinks.  Method names are unique to Hibernate so suffix
            // matching is unambiguous.  `openStatelessSession` returns a
            // `StatelessSession` with the same query-builder API.
            "openSession" | "getCurrentSession" | "openStatelessSession" => {
                Some(TypeKind::HibernateSession)
            }
            // `new ProcessBuilder(...)` — the receiver's `command(argList)`
            // setter is a command-injection sink for the list contents.
            // Type-qualified resolution rewrites `pb.command(...)` →
            // `ProcessBuilder.command` against the flat SHELL_ESCAPE rule.
            "ProcessBuilder" => Some(TypeKind::ProcessBuilder),
            // `new StringBuilder(...)` / `new StringBuffer(...)`: the
            // receiver of statement-form `append` / `insert` mutation.
            "StringBuilder" | "StringBuffer" => Some(TypeKind::StringBuilder),
            // `Runtime.getRuntime()` — the static factory returns the
            // singleton `java.lang.Runtime`.  Gating on `callee.contains
            // ("Runtime")` keeps an unrelated `foo.getRuntime()` method from
            // being mistyped.  Type-qualified resolution rewrites the
            // split-receiver `r.exec(...)` → `Runtime.exec` against the flat
            // SHELL_ESCAPE rule.
            "getRuntime" if callee.contains("Runtime") => Some(TypeKind::Runtime),
            _ => None,
        },
        Lang::JavaScript | Lang::TypeScript => {
            // NB: `fs.promises` and `require('fs').promises` member-access
            // shapes are NOT mapped here — SSA decomposes member-of-call
            // into separate Call + FieldProj ops, so the full expression
            // text never reaches `constructor_type` as a callee string.
            // The `FileSystemPromisesNs` TypeKind is reached via the
            // gated-import path in `cfg::apply_gated_label_rules` instead.
            match suffix {
                "URL" => Some(TypeKind::Url),
                "Request" | "XMLHttpRequest" => Some(TypeKind::HttpClient),
                // Phase 07 — ORM constructors / factory functions. Coverage:
                // `new Sequelize(...)`           → Sequelize
                // `getRepository(Entity)`        → TypeOrmRepo  (typeorm)
                // `getManager()`                 → TypeOrmManager (typeorm)
                // `createEntityManager()`        → MikroOrmEm (@mikro-orm/core)
                // Gated on the per-file local-import view published via
                // [`with_file_imports`]: the suffix names are distinctive but
                // not unique (an app-internal class named `Sequelize` with a
                // `.literal()` helper, a custom `getRepository` method on a
                // user-defined repository pattern, etc. would collide).
                // When the TLS view is unset (test paths / non-file callers)
                // the gate is treated as satisfied so prior behaviour is
                // preserved.
                "Sequelize" => orm_gate(TypeKind::Sequelize),
                "getRepository" => orm_gate(TypeKind::TypeOrmRepo),
                "getManager" => orm_gate(TypeKind::TypeOrmManager),
                "createEntityManager" => orm_gate(TypeKind::MikroOrmEm),
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
            } else if callee == "Path"
                || callee == "pathlib.Path"
                || callee == "PurePath"
                || callee == "pathlib.PurePath"
                || callee == "PurePosixPath"
                || callee == "pathlib.PurePosixPath"
                || callee == "PureWindowsPath"
                || callee == "pathlib.PureWindowsPath"
                || callee == "PosixPath"
                || callee == "WindowsPath"
            {
                // Phase 13 — `pathlib.Path(p)` and friends.  Tagging the
                // receiver as `FileHandle` lets the type-qualified resolver
                // rewrite `p.read_text()` / `p.write_text()` etc. against
                // the new `FileHandle.*` matchers in `labels/python.rs`,
                // covering the receiver-bound shape `p = Path(name);
                // p.read_text()` that the chained `Path(name).read_text()`
                // matcher already handles via paren-strip.
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
            } else if callee == "sessionmaker"
                || callee == "scoped_session"
                || callee == "sqlalchemy.orm.sessionmaker"
                || callee == "sqlalchemy.orm.scoped_session"
                || callee == "Session"
                || callee == "sqlalchemy.orm.Session"
                || (suffix == "connect" && callee.contains("sqlalchemy"))
                || (suffix == "begin" && callee.contains("engine"))
            {
                // Phase 15 — SQLAlchemy session / connection factories.
                // `sessionmaker()` returns a callable, `sessionmaker()()`
                // returns a Session; the inner-call collapse step in
                // `cfg::push_node` flattens that to a single CallFn whose
                // callee text suffix matches `sessionmaker`.  `Session(engine)`,
                // `Session()`, and `engine.connect()` likewise produce a
                // session-like object.  Tagging the resulting receiver as
                // `SqlAlchemySession` lets the type-qualified resolver rewrite
                // `session.execute(sql)` → `SqlAlchemySession.execute`.
                Some(TypeKind::SqlAlchemySession)
            } else if suffix == "objects" {
                // Phase 15 — Django ORM `Model.objects` access surfaces as a
                // FieldProj whose call form is `Model.objects` (read as a
                // call by the chain-normalisation pass).  Tagging the
                // resulting receiver as `DjangoQuerySet` lets `qs.raw(sql)` /
                // `qs.extra(...)` rewrite to `DjangoQuerySet.<method>`.
                Some(TypeKind::DjangoQuerySet)
            } else if callee.contains(".objects.") && is_orm_queryset_chain_method(suffix) {
                // Django ORM chained-queryset producers.
                // `Model.objects.all() / .filter(...) / .exclude(...)` etc.
                // return another `QuerySet`.  The FieldProj-chain
                // decomposition for `Model.<chain>` bails when the base
                // identifier (the class name `Model`) isn't in the local
                // SSA var stack, leaving the Call op carrying the full
                // chain text as its callee.  Tagging the result as
                // `DjangoQuerySet` lets a bound `qs = Model.objects.all();
                // qs.raw(sql)` resolve `qs.raw` via the type-qualified
                // sink rule, closing the intermediate-binding shape that
                // the flat `objects.raw` matcher misses.
                Some(TypeKind::DjangoQuerySet)
            } else {
                None
            }
        }
        Lang::Go => {
            // `http.Get` / `http.Post` return a `*http.Response` and
            // `http.NewRequest` a `*http.Request`; neither is a client.  A
            // client value is typed from its declaration
            // (`cfg::extract_decl_type_go`, `c *http.Client` formals).
            if callee.contains("sql.") && suffix == "Open" {
                Some(TypeKind::DatabaseConnection)
            } else if callee.contains("os.") && matches!(suffix, "Open" | "Create" | "OpenFile") {
                Some(TypeKind::FileHandle)
            } else if callee.contains("bytes.") && matches!(suffix, "NewBuffer" | "NewBufferString")
            {
                // In-memory byte buffers (`bytes.NewBuffer(nil)` /
                // `bytes.NewBufferString("")`).  Tagged `FileHandle` so a
                // `fmt.Fprintf(buf, ...)` into the buffer is recognised as a
                // non-response (non-XSS) write by the Go ResponseWriter gate —
                // same rationale as `classify_param_type_go`.  gitea's
                // git-index write helpers build a `*bytes.Buffer` and stream
                // it to `git update-index` stdin.
                Some(TypeKind::FileHandle)
            } else if callee.contains("bufio.")
                && matches!(suffix, "NewWriter" | "NewWriterSize" | "NewReadWriter")
            {
                // Buffered writers wrapping an underlying stream/file.
                Some(TypeKind::FileHandle)
            } else if callee.contains("url.") && suffix == "Parse" {
                Some(TypeKind::Url)
            } else if callee.contains("ldap.") && matches!(suffix, "Dial" | "DialURL" | "DialTLS") {
                // go-ldap (`github.com/go-ldap/ldap/v3`): `conn, _ := ldap.DialURL(url)`
                // returns `*ldap.Conn` whose `Search(req)` is an LDAP-injection sink.
                Some(TypeKind::LdapClient)
            } else if callee.starts_with("gorm.") && matches!(suffix, "Open" | "Must") {
                // Phase 15 — GORM: `gorm.Open(driver, &gorm.Config{})` returns
                // `*gorm.DB`.  Tagging it as `GormDb` lets the type-qualified
                // resolver rewrite `db.Raw(...)` → `GormDb.Raw` etc.
                Some(TypeKind::GormDb)
            } else if callee.starts_with("sqlx.")
                && matches!(suffix, "Connect" | "MustConnect" | "Open" | "MustOpen")
            {
                // Phase 15 — sqlx: `sqlx.Connect("postgres", dsn)` returns
                // `*sqlx.DB`; tagging it as `SqlxDb` lets `db.NamedExec(...)`
                // / `db.NamedQuery(...)` rewrite to `SqlxDb.<method>`.
                Some(TypeKind::SqlxDb)
            } else {
                None
            }
        }
        Lang::Php => match suffix {
            "PDO" | "mysqli" => Some(TypeKind::DatabaseConnection),
            "curl_init" => Some(TypeKind::HttpClient),
            // Phase 14 — Guzzle / Symfony HTTP client constructors.
            // `new \GuzzleHttp\Client(...)` and `new Client(...)` both
            // tail-match `Client` here; the resulting `TypeKind::HttpClient`
            // routes `$c->request($method, $url)` through the type-qualified
            // `HttpClient.request` SSRF rule in `labels/php.rs`.  The
            // `Client` leaf can collide with framework-internal classes
            // also named `Client`, but the source-sensitivity gate
            // already silences plain user-input flows so the FP surface
            // is bounded.
            "Client" => Some(TypeKind::HttpClient),
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
            } else if callee == "Faraday.new"
                || callee == "RestClient::Resource.new"
                || (after_colons.starts_with("Typhoeus") && suffix == "new")
            {
                // Phase 14 — Faraday / Typhoeus / rest-client client
                // instances.  `client = Faraday.new(url: base)` returns
                // an HTTP client whose `client.get(path)` resolves via
                // the type-qualified `HttpClient.get` SSRF rule.
                Some(TypeKind::HttpClient)
            } else if after_colons.starts_with("URI") && matches!(suffix, "parse" | "URI") {
                Some(TypeKind::Url)
            } else if after_colons == "PG.connect"
                || callee == "PG::Connection.new"
                || callee == "PG::Connection.connect"
                || callee == "PG::Connection.open"
                || callee == "PGconn.new"
                || callee == "PGconn.connect"
                || (after_colons.starts_with("Sequel") && suffix == "connect")
                || callee.contains("Mysql2")
            {
                // `pg` gem low-level driver: `@@conn = PG::Connection.new(...)`
                // (and the `PG.connect` / `PGconn.new` aliases) return a raw
                // libpq connection whose `conn.exec(sql)` runs an unparameterised
                // string and `conn.exec_params(sql, params)` is the safe
                // placeholder form.  Tagging the receiver `DatabaseConnection`
                // lets the type-qualified resolver rewrite `conn.exec(query)` to
                // `DatabaseConnection.exec` (a SQL_QUERY sink) without widening
                // the bare `exec` matcher (which is Kernel#exec — a shell sink).
                // Motivated by CVE-2026-42087 (OpenC3 COSMOS QuestDB SQLi).
                Some(TypeKind::DatabaseConnection)
            } else if matches!(suffix, "connection" | "lease_connection")
                && callee
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
            {
                // ActiveRecord adapter handle: `ActiveRecord::Base.connection`,
                // `Model.connection`, `Model.lease_connection`.  Its
                // `execute(sql)` runs the string as written, so a local bound to
                // it (`c = ActiveRecord::Base.connection; c.execute(q)`)
                // resolves to the type-qualified `DatabaseConnection.execute`
                // sink.  Only class-qualified receivers qualify: a bare
                // `connection` helper has no known type.
                Some(TypeKind::DatabaseConnection)
            } else if after_colons.starts_with("File.") && matches!(suffix, "open" | "new") {
                Some(TypeKind::FileHandle)
            } else if callee.contains("Net::LDAP") && matches!(suffix, "new" | "open") {
                // net-ldap gem: `Net::LDAP.new(host: ...)` / `Net::LDAP.open`
                // returns a connection whose `search(base:, filter:)` accepts
                // an attacker-influenceable filter expression.
                Some(TypeKind::LdapClient)
            } else if matches!(
                suffix,
                "where" | "all" | "find_by_sql" | "find_by" | "joins" | "order"
            ) && callee
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
            {
                // Phase 15 — ActiveRecord class-method scopes return a
                // `Relation` (chainable query object).  Tagging the receiver
                // as `ActiveRecordRelation` lets the type-qualified resolver
                // rewrite chained calls (`User.where(...).find_by_sql(...)`)
                // to `ActiveRecordRelation.<method>` when the original class
                // name is preserved in the receiver text.  Conservative:
                // only fires on receivers that start with an uppercase
                // segment (Ruby class-name convention) so plain helpers are
                // not collected.
                Some(TypeKind::ActiveRecordRelation)
            } else {
                None
            }
        }
    }
}

/// Phase 14 — recognise per-language URL builders that take a `(base,
/// path)`-shaped argument pair.  Returns `Some((path_arg_idx, base_arg_idx))`
/// when the callee is known to construct / join a URL out of a literal
/// base origin and a (possibly tainted) path component.  The caller then:
///
/// 1. Forwards taint from the path arg into the call's result SSA value
///    (so downstream HTTP sinks see the propagated taint).
/// 2. When the base arg is a syntactic string literal, seeds the abstract
///    [`crate::abstract_interp::StringFact::from_url_with_base`] on the
///    result so [`is_string_safe_for_ssrf`] can suppress the SSRF sink at
///    a fully-formed `scheme://host/...` prefix.
///
/// Coverage matches the phase-14 origin-lock table: JS/TS `new URL(path,
/// base)` (constructor), Python `urllib.parse.urljoin(base, path)`, Java
/// `new URL(URL context, String spec)`, Go `url.JoinPath(base, paths...)`,
/// Ruby `URI.join(base, path)`.  Rust is intentionally omitted: the
/// idiomatic shape is `Url::parse(base).unwrap().join(path)` (a chain),
/// not a single (base, path) call, so no per-call site fits the helper's
/// shape.  The `Url::parse(literal_url)` single-arg case is covered by
/// generic abstract-string seeding via [`SsaOp::Const`].
pub(crate) fn url_builder_arg_indices(
    lang: Lang,
    callee: &str,
    outer_callee: Option<&str>,
    is_constructor: bool,
) -> Option<(usize, usize)> {
    // Normalise to leaf segment (last `::`/`.` token) for languages that
    // attach module / receiver prefixes in front of the callee text.
    let leaf = callee.rsplit("::").next().unwrap_or(callee);
    let leaf = leaf.rsplit('.').next().unwrap_or(leaf);
    match lang {
        Lang::JavaScript | Lang::TypeScript => {
            if !is_constructor {
                return None;
            }
            // CFG-level rewrite of source-bearing assignments may replace
            // the visible callee with the source path; the original
            // constructor identifier is preserved on `outer_callee`.
            let direct = constructor_type(lang, callee) == Some(TypeKind::Url);
            let via_outer =
                outer_callee.is_some_and(|oc| constructor_type(lang, oc) == Some(TypeKind::Url));
            if direct || via_outer {
                Some((0, 1))
            } else {
                None
            }
        }
        Lang::Python => {
            // `urllib.parse.urljoin(base, path)` and the bare-import
            // `urljoin(base, path)` (`from urllib.parse import urljoin`).
            if callee == "urllib.parse.urljoin" || leaf == "urljoin" {
                Some((1, 0))
            } else {
                None
            }
        }
        Lang::Go => {
            // `url.JoinPath(base, paths...)` and the receiver form
            // `(*URL).JoinPath(base, paths...)` — both expose `JoinPath`
            // as the leaf segment.  `(*URL).Parse(ref)` (single-arg
            // resolve against a base URL receiver) is not modelled here
            // because the base lives on the receiver rather than at a
            // positional arg.
            if leaf == "JoinPath" {
                Some((1, 0))
            } else {
                None
            }
        }
        Lang::Java => {
            // `new URL(URL context, String spec)` — context (base) at
            // arg 0, spec (path) at arg 1.  Only the explicit
            // (context, spec) two-arg constructor form is recognised;
            // `new URL(String spec)` and `new URI(String spec)` carry a
            // single string literal that the generic abstract-string
            // path already handles via `SsaOp::Const` seeding.
            if is_constructor && (leaf == "URL" || leaf == "URI") {
                Some((1, 0))
            } else {
                None
            }
        }
        Lang::Ruby => {
            // `URI.join(base, *paths)` — base at arg 0, first path at arg 1.
            if callee == "URI.join" || (leaf == "join" && callee.contains("URI")) {
                Some((1, 0))
            } else {
                None
            }
        }
        // PHP / Rust / C / C++: no first-class (base, path) URL builder
        // function the engine recognises.  Single-arg shapes (e.g.
        // `Url::parse("https://api/" . $tainted)`) flow through the
        // generic abstract-string concat prefix path.
        _ => None,
    }
}

/// True when the `(base, path)` builder appends its path arguments as path
/// segments instead of resolving them as a URL reference.  Go `url.JoinPath`
/// does: no element can change the host, so the base origin stays pinned.
/// The other builders resolve a reference, where an absolute or
/// protocol-relative path replaces the host.
pub(crate) fn url_builder_appends_path(lang: Lang) -> bool {
    lang == Lang::Go
}

/// Callee texts at least this long are memoised by
/// [`normalized_callee_head`].
const CALLEE_MEMO_MIN_LEN: usize = 192;
/// Per-thread byte budget for memoised callee texts (keys plus values).
const CALLEE_MEMO_MAX_BYTES: usize = 4 << 20;

#[derive(Default)]
struct CalleeMemo {
    map: rustc_hash::FxHashMap<Box<str>, Box<str>>,
    bytes: usize,
}

thread_local! {
    static CALLEE_MEMO: std::cell::RefCell<CalleeMemo> = std::cell::RefCell::new(CalleeMemo::default());
}

/// Chained-call normalization of `callee`, cut at the first remaining `(`.
///
/// Callee texts of chained JS calls can embed whole callback bodies
/// (`wrap(function(){...}).then`), and every call instruction asks several
/// predicates (`is_int_producing_callee`, `is_safe_string_producing_callee`,
/// the constructor matchers) about the same text, each of which re-scans it
/// in full.  The result is a pure function of the text, so long texts are
/// memoised per thread; short texts, the common case, skip the table.
fn normalized_callee_head(callee: &str) -> String {
    fn compute(callee: &str) -> String {
        let mut cur = crate::labels::normalize_chained_call_for_classify(callee);
        if let Some(p) = cur.find('(') {
            cur.truncate(p);
        }
        cur
    }
    if callee.len() < CALLEE_MEMO_MIN_LEN {
        return compute(callee);
    }
    CALLEE_MEMO.with(|m| {
        let Ok(mut memo) = m.try_borrow_mut() else {
            return compute(callee);
        };
        if let Some(hit) = memo.map.get(callee) {
            return hit.to_string();
        }
        let value = compute(callee);
        let cost = callee.len() + value.len();
        if memo.bytes + cost > CALLEE_MEMO_MAX_BYTES {
            memo.map.clear();
            memo.bytes = 0;
        }
        memo.bytes += cost;
        memo.map.insert(callee.into(), value.as_str().into());
        value
    })
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
    peel_suffix_with(callee, is_identity_method)
}

/// [`peel_identity_suffix`] with a caller-chosen set of peelable trailing
/// methods, for consumers that see through more adapters than the type facts
/// do (`map_err`, `context`).
pub fn peel_suffix_with(callee: &str, peelable: impl Fn(&str) -> bool) -> String {
    // Normalize, then strip any trailing paren group (e.g.
    // `Connection::open("app.db")` with no subsequent segment) so the base
    // text ends at the constructor.
    let mut cur = normalized_callee_head(callee);
    while let Some(dot_idx) = cur.rfind('.') {
        let tail = &cur[dot_idx + 1..];
        if !peelable(tail) {
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
    REQWEST_CLIENT_VERBS.iter().any(|v| {
        base.ends_with(&format!("Client::new.{v}")) || base.ends_with(&format!("Client::{v}"))
    })
}

pub fn is_identity_method(callee: &str) -> bool {
    let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);
    matches!(
        suffix,
        "unwrap" | "expect" | "clone" | "to_owned" | "into" | "as_ref" | "as_mut" | "ok" | "await"
    )
}

/// True when `verb` is an ORM queryset chain method that returns another
/// queryset of the same logical type as the receiver.  Used to propagate
/// `DjangoQuerySet` / `ActiveRecordRelation` type facts through chained
/// calls (`qs.filter(...).exclude(...)`) so a terminal verb like `.raw(sql)`
/// / `.find_by_sql(sql)` resolves via the type-qualified sink rule.
pub fn is_orm_queryset_chain_method(verb: &str) -> bool {
    matches!(
        verb,
        // Django queryset chain methods (subset that returns QuerySet)
        "all"
            | "filter"
            | "exclude"
            | "order_by"
            | "annotate"
            | "distinct"
            | "select_related"
            | "prefetch_related"
            | "only"
            | "defer"
            | "reverse"
            | "none"
            | "using"
            | "values"
            | "values_list"
            // ActiveRecord relation chain methods (subset that returns Relation)
            | "where"
            | "joins"
            | "includes"
            | "preload"
            | "eager_load"
            | "references"
            | "group"
            | "having"
            | "limit"
            | "offset"
            | "lock"
            | "readonly"
            | "rewhere"
            | "unscope"
    )
}

/// Map a Rust type-annotation fragment — from a `let x: T = …` binding or a
/// `s.parse::<T>()` turbofish — to the lattice [`TypeKind`] it denotes.
///
/// Resolves the long-standing ambiguity of the Rust `str::parse` verb, which
/// `is_int_producing_callee` otherwise tags `Int` by default (the callee text
/// alone cannot name the `FromStr` target).  Two real shapes drive this:
///   * `let port: u16 = s.parse()?` / `s.parse::<u16>()` → `Int` (precision:
///     a numeric port flowing into a shell arg stays suppressed).
///   * `let p: PathBuf = s.parse()?` / `s.parse::<PathBuf>()` → `Object`
///     (recall: a parsed filesystem path is not numeric, so `fs::read(p)`
///     must still fire `FILE_IO`).
///
/// Returns `None` for any unrecognised named type (custom structs, numeric
/// newtypes like `UserId`, bare generics) so the conservative bare-`parse`
/// → `Int` default is preserved and no new false positive is introduced on
/// e.g. `let id: UserId = s.parse()?` shapes that flow into SQL.
pub fn rust_annotation_type_kind(text: &str) -> Option<TypeKind> {
    // Strip leading reference / lifetime / `mut` markers so `&'a mut PathBuf`
    // exposes `PathBuf`.
    let mut s = text.trim();
    loop {
        if let Some(rest) = s.strip_prefix('&') {
            let rest = rest.trim_start();
            // Optional lifetime label `'a` / `'static` / `'_`.
            let rest = if let Some(after) = rest.strip_prefix('\'') {
                let end = after
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(after.len());
                after[end..].trim_start()
            } else {
                rest
            };
            s = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
            continue;
        }
        if let Some(rest) = s.strip_prefix("mut ") {
            s = rest.trim_start();
            continue;
        }
        break;
    }
    // Numeric / bool / string scalars.  Floats join `Int` (the suppression
    // policy treats both as non-payload-bearing numerics).
    match s {
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" | "f32" | "f64" => return Some(TypeKind::Int),
        "bool" => return Some(TypeKind::Bool),
        "String" | "str" | "char" => return Some(TypeKind::String),
        _ => {}
    }
    // Drop module-path prefix + generic args to the head identifier
    // (`std::path::PathBuf` → `PathBuf`, `url::Url` → `Url`).
    let head = s.rsplit("::").next().unwrap_or(s);
    let head = head.split('<').next().unwrap_or(head).trim();
    match head {
        // Known non-numeric std payload-bearing types.  A value parsed into
        // one of these can carry path / host metacharacters, so it must NOT
        // be tagged `Int` (which would suppress FILE_IO / SSRF).  `Object`
        // is a known, non-suppressing kind: it overrides the bare-`parse`
        // → `Int` heuristic without claiming a security-relevant type.
        "PathBuf" | "Path" | "OsString" | "OsStr" | "IpAddr" | "Ipv4Addr" | "Ipv6Addr"
        | "SocketAddr" | "SocketAddrV4" | "SocketAddrV6" => Some(TypeKind::Object),
        // A `url::Url` / `http::Uri` parse target — dedicated security type
        // so type-qualified SSRF resolution still applies downstream.
        "Url" | "Uri" => Some(TypeKind::Url),
        // Unrecognised: leave the default heuristic in charge.
        _ => None,
    }
}

/// Extract the inner type text `T` of a Rust `parse::<T>()` turbofish from a
/// (possibly chained) callee string, balancing nested `<...>` so
/// `parse::<Vec<u8>>()` yields `Vec<u8>`.  Returns `None` when no turbofish
/// `parse::<` segment is present (the `parse` token must sit on a `.`/`:`
/// boundary so `reparse::<…>` does not match).
fn parse_turbofish_arg(callee: &str) -> Option<&str> {
    const NEEDLE: &str = "parse::<";
    let mut search_from = 0usize;
    let idx = loop {
        let rel = callee[search_from..].find(NEEDLE)?;
        let abs = search_from + rel;
        let on_boundary =
            abs == 0 || matches!(callee.as_bytes()[abs - 1], b'.' | b':' | b' ' | b'(');
        if on_boundary {
            break abs;
        }
        search_from = abs + NEEDLE.len();
    };
    let after = &callee[idx + NEEDLE.len()..];
    let mut depth = 1usize;
    for (i, c) in after.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(after[..i].trim());
                }
            }
            _ => {}
        }
    }
    // Unterminated turbofish (truncated callee text): take the remainder.
    Some(after.trim())
}

/// True when `callee` is a call whose result is numeric in `lang`.
///
/// `lang` gates the one ambiguous suffix, bare `parse`.  Rust `str::parse` is
/// numeric in most real code, so it keeps the `Int` default there (and on the
/// lang-less `None` path).  Everywhere else a `.parse` method is a parser
/// that returns an object or markup built from its input (`JSON.parse`,
/// `url.parse`, `qs.parse`, `yaml.parse`, `marked.parse`, `Jsoup.parse`), so
/// tagging it `Int` would hide every sink fed by the parsed value.  The one
/// numeric exception outside Rust is JS `Date.parse`, which returns
/// milliseconds since the epoch.
pub fn is_int_producing_callee(lang: Option<Lang>, callee: &str) -> bool {
    // Rust `s.parse::<T>()` turbofish: an explicit `FromStr` target is ground
    // truth, so trust it over the conservative bare-`parse` → `Int` default.
    // A recognised numeric `T` → `Int`; a recognised non-numeric `T`
    // (`PathBuf` / `IpAddr` / `Url` / …) or an unrecognised explicit `T` →
    // NOT `Int`, so FILE_IO / SSRF / SHELL on the parsed value is not
    // silently suppressed.  (`peel_identity_suffix` truncates at `<`, so the
    // turbofish is invisible to the suffix match below — read it here from
    // the raw callee.)
    if let Some(inner) = parse_turbofish_arg(callee) {
        return matches!(rust_annotation_type_kind(inner), Some(TypeKind::Int));
    }
    // Peel trailing identity methods (e.g. `.unwrap()`/`.expect("...")` after
    // `.parse()`) so the underlying numeric-producing verb is exposed.
    let base = peel_identity_suffix(callee);
    // `peel_identity_suffix` normalizes a turbofish callee by truncating at
    // `<`, which leaves a trailing `::` (e.g. `s.parse::<u32>()` →
    // `s.parse::`).  Trim trailing path separators so the method suffix is
    // recovered (`parse`) instead of an empty segment.
    // Trim the trailing path separators a turbofish callee leaves behind:
    // `peel_identity_suffix` truncates at `<`, so `s.parse::<u32>()` →
    // `s.parse::`.  Trimming recovers the method suffix (`parse`) instead of
    // an empty segment.
    let trimmed = base.trim_end_matches([':', '.']);
    let suffix = trimmed.rsplit(['.', ':']).next().unwrap_or(trimmed);
    // Zero-argument numeric-length accessors (`s.length()`, `list.size()`,
    // `vec.len()`, `xs.count()`) produce an integer in every grammar we scan.
    // The CFG detector already pins `TypeKind::Int` on the *binding* shape
    // (`int n = s.length();` sets `NodeInfo::is_numeric_length_access`), but an
    // accessor written inline inside a sink argument — `res.setHeader("X-Len",
    // String.valueOf(rendered.length()))` — never lowers to its own SSA value,
    // so the Int fact has nothing to attach to and only the callee-text
    // predicates (`cfg::count_confined_idents_into`,
    // `apply_arg_type_safe_suppression`) can still see it.  Reuse the single
    // narrow property list instead of restating it so both grains stay in
    // lock-step.
    if crate::cfg::is_numeric_length_property(suffix) {
        return true;
    }
    if suffix == "parse" {
        // Rust: `.parse::<N>()` / `let n: u32 = s.parse()?` is conservative
        // (most `str::parse` targets are numeric).  The callee text alone
        // cannot tell `s.parse()` into a `u32` from one into a `PathBuf`;
        // the turbofish branch above and the `let p: PathBuf` annotation in
        // `analyze_types` override this default when the target is spelled
        // out (`type_facts_suppress_int_typed_shell_arg` pins the u16 port
        // case).
        return match lang {
            None | Some(Lang::Rust) => true,
            Some(Lang::JavaScript | Lang::TypeScript) => {
                trimmed == "Date.parse" || trimmed.ends_with(".Date.parse")
            }
            Some(_) => false,
        };
    }
    matches!(
        suffix,
        "parseInt" | "parseFloat" | "Number"        // JS/TS
        | "int" | "float" | "ord"                    // Python
        | "parseLong" | "parseDouble" | "parseShort" // Java
        | "Atoi" | "ParseInt" | "ParseFloat"         // Go
        | "intval" | "floatval"                       // PHP
        | "to_i" | "to_f" // Ruby
    )
}

/// True when `callee` produces a string value that is provably free of
/// CRLF / quote / shell-metacharacter / SQL-quote payloads ,  the
/// canonical "safe-by-construction string" idiom.  Used as a stealth
/// type-fact upgrade so the resulting SSA value is tagged as
/// [`TypeKind::Int`] and the type-suppressible sink mask
/// (HEADER_INJECTION / OPEN_REDIRECT / SQL_QUERY / ...) fires on
/// idiomatic Java patterns:
///
/// ```java
/// res.setHeader("X-Count", Integer.toString(payload.size()));
/// res.setHeader("X-Class", loaded.getClass().getName());
/// ```
///
/// Coverage:
/// * Numeric-to-string converters: `Integer.toString` / `Long.toString`
///   / `Float.toString` / `Double.toString` / `Short.toString` /
///   `Byte.toString` / `Boolean.toString` / `Character.toString` ,
///   output is `[+-]?\d+(\.\d+)?` / `"true"` / `"false"` / `"NaN"` /
///   `"Infinity"`, none of which can carry CRLF or injection metachars.
/// * `String.valueOf` is deliberately **not** covered.  Its `String` /
///   `Object` overloads return the argument verbatim (or its arbitrary
///   `toString()`), so `String.valueOf(req.getParameter("x"))` is an
///   identity passthrough — recognising it as a safe-string producer
///   silently suppressed real injections.  The callee text alone cannot
///   distinguish the safe numeric overload from the identity form, so the
///   whole family is left unrecognised (soundness over precision).
/// * `Class.getName` / `Class.getSimpleName` / `Class.getCanonicalName`
///   ,  the JVM class-name grammar disallows CRLF, quotes, slashes,
///   spaces, and shell metacharacters; the dot-separated FQCN is safe
///   for header / shell / SQL / file / HTML / SSRF sinks.
///
/// * Go `strconv.Itoa` / `FormatInt` / `FormatUint` / `FormatBool` /
///   `FormatFloat`, statically typed numeric / boolean formatters whose
///   output is digits, a sign, `.`, an exponent, `true` / `false`, `NaN`
///   or `Inf`.  Matched on the bare `strconv` package qualifier only.
///
/// Receiver shape match: also accepts the chained form
/// `<expr>.getClass().getName()` whose collapsed callee text contains
/// `.getClass()` followed by the class-name accessor.
pub fn is_safe_string_producing_callee(callee: &str) -> bool {
    let base = peel_identity_suffix(callee);
    // Last segment after `::` (Rust/Ruby) ,  Java callees normalise
    // through `.` only, but the same peeling is harmless for cross-lang
    // input.
    let after_colons = base.rsplit("::").next().unwrap_or(&base);
    if let Some((prefix, method)) = after_colons.rsplit_once('.') {
        if prefix == "strconv"
            && matches!(
                method,
                "Itoa" | "FormatInt" | "FormatUint" | "FormatBool" | "FormatFloat"
            )
        {
            return true;
        }
        let class_name = prefix.rsplit(['.', ' ']).next().unwrap_or(prefix);
        match (class_name, method) {
            (
                "Integer" | "Long" | "Float" | "Double" | "Short" | "Byte" | "Boolean"
                | "Character",
                "toString",
            ) => return true,
            // `String.valueOf` is NOT safe-by-construction: while the
            // primitive overloads (`valueOf(int)` / `valueOf(boolean)` /
            // `valueOf(char)`) emit digit / boolean / single-char text,
            // `valueOf(String s)` returns `s` *verbatim* and the
            // `valueOf(Object o)` overload returns `o.toString()` whose
            // shape is arbitrary.  The callee text (`String.valueOf`)
            // carries no argument-type signal, so we cannot tell the safe
            // numeric form from the identity form here.  Tagging it as a
            // safe-string producer suppressed real injections like
            // `stmt.execute(String.valueOf(req.getParameter("x")))`
            // (the suppression consumer `apply_arg_type_safe_suppression`
            // drops the tainted arg at the sink).  Erring toward soundness:
            // `String.valueOf` is left unrecognised, so the numeric
            // mitigation shape (`String.valueOf(payload.size())`) is no
            // longer auto-suppressed but no injection is silently dropped.
            ("Class", "getName" | "getSimpleName" | "getCanonicalName") => return true,
            _ => {}
        }
    }
    // Chained `<expr>.getClass().<accessor>()` form.  The Java arm of
    // `call_ident_of` preserves the inner `.getClass` segment in the
    // collapsed chain text (e.g. `loaded.getClass.getName`), so a
    // contains-check on `.getClass.` suffices to disambiguate from
    // user-defined `getName` methods on unrelated classes.
    let suffix = after_colons
        .rsplit(['.', ':'])
        .next()
        .unwrap_or(after_colons);
    matches!(suffix, "getName" | "getSimpleName" | "getCanonicalName")
        && (after_colons.contains(".getClass.") || after_colons.contains(".getClass()"))
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
/// True when a numeric / safe-string producing Call op stands for a larger
/// expression with another variable operand beside the call: the op's value
/// is then that expression (typically a string concatenation), not the
/// producer's number.  Operands wrapped by a producer of their own, and
/// operands already typed numeric, keep the expression numeric.
fn operand_beside_numeric_call(
    cfg: &Cfg,
    inst: &SsaInst,
    body: &SsaBody,
    facts: &HashMap<SsaValue, TypeFact>,
    lang: Option<Lang>,
) -> bool {
    let SsaOp::Call { args, receiver, .. } = &inst.op else {
        return false;
    };
    let Some(tree) = cfg
        .node_weight(inst.cfg_node)
        .and_then(|ni| ni.call.nested_calls.as_deref())
    else {
        return false;
    };
    let producer = |c: &str| is_int_producing_callee(lang, c) || is_safe_string_producing_callee(c);
    args.iter().flatten().chain(receiver.iter()).any(|v| {
        let numeric = facts
            .get(v)
            .is_some_and(|f| matches!(f.kind, TypeKind::Int | TypeKind::Bool));
        !numeric
            && body
                .value_defs
                .get(v.0 as usize)
                .and_then(|d| d.var_name.as_deref())
                .is_some_and(|n| tree.occurs_beside_anchor(n, producer))
    })
}

/// Declared type of a Go binding that does not lower to a call:
/// `var sb strings.Builder` (a `Nop`), `c := http.Client{}` (a `Const`),
/// `c := &http.Client{Timeout: t}` (an `Assign` over the field values).
/// The CFG node's `decl_type` ([`crate::cfg::NodeInfo::decl_type`]) is the
/// ground truth for these; the operands of a composite literal say nothing
/// about the type of the value it builds.  Calls consult `decl_type` in their
/// own arm, after the constructor table.
fn go_binding_decl_type(inst: &SsaInst, cfg: &Cfg, lang: Option<Lang>) -> Option<TypeKind> {
    if lang != Some(Lang::Go)
        || inst.var_name.is_none()
        || !matches!(inst.op, SsaOp::Const(_) | SsaOp::Nop | SsaOp::Assign(_))
    {
        return None;
    }
    cfg.node_weight(inst.cfg_node)?.decl_type.clone()
}

pub fn analyze_types(
    body: &SsaBody,
    cfg: &Cfg,
    consts: &ConstValues,
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
    consts: &ConstValues,
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
            if let Some(dt) = go_binding_decl_type(inst, cfg, lang) {
                facts.insert(inst.value, TypeFact::from_kind(dt));
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
                SsaOp::Call {
                    callee,
                    callee_text,
                    args,
                    ..
                } => {
                    // For the Rust `.parse()` numeric-turbofish gate (see
                    // `is_int_producing_callee`) the discriminating
                    // `::<T>` lives in the *original* callee text, which SSA
                    // moves into `callee_text` when it decomposes a chained
                    // receiver (`x.parse::<u32>()` → `callee = "parse"`,
                    // `callee_text = Some("x.parse::<u32>")`).  Prefer the
                    // full text so the turbofish survives; `callee` is the
                    // canonical fallback when no decomposition occurred.
                    let callee_for_int = callee_text.as_deref().unwrap_or(callee);
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
                    // The CFG-level text-rewrite for source-bearing
                    // assignments (`const u = new URL(req.body.path, …)`
                    // → `callee` becomes `req.body.path`) strips the
                    // visible constructor identifier, so when the direct
                    // `callee` mapping fails fall back to
                    // `info.call.outer_callee` which preserves the
                    // original (e.g. `URL`) for type inference.
                    let outer_callee = cfg
                        .node_weight(inst.cfg_node)
                        .and_then(|ni| ni.call.outer_callee.clone());
                    let constructor_ty = lang.and_then(|l| {
                        constructor_type(l, callee).or_else(|| {
                            outer_callee
                                .as_deref()
                                .and_then(|oc| constructor_type(l, oc))
                        })
                    });
                    if null_proto {
                        TypeFact::from_kind(TypeKind::NullPrototypeObject)
                    } else if let Some(ty) = constructor_ty {
                        TypeFact::from_kind(ty)
                    } else if let Some(ty) =
                        lang.and_then(|l| arg_aware_call_type(l, callee, args, consts))
                    {
                        TypeFact::from_kind(ty)
                    } else if let Some(dt) = cfg
                        .node_weight(inst.cfg_node)
                        .and_then(|ni| ni.decl_type.clone())
                    {
                        // A declared `let x: T = …` binding annotation is
                        // ground truth for the bound value's type — strictly
                        // more authoritative than the bare-`parse` → `Int`
                        // heuristic below.  Fixes `let p: PathBuf =
                        // s.parse()?; fs::read(p)` (recall: `Object`, not
                        // suppressed) while keeping `let port: u16 =
                        // s.parse()?` numeric (precision).  Placed after the
                        // constructor / arg-aware paths so security-typed
                        // constructors (`Client::new()` → `HttpClient`) still
                        // win the type-qualified resolution.
                        TypeFact::from_kind(dt)
                    } else if (is_int_producing_callee(lang, callee_for_int)
                        || is_safe_string_producing_callee(callee))
                        && operand_beside_numeric_call(cfg, inst, body, &facts, lang)
                    {
                        // `"... id=" + Integer.parseInt(id) + " AND name='" + name`:
                        // the op stands for the whole concatenation, whose
                        // value is a string carrying `name`, not the number
                        // the anchor call returns.
                        TypeFact::unknown()
                    } else if is_int_producing_callee(lang, callee_for_int) {
                        TypeFact::from_kind(TypeKind::Int)
                    } else if is_safe_string_producing_callee(callee) {
                        // Numeric/boolean to-string converters and class-name
                        // accessors emit a string provably free of CRLF and
                        // injection metacharacters.  Tag as `Int` so the
                        // shared type-suppressible sink mask treats the
                        // value as non-payload-bearing for HEADER_INJECTION
                        // / OPEN_REDIRECT / SQL_QUERY / FILE_IO / SHELL /
                        // HTML / SSRF / DATA_EXFIL.
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

            // ORM queryset chain propagation.  `Model.objects.filter(...)`
            // / `qs.exclude(...)` / `qs.all()` etc. return a `QuerySet` of
            // the same logical type as the receiver.  When the receiver
            // carries a `DjangoQuerySet` fact and the callee verb is one of
            // the QuerySet-returning chain methods, propagate the fact to
            // the result so a later `qs2.raw(sql)` / `qs2.extra(sql)` resolves
            // via the type-qualified rule.  Gated on the receiver type to
            // keep the FP surface bounded.
            for inst in &block.body {
                if let SsaOp::Call {
                    callee,
                    receiver: Some(recv),
                    ..
                } = &inst.op
                {
                    let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);
                    if !is_orm_queryset_chain_method(suffix) {
                        continue;
                    }
                    let recv_fact = facts.get(recv).cloned().unwrap_or_else(TypeFact::unknown);
                    let propagate = matches!(
                        recv_fact.kind,
                        TypeKind::DjangoQuerySet | TypeKind::ActiveRecordRelation
                    );
                    if !propagate {
                        continue;
                    }
                    let current_kind = facts
                        .get(&inst.value)
                        .map(|f| f.kind.clone())
                        .unwrap_or(TypeKind::Unknown);
                    if !matches!(current_kind, TypeKind::Unknown) {
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
                // WHATWG URL alias: a `URL` instance's `searchParams`
                // and identity-projection accessors (`host`, `hostname`,
                // `pathname`, `href`, `origin`) read as the same logical
                // URL for sink/sanitiser dispatch.  Mark the projection
                // as `TypeKind::Url` so a downstream `.set(k, v)` /
                // `.append(k, v)` on the searchParams view dispatches via
                // the URL receiver-type rule rather than as an opaque
                // Object.
                if matches!(recv_fact.kind, TypeKind::Url) && is_url_identity_field(&field_name) {
                    let new_fact = TypeFact::from_kind(TypeKind::Url);
                    if facts.get(&inst.value) != Some(&new_fact) {
                        facts.insert(inst.value, new_fact);
                        changed = true;
                    }
                    continue;
                }
                // Django ORM manager projection.  `Model.objects` decomposes
                // into a FieldProj whose `field` is `objects`.  Tag it as
                // `DjangoQuerySet` so a downstream `qs.raw(sql)` /
                // `qs.extra(sql)` (where `qs = Model.objects`) resolves via
                // the type-qualified `DjangoQuerySet.<method>` sink rule.
                // Strictly additive — fires only when the projection has not
                // already been pinned to another type.
                if matches!(lang, Some(Lang::Python)) && field_name == "objects" {
                    let new_fact = TypeFact::from_kind(TypeKind::DjangoQuerySet);
                    if facts.get(&inst.value) != Some(&new_fact) {
                        facts.insert(inst.value, new_fact);
                        changed = true;
                    }
                    continue;
                }
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
                // whole point of the accessor rule.  A Go declared binding
                // type is kept for the same reason.
                if cfg
                    .node_weight(inst.cfg_node)
                    .is_some_and(|ni| ni.is_numeric_length_access)
                    || go_binding_decl_type(inst, cfg, lang).is_some()
                {
                    continue;
                }
                if let SsaOp::Assign(uses) = &inst.op {
                    // Django ORM manager projection in Assign form.
                    // `qs = Model.objects` lowers to an Assign whose CFG
                    // node carries `member_field = Some("objects")`.  The
                    // FieldProj-chain decomposition only fires when there
                    // is a trailing method call (e.g. `Model.objects.all()`);
                    // the bare-projection shape leaves the Assign with
                    // multiple operands (the path "Model.objects" plus the
                    // unresolved root identifiers), so neither the len==1
                    // copy-prop arm nor the len==2 BinOp arm picks up the
                    // type.  Tag the result as `DjangoQuerySet` directly
                    // when the CFG node's `member_field` is "objects" and
                    // the language is Python; mirrors the FieldProj
                    // second-pass arm above.  Strictly additive: only
                    // fires when the result fact is still Unknown.
                    if matches!(lang, Some(Lang::Python))
                        && cfg
                            .node_weight(inst.cfg_node)
                            .and_then(|ni| ni.member_field.as_deref())
                            == Some("objects")
                    {
                        let current_kind = facts
                            .get(&inst.value)
                            .map(|f| f.kind.clone())
                            .unwrap_or(TypeKind::Unknown);
                        if matches!(current_kind, TypeKind::Unknown) {
                            let new_fact = TypeFact::from_kind(TypeKind::DjangoQuerySet);
                            facts.insert(inst.value, new_fact);
                            changed = true;
                            continue;
                        }
                    }
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

/// True when a Go `fmt.Fprint*` writer value (positional arg 0) is provably
/// **not** an `http.ResponseWriter`, so the reflected-XSS (`HTML_ESCAPE`)
/// sink label does not apply.  Shared by the SSA taint sink gate and the
/// structural `cfg-unguarded-sink` rule so suppressing the finding on one
/// path does not surface the twin false positive on the other.
pub fn go_writer_is_non_response(kind: &TypeKind) -> bool {
    GoInterfaceTable::definitely_not(kind, "http.ResponseWriter")
}

/// Go response-writing sinks whose positional arg 0 is the `io.Writer`
/// written to (`fmt.Fprintf(w, ...)`, `io.WriteString(w, s)`).  The writer,
/// not the payload, decides whether the call renders into a response, so
/// these are the callees the writer gates above apply to.
pub fn is_go_writer_sink_callee(callee: &str) -> bool {
    matches!(
        callee,
        "fmt.Fprintf" | "fmt.Fprint" | "fmt.Fprintln" | "io.WriteString"
    )
}

/// Go writer expressions that are never an `http.ResponseWriter`: the
/// stdlib stdout / stderr / discard streams and gin's package-level
/// `DefaultWriter` / `DefaultErrorWriter` (`io.Writer` aliases for
/// `os.Stdout` / `os.Stderr`), qualified or bare.  A text match because the
/// package-level vars have no local definition to carry a type fact.
pub fn is_go_non_response_writer(text: &str) -> bool {
    matches!(
        text,
        "os.Stderr"
            | "os.Stdout"
            | "io.Discard"
            | "ioutil.Discard"
            | "DefaultErrorWriter"
            | "DefaultWriter"
            | "gin.DefaultErrorWriter"
            | "gin.DefaultWriter"
    )
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
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let consts: ConstValues = [
            (SsaValue(0), ConstLattice::Int(42)),
            (SsaValue(1), ConstLattice::Str("hello".into())),
        ]
        .into_iter()
        .collect();

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
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let consts = ConstValues::default();
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
            Cap::HEADER_INJECTION,
            Cap::OPEN_REDIRECT,
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
            Cap::HEADER_INJECTION,
            Cap::OPEN_REDIRECT,
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
    /// | TypeKind | SQL | FILE | SHELL | HTML | SSRF | DATA_EXFIL | HEADER_INJ | OPEN_REDIR | CODE_EXEC | DESERIALIZE |
    /// |----------|-----|------|-------|------|------|------------|------------|------------|-----------|-------------|
    /// | Int      |  Y  |  Y   |   Y   |  Y   |  Y   |     Y      |     Y      |     Y      |     N     |      N      |
    /// | Bool     |  Y  |  Y   |   Y   |  Y   |  Y   |     Y      |     Y      |     Y      |     N     |      N      |
    /// | String   |  N  |  N   |   N   |  N   |  N   |     N      |     N      |     N      |     N     |      N      |
    /// | Url      |  N  |  N   |   N   |  N   |  N   |     N      |     N      |     N      |     N     |      N      |
    /// | Object   |  N  |  N   |   N   |  N   |  N   |     N      |     N      |     N      |     N     |      N      |
    /// | Unknown  |  N  |  N   |   N   |  N   |  N   |     N      |     N      |     N      |     N     |      N      |
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
            ("HEADER_INJECTION", Cap::HEADER_INJECTION),
            ("OPEN_REDIRECT", Cap::OPEN_REDIRECT),
            ("CODE_EXEC", Cap::CODE_EXEC),
            ("DESERIALIZE", Cap::DESERIALIZE),
        ];
        // (kind_name, kind, [suppress for each cap in `caps` order])
        let rows: &[(&str, TypeKind, [bool; 10])] = &[
            (
                "Int",
                TypeKind::Int,
                [true, true, true, true, true, true, true, true, false, false],
            ),
            (
                "Bool",
                TypeKind::Bool,
                [true, true, true, true, true, true, true, true, false, false],
            ),
            (
                "String",
                TypeKind::String,
                [
                    false, false, false, false, false, false, false, false, false, false,
                ],
            ),
            (
                "Url",
                TypeKind::Url,
                [
                    false, false, false, false, false, false, false, false, false, false,
                ],
            ),
            (
                "Object",
                TypeKind::Object,
                [
                    false, false, false, false, false, false, false, false, false, false,
                ],
            ),
            (
                "Unknown",
                TypeKind::Unknown,
                [
                    false, false, false, false, false, false, false, false, false, false,
                ],
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
            field_writes: Default::default(),

            synthetic_externals: Default::default(),
            slot_scoped_assigns: Default::default(),
        };

        let consts = ConstValues::default();
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

    #[test]
    fn go_writer_is_non_response_discriminates_buffer_from_response() {
        // The shared `fmt.Fprint*` writer-type gate: byte-sink writers are
        // non-response; an `http.ResponseWriter` (or an unknown writer type)
        // is not, so the reflected-XSS label is preserved for real handlers.
        assert!(go_writer_is_non_response(&TypeKind::FileHandle));
        assert!(!go_writer_is_non_response(&TypeKind::HttpResponse));
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
    fn constructor_type_ruby_pg() {
        // Raw `pg` gem connection constructors → DatabaseConnection so the
        // type-qualified `DatabaseConnection.exec` SQL sink resolves
        // (CVE-2026-42087 regression guard).
        assert_eq!(
            constructor_type(Lang::Ruby, "PG::Connection.new"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "PG.connect"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "PGconn.new"),
            Some(TypeKind::DatabaseConnection)
        );
        // A plain method named `new` on an unrelated receiver is not a DB conn.
        assert_eq!(constructor_type(Lang::Ruby, "Widget.new"), None);
        // ActiveRecord adapter handles, class-qualified only.
        assert_eq!(
            constructor_type(Lang::Ruby, "ActiveRecord::Base.connection"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            constructor_type(Lang::Ruby, "User.lease_connection"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(constructor_type(Lang::Ruby, "connection"), None);
        assert_eq!(constructor_type(Lang::Ruby, "client.connection"), None);
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
        // Hibernate Session factory methods.  Suffix-only match — receiver
        // text is irrelevant.
        assert_eq!(
            constructor_type(Lang::Java, "sessionFactory.openSession"),
            Some(TypeKind::HibernateSession)
        );
        assert_eq!(
            constructor_type(Lang::Java, "sessionFactory.getCurrentSession"),
            Some(TypeKind::HibernateSession)
        );
        assert_eq!(
            constructor_type(Lang::Java, "openStatelessSession"),
            Some(TypeKind::HibernateSession)
        );
        assert_eq!(
            TypeKind::HibernateSession.label_prefix(),
            Some("HibernateSession")
        );
    }

    #[test]
    fn constructor_type_java_jdbc_statements() {
        for callee in [
            "conn.createStatement",
            "conn.prepareStatement",
            "this.connection.prepareStatement",
            "conn.prepareCall",
        ] {
            assert_eq!(
                constructor_type(Lang::Java, callee),
                Some(TypeKind::DatabaseConnection),
                "{callee}"
            );
        }
    }

    #[test]
    fn value_wrapper_constructors() {
        for class in [
            "File",
            "java.io.File",
            "String",
            "StringBuilder",
            "java.lang.StringBuffer",
        ] {
            assert!(constructor_is_value_wrapper(Lang::Java, class), "{class}");
        }
        // Stream and reader objects wrap a handle, not the path text, and
        // unknown classes keep the SDK-wrapper narrowing.
        for class in [
            "FileInputStream",
            "BufferedReader",
            "Scanner",
            "Stripe",
            "ArrayList<String>",
        ] {
            assert!(!constructor_is_value_wrapper(Lang::Java, class), "{class}");
        }
        assert!(constructor_is_value_wrapper(Lang::JavaScript, "String"));
        assert!(!constructor_is_value_wrapper(Lang::JavaScript, "Stripe"));
        assert!(!constructor_is_value_wrapper(Lang::Python, "File"));
        assert!(!constructor_is_value_wrapper(Lang::Go, "String"));
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
            constructor_type(Lang::Go, "sql.Open"),
            Some(TypeKind::DatabaseConnection)
        );
    }

    #[test]
    fn go_http_response_and_request_constructors_are_not_clients() {
        // `http.Get` / `http.Post` return a `*http.Response`, `http.NewRequest`
        // a `*http.Request`.  Typing either as a client would turn
        // `resp.Header.Get(k)` into the `HttpClient.Get` SSRF sink.
        for callee in ["http.Get", "http.Post", "http.NewRequest"] {
            assert_eq!(constructor_type(Lang::Go, callee), None, "{callee}");
        }
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
        let consts = ConstValues::default();
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

    /// Audit #3: `String.valueOf` is an identity passthrough for its
    /// `String`/`Object` overloads, so it must NOT be recognised as a
    /// safe-string producer (which would suppress real injections like
    /// `stmt.execute(String.valueOf(req.getParameter("x")))`).  The
    /// genuinely-safe numeric to-string converters and class-name
    /// accessors are still recognised.
    #[test]
    fn string_valueof_not_safe_string_producer() {
        // The defect: must be false now (was unconditionally true).
        assert!(
            !is_safe_string_producing_callee("String.valueOf"),
            "String.valueOf is identity for String/Object overloads — unsound to treat as safe"
        );
        assert!(
            !is_safe_string_producing_callee("java.lang.String.valueOf"),
            "fully-qualified String.valueOf must also be unrecognised"
        );
        // Regression guard: the genuinely safe converters/accessors remain.
        assert!(is_safe_string_producing_callee("Integer.toString"));
        assert!(is_safe_string_producing_callee("Long.toString"));
        assert!(is_safe_string_producing_callee("Boolean.toString"));
        assert!(is_safe_string_producing_callee("Class.getName"));
        assert!(is_safe_string_producing_callee("loaded.getClass().getName"));
    }

    #[test]
    fn go_strconv_formatters_are_safe_string_producers() {
        for callee in [
            "strconv.Itoa",
            "strconv.FormatInt",
            "strconv.FormatUint",
            "strconv.FormatBool",
            "strconv.FormatFloat",
        ] {
            assert!(is_safe_string_producing_callee(callee), "{callee}");
        }
        // `Quote` keeps arbitrary input text, and a non-stdlib package that
        // happens to export `Itoa` is not the stdlib formatter.
        assert!(!is_safe_string_producing_callee("strconv.Quote"));
        assert!(!is_safe_string_producing_callee("util.strconv.Itoa"));
        assert!(!is_safe_string_producing_callee("conv.Itoa"));
    }

    /// Bare Rust `.parse()` is generic over `FromStr` and the callee text
    /// alone cannot name the target, so it is tagged `Int` by default
    /// (precision: a u16 port into a shell arg is suppressed — pinned by
    /// `cfg_analysis::tests::type_facts_suppress_int_typed_shell_arg`).  An
    /// EXPLICIT `parse::<T>()` turbofish, however, names the target: numeric
    /// `T` → `Int`, a recognised non-numeric `T` (`PathBuf` / `IpAddr` /
    /// `Url`) or an unrecognised explicit `T` → NOT `Int` (recall — a parsed
    /// path / host must not be suppressed for FILE_IO / SSRF).  This test
    /// pins the bare default, turbofish discrimination, cross-language
    /// converters, and form robustness.
    #[test]
    fn rust_parse_is_int_producing_and_turbofish_forms_are_robust() {
        // Bare parse and its identity-peeled / receiver-qualified forms — Int.
        assert!(is_int_producing_callee(Some(Lang::Rust), "parse"));
        assert!(is_int_producing_callee(Some(Lang::Rust), "s.parse"));
        assert!(is_int_producing_callee(
            Some(Lang::Rust),
            "parse().unwrap()"
        ));
        // Numeric turbofish forms — Int.
        assert!(is_int_producing_callee(
            Some(Lang::Rust),
            "s.parse::<u32>()"
        ));
        assert!(is_int_producing_callee(
            Some(Lang::Rust),
            "s.parse::<i64>()"
        ));
        assert!(is_int_producing_callee(
            Some(Lang::Rust),
            "contents.trim().parse::<u32>().expect(\"invalid pid\")"
        ));
        // Non-numeric turbofish forms — NOT Int (recall: the parsed value can
        // carry path / host metacharacters).
        assert!(!is_int_producing_callee(
            Some(Lang::Rust),
            "s.parse::<PathBuf>()"
        ));
        assert!(!is_int_producing_callee(
            Some(Lang::Rust),
            "addr.parse::<IpAddr>().unwrap()"
        ));
        assert!(!is_int_producing_callee(
            Some(Lang::Rust),
            "u.parse::<Url>()"
        ));
        // Unrecognised explicit turbofish target — conservatively NOT Int.
        assert!(!is_int_producing_callee(
            Some(Lang::Rust),
            "x.parse::<MyNewtype>()"
        ));
        // Boundary: a method that merely ends in `parse` must not match the
        // turbofish needle (`reparse::<u32>` is not `parse::<u32>`).
        assert!(!is_int_producing_callee(
            Some(Lang::Rust),
            "v.reparse::<Foo>()"
        ));
        // The lang-less path keeps the Rust default.
        assert!(is_int_producing_callee(None, "s.parse"));
        // Other languages' numeric converters remain unconditional.
        assert!(is_int_producing_callee(Some(Lang::JavaScript), "parseInt"));
        assert!(is_int_producing_callee(Some(Lang::JavaScript), "Number"));
        assert!(is_int_producing_callee(Some(Lang::Go), "Atoi"));
        assert!(is_int_producing_callee(Some(Lang::Go), "strconv.ParseInt"));
        assert!(is_int_producing_callee(Some(Lang::Ruby), "x.to_i"));
        // Negative: a non-numeric-producing method must not be Int.
        assert!(!is_int_producing_callee(
            Some(Lang::JavaScript),
            "toUpperCase"
        ));
        assert!(!is_int_producing_callee(Some(Lang::Rust), "trim"));
    }

    /// Outside Rust a `.parse` method is a parser that returns an object or
    /// markup built from its input, not a number.  Tagging it `Int` hid every
    /// sink fed by `JSON.parse` / `url.parse` / `yaml.parse` / `marked.parse`
    /// / fastjson `JSON.parse` / `Jsoup.parse`.  JS `Date.parse` is the one
    /// numeric exception (milliseconds since the epoch).
    #[test]
    fn bare_parse_is_int_only_for_rust_and_js_date_parse() {
        for (lang, callee) in [
            (Lang::JavaScript, "JSON.parse"),
            (Lang::JavaScript, "url.parse"),
            (Lang::JavaScript, "qs.parse"),
            (Lang::TypeScript, "yaml.parse"),
            (Lang::TypeScript, "marked.parse"),
            (Lang::Python, "parser.parse"),
            (Lang::Java, "JSON.parse"),
            (Lang::Java, "Jsoup.parse"),
            (Lang::Java, "LocalDate.parse"),
            (Lang::Php, "Yaml::parse"),
            (Lang::Ruby, "JSON.parse"),
            (Lang::Cpp, "json::parse"),
            (Lang::Go, "tmpl.parse"),
        ] {
            assert!(
                !is_int_producing_callee(Some(lang), callee),
                "{lang:?} `{callee}` must not be Int"
            );
        }
        assert!(is_int_producing_callee(
            Some(Lang::JavaScript),
            "Date.parse"
        ));
        assert!(is_int_producing_callee(
            Some(Lang::TypeScript),
            "globalThis.Date.parse"
        ));
        assert!(!is_int_producing_callee(Some(Lang::Java), "Date.parse"));
        // Rust keeps the bare-`parse` default (dropping it regressed the
        // u16-port-into-shell precision case).
        assert!(is_int_producing_callee(Some(Lang::Rust), "s.parse"));
        assert!(is_int_producing_callee(
            Some(Lang::Rust),
            "port_str.parse().unwrap()"
        ));
    }

    /// `rust_annotation_type_kind` maps `let x: T` / `parse::<T>` annotation
    /// text to the lattice kind: numeric → `Int`, `bool` → `Bool`, string
    /// scalars → `String`, known non-numeric std payload types → `Object`,
    /// `Url`/`Uri` → `Url`, everything else → `None` (preserve the default).
    #[test]
    fn rust_annotation_type_kind_maps_known_targets() {
        use TypeKind::*;
        // Numeric scalars (incl. floats and ref/mut-prefixed forms).
        for t in ["u16", "i64", "usize", "f64", "&mut u32", "&'a u8"] {
            assert_eq!(rust_annotation_type_kind(t), Some(Int), "{t}");
        }
        assert_eq!(rust_annotation_type_kind("bool"), Some(Bool));
        for t in ["String", "&str", "str", "char"] {
            assert_eq!(rust_annotation_type_kind(t), Some(String), "{t}");
        }
        // Known non-numeric std payload types → Object (non-suppressing).
        for t in [
            "PathBuf",
            "std::path::PathBuf",
            "Path",
            "OsString",
            "IpAddr",
            "Ipv4Addr",
            "SocketAddr",
            "&PathBuf",
        ] {
            assert_eq!(rust_annotation_type_kind(t), Some(Object), "{t}");
        }
        // Url / Uri keep a dedicated security kind.
        assert_eq!(rust_annotation_type_kind("Url"), Some(Url));
        assert_eq!(rust_annotation_type_kind("url::Url"), Some(Url));
        assert_eq!(rust_annotation_type_kind("http::Uri"), Some(Url));
        // Unrecognised named types / generics / containers → None so the
        // bare-`parse` default and downstream inference stay in charge.
        for t in ["UserId", "MyStruct", "T", "Vec<u8>", "Foo<Bar>"] {
            assert_eq!(rust_annotation_type_kind(t), None, "{t}");
        }
    }

    /// `parse_turbofish_arg` extracts the inner `T` of `parse::<T>()`,
    /// balancing nested generics and respecting token boundaries.
    #[test]
    fn parse_turbofish_arg_extracts_inner_type() {
        assert_eq!(parse_turbofish_arg("s.parse::<u32>()"), Some("u32"));
        assert_eq!(
            parse_turbofish_arg("a.b().parse::<PathBuf>().unwrap()"),
            Some("PathBuf")
        );
        // Nested generics balance to the matching `>`.
        assert_eq!(parse_turbofish_arg("x.parse::<Vec<u8>>()"), Some("Vec<u8>"));
        // Truncated (peeled) callee text — take the remainder after `<`.
        assert_eq!(parse_turbofish_arg("s.parse::<u32"), Some("u32"));
        // No turbofish, or a non-boundary `parse` token.
        assert_eq!(parse_turbofish_arg("s.parse()"), None);
        assert_eq!(parse_turbofish_arg("reparse::<Foo>()"), None);
    }

    #[test]
    fn java_string_builder_constructors_are_typed() {
        for callee in ["StringBuilder", "StringBuffer", "java.lang.StringBuilder"] {
            assert_eq!(
                constructor_type(Lang::Java, callee),
                Some(TypeKind::StringBuilder),
                "{callee}"
            );
        }
    }
}

//! Constraint solver: apply conditions to [`PathEnv`] and check satisfiability.
//!
//! The solver operates on structured [`ConditionExpr`] values, never on raw
//! text. Negation is always structural (via [`ConditionExpr::negate`] /
//! [`CompOp::negate`]), not via a generic "negate ValueFact" operation.

use crate::ssa::type_facts::TypeKind;

use super::domain::{BoolState, ConstValue, Nullability, PathEnv, RelOp, TypeSet, ValueFact};
use super::lower::{CompOp, ConditionExpr, Operand};

/// Apply a condition to a [`PathEnv`], producing the refined environment
/// for the branch where the condition has the given polarity.
///
/// `polarity = true`: condition holds (true branch).
/// `polarity = false`: condition does NOT hold (false branch), negate
/// the condition structurally, then apply.
pub fn refine_env(env: &PathEnv, cond: &ConditionExpr, polarity: bool) -> PathEnv {
    if env.is_unsat() {
        return env.clone();
    }

    let effective = if polarity {
        cond.clone()
    } else {
        cond.negate()
    };

    let mut result = env.clone();
    apply_condition(&mut result, &effective);
    result
}

/// Check if a [`PathEnv`] is satisfiable.
///
/// Unsatisfiability is detected incrementally during [`PathEnv::refine`],
/// so this is just a flag check.
pub fn is_satisfiable(env: &PathEnv) -> bool {
    !env.is_unsat()
}

// ── Internal dispatch ───────────────────────────────────────────────────

fn apply_condition(env: &mut PathEnv, cond: &ConditionExpr) {
    match cond {
        ConditionExpr::NullCheck { var, is_null } => {
            let mut fact = ValueFact::top();
            if *is_null {
                fact.null = Nullability::Null;
                fact.types = TypeSet::singleton(&TypeKind::Null);
            } else {
                fact.null = Nullability::NonNull;
            }
            env.refine(*var, &fact);
        }

        ConditionExpr::TypeCheck {
            var,
            type_name,
            positive,
        } => {
            if let Some(kind) = parse_type_name(type_name) {
                let ts = TypeSet::singleton(&kind);
                let mut fact = ValueFact::top();
                if *positive {
                    fact.types = ts;
                    if kind != TypeKind::Null {
                        fact.null = Nullability::NonNull;
                    }
                } else {
                    fact.types = ts.complement();
                }
                env.refine(*var, &fact);
            }
            // Unknown type name → no refinement (conservative)
        }

        ConditionExpr::BoolTest { var } => {
            // Conservative: only refine NonNull for known boolean-typed values.
            // Truthiness is language-specific (0, "", empty containers are
            // falsy in some languages). Over-constraining would be unsound.
            //
            // We check the existing fact: if the value is already known
            // boolean-typed, we can safely refine to True.
            let existing = env.get(*var);
            if existing.types == TypeSet::singleton(&TypeKind::Bool) {
                let mut fact = ValueFact::top();
                fact.bool_state = BoolState::True;
                fact.null = Nullability::NonNull;
                env.refine(*var, &fact);
            }
            // Otherwise: no refinement (conservative)
        }

        ConditionExpr::Comparison { lhs, op, rhs } => {
            apply_comparison(env, lhs, *op, rhs);
        }

        ConditionExpr::Unknown => {
            // No information, no refinement
        }
    }
}

fn apply_comparison(env: &mut PathEnv, lhs: &Operand, op: CompOp, rhs: &Operand) {
    match (lhs, rhs) {
        (Operand::Value(v), Operand::Const(c)) => {
            apply_value_const(env, *v, op, c);
        }
        (Operand::Const(c), Operand::Value(v)) => {
            // Flip: const op var → var (flipped_op) const
            apply_value_const(env, *v, op.flip(), c);
        }
        (Operand::Value(a), Operand::Value(b)) => match op {
            CompOp::Eq => env.assert_equal(*a, *b),
            CompOp::Neq => env.assert_not_equal(*a, *b),
            CompOp::Lt => env.assert_relational(*a, RelOp::Lt, *b),
            CompOp::Gt => env.assert_relational(*b, RelOp::Lt, *a),
            CompOp::Le => env.assert_relational(*a, RelOp::Le, *b),
            CompOp::Ge => env.assert_relational(*b, RelOp::Le, *a),
        },
        // At least one Unknown operand: no refinement
        _ => {}
    }
}

/// Apply a value-vs-constant comparison to the environment.
fn apply_value_const(env: &mut PathEnv, v: crate::ssa::ir::SsaValue, op: CompOp, c: &ConstValue) {
    let mut fact = ValueFact::top();

    match op {
        CompOp::Eq => {
            fact.exact = Some(c.clone());
            match c {
                ConstValue::Int(i) => {
                    fact.lo = Some(*i);
                    fact.hi = Some(*i);
                    fact.types = TypeSet::singleton(&TypeKind::Int);
                    fact.null = Nullability::NonNull;
                }
                ConstValue::Null => {
                    fact.null = Nullability::Null;
                    fact.types = TypeSet::singleton(&TypeKind::Null);
                }
                ConstValue::Bool(b) => {
                    fact.bool_state = if *b {
                        BoolState::True
                    } else {
                        BoolState::False
                    };
                    fact.types = TypeSet::singleton(&TypeKind::Bool);
                    fact.null = Nullability::NonNull;
                }
                ConstValue::Str(_) => {
                    fact.types = TypeSet::singleton(&TypeKind::String);
                    fact.null = Nullability::NonNull;
                }
            }
        }
        CompOp::Neq => {
            if c == &ConstValue::Null {
                fact.null = Nullability::NonNull;
            }
            fact.excluded.push(c.clone());
        }
        CompOp::Lt => {
            if let ConstValue::Int(i) = c {
                fact.hi = Some(*i);
                fact.hi_strict = true;
                fact.null = Nullability::NonNull;
            }
            // Non-Int Lt: no refinement (V1)
        }
        CompOp::Le => {
            if let ConstValue::Int(i) = c {
                fact.hi = Some(*i);
                fact.null = Nullability::NonNull;
            }
        }
        CompOp::Gt => {
            if let ConstValue::Int(i) = c {
                fact.lo = Some(*i);
                fact.lo_strict = true;
                fact.null = Nullability::NonNull;
            }
        }
        CompOp::Ge => {
            if let ConstValue::Int(i) = c {
                fact.lo = Some(*i);
                fact.null = Nullability::NonNull;
            }
        }
    }

    env.refine(v, &fact);
}

/// Map typeof / type-name strings to [`TypeKind`].
///
/// Resolution order:
/// 1. Cross-language primitive aliases (case-insensitive)
/// 2. Java/Ruby/Go class and framework names (case-sensitive)
/// 3. Java type hierarchy fallback (case-sensitive, via [`crate::ssa::type_facts::TypeHierarchy`])
pub fn parse_type_name(name: &str) -> Option<TypeKind> {
    use crate::ssa::type_facts::TypeHierarchy;

    primitive_type_alias(name)
        .or_else(|| class_name_to_type_kind(name))
        .or_else(|| TypeHierarchy::resolve_kind(name))
}

/// Tier 1: Cross-language primitive type aliases (case-insensitive).
fn primitive_type_alias(name: &str) -> Option<TypeKind> {
    match name.to_ascii_lowercase().as_str() {
        "string" | "str" => Some(TypeKind::String),
        "number" | "int" | "integer" | "i32" | "i64" | "u32" | "u64" | "float" | "double"
        | "numeric" => Some(TypeKind::Int),
        "boolean" | "bool" => Some(TypeKind::Bool),
        "object" => Some(TypeKind::Object),
        "array" | "list" => Some(TypeKind::Array),
        "null" | "nil" | "none" | "undefined" => Some(TypeKind::Null),
        _ => None,
    }
}

/// Tier 2: Java/Ruby/Go class and framework type names (case-sensitive).
pub fn class_name_to_type_kind(name: &str) -> Option<TypeKind> {
    match name {
        "String" | "CharSequence" | "StringBuilder" | "StringBuffer" => Some(TypeKind::String),
        "Integer" | "Long" | "Short" | "Byte" | "Number" | "BigInteger" | "BigDecimal"
        | "Double" | "Float" => Some(TypeKind::Int),
        "Boolean" => Some(TypeKind::Bool),
        "List" | "ArrayList" | "Collection" | "Set" | "HashSet" => Some(TypeKind::Array),
        "URL" | "URI" => Some(TypeKind::Url),
        // Framework HTTP clients, also listed in JAVA_HIERARCHY (type_facts.rs)
        // for subtype resolution. Both locations needed: this function is called
        // directly by the constraint solver, while the hierarchy provides
        // is_subtype_of() for instanceof checks.
        "HttpClient" | "CloseableHttpClient" | "OkHttpClient" | "WebClient"
        | "RestTemplate" => Some(TypeKind::HttpClient),
        "HttpServletResponse" | "HttpResponse" | "ServletResponse"
        // Spring HTTP response
        | "ResponseEntity" => {
            Some(TypeKind::HttpResponse)
        }
        "Connection" | "DataSource" | "MongoClient"
        // JDBC statement types (execute SQL, same suppression semantics)
        | "Statement" | "PreparedStatement" => Some(TypeKind::DatabaseConnection),
        "File" | "Path"
        // Java I/O supertypes (enables hierarchy fallback for subtypes)
        | "InputStream" | "OutputStream" | "Reader" | "Writer" | "PrintWriter"
        | "BufferedInputStream" | "BufferedOutputStream" => Some(TypeKind::FileHandle),
        // JNDI / Spring LDAP directory-service types.  Field- and method-typed
        // declarations (`DirContext ctx = ...`, `LdapTemplate ldapTemplate;`)
        // attach this fact to the receiver SSA value so type-qualified
        // resolution rewrites `ctx.search(...)` → `LdapClient.search`.
        "DirContext" | "LdapContext" | "InitialDirContext" | "InitialLdapContext"
        | "LdapTemplate" => Some(TypeKind::LdapClient),
        // JAXP XML parser instances.  Field/local declarations like
        // `DocumentBuilder builder = factory.newDocumentBuilder();` route
        // through this map so the receiver SSA value carries
        // `TypeKind::XmlParser` and the type-qualified
        // `XmlParser.parse` rule fires on `builder.parse(...)`.
        "DocumentBuilder" | "SAXParser" | "XMLReader" | "SAXBuilder" => {
            Some(TypeKind::XmlParser)
        }
        // JAXP XPath instances.  `XPath xpath = factory.newXPath();`
        // routes through this map so the receiver carries
        // `TypeKind::XPathClient`, enabling the type-qualified
        // `XPathClient.evaluate` resolution and the resolver-binding
        // suppression sidecar.
        "XPath" | "XPathExpression" => Some(TypeKind::XPathClient),
        // Apache FreeMarker `Template` declared receiver type.  Routes
        // `Template tpl = ...; tpl.process(model, out)` through
        // type-qualified resolution to `Template.process`, the SSTI
        // sink defined in `labels/java.rs`.
        "Template" => Some(TypeKind::Template),
        // Python qualified type names.
        // Only covers raw lowered names from isinstance(). The lowering in lower.rs
        // extracts the literal type text: isinstance(x, requests.Session) produces
        // type_name = "requests.Session". Does NOT handle import aliasing
        // (e.g., `from requests import Session as S` → "S" is not resolved).
        "requests.Response" | "http.client.HTTPResponse" | "urllib3.response.HTTPResponse"
        | "httpx.Response" | "aiohttp.ClientResponse" => Some(TypeKind::HttpResponse),
        "requests.Session" | "urllib3.PoolManager" | "aiohttp.ClientSession"
        | "httpx.Client" | "httpx.AsyncClient" => Some(TypeKind::HttpClient),
        "sqlite3.Connection" | "psycopg2.connection" | "mysql.connector.connection"
        | "pymongo.MongoClient" | "redis.Redis" => Some(TypeKind::DatabaseConnection),
        "io.TextIOWrapper" | "io.BufferedReader" | "io.BufferedWriter" | "io.FileIO"
        | "io.BytesIO" | "io.StringIO" => Some(TypeKind::FileHandle),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_type_name tier 1 (primitive aliases) ───────────────────────

    #[test]
    fn parse_numeric_to_int() {
        // PHP-style "numeric" → Int via tier 1 primitive alias
        assert_eq!(parse_type_name("numeric"), Some(TypeKind::Int));
    }

    #[test]
    fn parse_string_case_insensitive() {
        // Tier 1 lowercase "string" matches "String" via case-insensitive
        assert_eq!(parse_type_name("String"), Some(TypeKind::String));
    }

    // ── parse_type_name tier 2 (class names) ────────────────────────────

    #[test]
    fn parse_integer_class_name() {
        // Java boxed class "Integer" → Int via tier 2
        assert_eq!(parse_type_name("Integer"), Some(TypeKind::Int));
    }

    #[test]
    fn parse_http_servlet_response() {
        // Java framework class → HttpResponse via tier 2
        assert_eq!(
            parse_type_name("HttpServletResponse"),
            Some(TypeKind::HttpResponse)
        );
    }

    // ── parse_type_name tier 3 (hierarchy fallback) ─────────────────────

    #[test]
    fn parse_closeable_http_client_via_hierarchy() {
        // CloseableHttpClient is in tier 2 class_name_to_type_kind directly
        assert_eq!(
            parse_type_name("CloseableHttpClient"),
            Some(TypeKind::HttpClient)
        );
    }

    #[test]
    fn parse_file_input_stream_via_hierarchy() {
        // FileInputStream: not in tier 1 or tier 2 directly.
        // Tier 3 hierarchy: FileInputStream → supertypes ["InputStream"].
        // "InputStream" IS in tier 2 → FileHandle.
        assert_eq!(
            parse_type_name("FileInputStream"),
            Some(TypeKind::FileHandle)
        );
    }

    // ── Java I/O and JDBC types ─────────────────────────────────────────

    #[test]
    fn parse_java_statement_to_db() {
        assert_eq!(
            parse_type_name("Statement"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            parse_type_name("PreparedStatement"),
            Some(TypeKind::DatabaseConnection)
        );
    }

    #[test]
    fn parse_java_io_stream_to_file_handle() {
        assert_eq!(parse_type_name("InputStream"), Some(TypeKind::FileHandle));
        assert_eq!(parse_type_name("OutputStream"), Some(TypeKind::FileHandle));
        assert_eq!(parse_type_name("Reader"), Some(TypeKind::FileHandle));
        assert_eq!(parse_type_name("Writer"), Some(TypeKind::FileHandle));
        assert_eq!(parse_type_name("PrintWriter"), Some(TypeKind::FileHandle));
    }

    #[test]
    fn parse_java_response_entity() {
        assert_eq!(
            parse_type_name("ResponseEntity"),
            Some(TypeKind::HttpResponse)
        );
    }

    // ── Python qualified type names ─────────────────────────────────────

    #[test]
    fn parse_python_qualified_http_client() {
        assert_eq!(
            parse_type_name("requests.Session"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            parse_type_name("aiohttp.ClientSession"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(parse_type_name("httpx.Client"), Some(TypeKind::HttpClient));
        assert_eq!(
            parse_type_name("httpx.AsyncClient"),
            Some(TypeKind::HttpClient)
        );
        assert_eq!(
            parse_type_name("urllib3.PoolManager"),
            Some(TypeKind::HttpClient)
        );
    }

    #[test]
    fn parse_python_qualified_db_connection() {
        assert_eq!(
            parse_type_name("sqlite3.Connection"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            parse_type_name("psycopg2.connection"),
            Some(TypeKind::DatabaseConnection)
        );
        assert_eq!(
            parse_type_name("mysql.connector.connection"),
            Some(TypeKind::DatabaseConnection)
        );
    }

    #[test]
    fn parse_python_qualified_http_response() {
        assert_eq!(
            parse_type_name("requests.Response"),
            Some(TypeKind::HttpResponse)
        );
        assert_eq!(
            parse_type_name("httpx.Response"),
            Some(TypeKind::HttpResponse)
        );
        assert_eq!(
            parse_type_name("aiohttp.ClientResponse"),
            Some(TypeKind::HttpResponse)
        );
    }

    #[test]
    fn parse_python_qualified_file_handle() {
        assert_eq!(
            parse_type_name("io.TextIOWrapper"),
            Some(TypeKind::FileHandle)
        );
        assert_eq!(parse_type_name("io.BytesIO"), Some(TypeKind::FileHandle));
        assert_eq!(parse_type_name("io.StringIO"), Some(TypeKind::FileHandle));
    }
}

//! Declared receiver types for Rust method calls.
//!
//! Rust receivers are typed by their constructor (`Connection::open(..)`) or
//! by a formal of exactly `Connection`.  A connection that arrives any other
//! way, held in a struct field (`self.conn.execute(..)`), behind a lock
//! (`Arc<Mutex<Connection>>`, bound by `let conn = self.pool.lock().unwrap()`)
//! or in a `let` with a type annotation, has its type only in the
//! declaration.  This module reads that declaration, the Rust counterpart of
//! `java_call_receiver_decl_type`, and records the result on
//! [`super::CallMeta::receiver_decl_type`] so type-qualified resolution can
//! reach `DatabaseConnection.execute` and the other SQL verbs.
//!
//! The type comes from the declaration, never from a name: only a leaf of
//! `Connection` (with `rusqlite` in scope) or `rusqlite::Connection`, under
//! reference, `Arc`, `Rc`, `Mutex`, `RwLock`, `RefCell`, `Box` or `Option`
//! wrappers, qualifies.  Pools, `PooledConnection` and other `*Connection`
//! types stay untyped.  A struct defined in another file is not seen.

use super::params::rust_peel_wrappers;
use super::text_of;
use crate::cfg::fast_kind::FastKind;
use crate::ssa::type_facts::TypeKind;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

#[derive(Default)]
struct FileInfo {
    /// The file can type a connection at all: it names `Connection`.
    enabled: bool,
    /// The file mentions `rusqlite`, so a bare `Connection` leaf is its type.
    rusqlite: bool,
    /// Struct name to the names of its fields that hold a connection.
    conn_fields: HashMap<String, HashSet<String>>,
}

thread_local! {
    static FILE_INFO: RefCell<FileInfo> = RefCell::new(FileInfo::default());
}

fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Read the per-file facts: whether connections can be typed here, and which
/// struct fields hold one.  Clears the previous file's facts.
pub(super) fn populate(tree: &Tree, code: &[u8]) {
    let mut info = FileInfo {
        enabled: contains_bytes(code, b"Connection"),
        rusqlite: contains_bytes(code, b"rusqlite"),
        conn_fields: HashMap::new(),
    };
    if info.enabled {
        collect_structs(tree.root_node(), code, &mut info);
    }
    FILE_INFO.with(|c| *c.borrow_mut() = info);
}

pub(super) fn clear() {
    FILE_INFO.with(|c| *c.borrow_mut() = FileInfo::default());
}

fn collect_structs(scope: Node, code: &[u8], info: &mut FileInfo) {
    let mut cursor = scope.walk();
    for item in scope.named_children(&mut cursor) {
        match item.fkind() {
            "struct_item" => {
                let (Some(name), Some(body)) = (
                    item.child_by_field_name("name")
                        .and_then(|n| text_of(n, code)),
                    item.child_by_field_name("body"),
                ) else {
                    continue;
                };
                let mut fields = HashSet::new();
                let mut c = body.walk();
                for field in body.named_children(&mut c) {
                    if field.fkind() != "field_declaration" {
                        continue;
                    }
                    if let (Some(fname), Some(fty)) = (
                        field
                            .child_by_field_name("name")
                            .and_then(|n| text_of(n, code)),
                        field
                            .child_by_field_name("type")
                            .and_then(|n| text_of(n, code)),
                    ) && type_is_db_connection(&fty, info.rusqlite)
                    {
                        fields.insert(fname);
                    }
                }
                // The same struct name in two modules is ambiguous: keep the
                // fields both declare as connections.
                match info.conn_fields.get_mut(&name) {
                    Some(existing) => existing.retain(|f| fields.contains(f)),
                    None => {
                        info.conn_fields.insert(name, fields);
                    }
                }
            }
            "mod_item" => {
                if let Some(body) = item.child_by_field_name("body") {
                    collect_structs(body, code, info);
                }
            }
            _ => {}
        }
    }
}

/// Whether a declared type, once its reference and wrapper layers are peeled,
/// is a `rusqlite` connection.
fn type_is_db_connection(type_text: &str, rusqlite_in_scope: bool) -> bool {
    match rust_peel_wrappers(type_text) {
        "rusqlite::Connection" => true,
        "Connection" => rusqlite_in_scope,
        _ => false,
    }
}

/// Methods that return the receiver's inner value (a lock guard, a borrowed
/// handle, the unwrapped `Result`), so the guard has the connection's type.
fn is_guard_adapter(method: &str) -> bool {
    matches!(
        method,
        "lock"
            | "try_lock"
            | "read"
            | "write"
            | "borrow"
            | "borrow_mut"
            | "get_mut"
            | "as_ref"
            | "as_mut"
            | "deref"
            | "deref_mut"
            | "clone"
            | "unwrap"
            | "expect"
            | "map_err"
            | "ok"
    )
}

/// Methods on the result of the call that carry no new receiver: the call
/// chain `conn.execute(..).unwrap()` is typed by `conn`.
fn is_result_adapter(method: &str) -> bool {
    matches!(
        method,
        "unwrap"
            | "expect"
            | "map_err"
            | "ok"
            | "unwrap_or"
            | "unwrap_or_default"
            | "unwrap_or_else"
            | "ok_or"
            | "ok_or_else"
    )
}

/// The declared type of the receiver of the call chain `call`: the
/// `DatabaseConnection` type when its receiver is a connection by declaration.
pub(super) fn call_receiver_decl_type(call: Node, code: &[u8]) -> Option<TypeKind> {
    FILE_INFO.with(|info| {
        let info = info.borrow();
        if !info.enabled {
            return None;
        }
        let mut cur = call;
        for _ in 0..8 {
            cur = peel_wrappers(cur);
            if cur.fkind() != "call_expression" {
                return None;
            }
            let func = cur.child_by_field_name("function")?;
            if func.fkind() != "field_expression" {
                return None;
            }
            let recv = func.child_by_field_name("value")?;
            if is_db_connection(recv, code, &info, 0) {
                return Some(TypeKind::DatabaseConnection);
            }
            let method = text_of(func.child_by_field_name("field")?, code)?;
            if !is_result_adapter(&method) {
                return None;
            }
            cur = recv;
        }
        None
    })
}

/// `expr?`, `expr.await` and `(expr)` evaluate to the inner expression.
fn peel_wrappers(mut n: Node) -> Node {
    while matches!(
        n.fkind(),
        "try_expression" | "await_expression" | "parenthesized_expression"
    ) {
        match n.named_child(0) {
            Some(c) => n = c,
            None => break,
        }
    }
    n
}

/// Whether the value of `expr` is a connection by declaration.
fn is_db_connection(expr: Node, code: &[u8], info: &FileInfo, depth: u32) -> bool {
    if depth > 6 {
        return false;
    }
    match expr.fkind() {
        "parenthesized_expression" | "try_expression" | "await_expression" => expr
            .named_child(0)
            .is_some_and(|c| is_db_connection(c, code, info, depth)),
        // `&conn`, `&mut conn`, `*guard`
        "reference_expression" | "unary_expression" => {
            let inner = expr
                .child_by_field_name("value")
                .or_else(|| expr.child_by_field_name("argument"))
                .or_else(|| expr.named_child(expr.named_child_count().saturating_sub(1) as u32));
            inner.is_some_and(|c| is_db_connection(c, code, info, depth))
        }
        "call_expression" => {
            let Some(func) = expr.child_by_field_name("function") else {
                return false;
            };
            if func.fkind() != "field_expression" {
                return false;
            }
            let adapter = func
                .child_by_field_name("field")
                .and_then(|f| text_of(f, code))
                .is_some_and(|m| is_guard_adapter(&m));
            adapter
                && func
                    .child_by_field_name("value")
                    .is_some_and(|v| is_db_connection(v, code, info, depth + 1))
        }
        "field_expression" => self_field_is_connection(expr, code, info),
        "identifier" => match text_of(expr, code) {
            Some(name) => ident_is_connection(expr, &name, code, info, depth),
            None => false,
        },
        _ => false,
    }
}

/// `self.<field>` where the field of the enclosing `impl` type is declared as
/// a connection.
fn self_field_is_connection(expr: Node, code: &[u8], info: &FileInfo) -> bool {
    let (Some(value), Some(field)) = (
        expr.child_by_field_name("value"),
        expr.child_by_field_name("field")
            .and_then(|f| text_of(f, code)),
    ) else {
        return false;
    };
    if value.fkind() != "self" {
        return false;
    }
    // The nearest function must take `self`; the impl is the next one out.
    let mut cur = expr.parent();
    let mut has_self = false;
    let mut seen_fn = false;
    while let Some(p) = cur {
        match p.fkind() {
            "function_item" if !seen_fn => {
                seen_fn = true;
                has_self = p.child_by_field_name("parameters").is_some_and(|ps| {
                    let mut c = ps.walk();
                    ps.named_children(&mut c)
                        .any(|x| x.fkind() == "self_parameter")
                });
            }
            "impl_item" => {
                if !has_self {
                    return false;
                }
                let Some(ty) = p.child_by_field_name("type").and_then(|t| text_of(t, code)) else {
                    return false;
                };
                let head = ty.split('<').next().unwrap_or(&ty).trim();
                let leaf = head.rsplit("::").next().unwrap_or(head);
                return info
                    .conn_fields
                    .get(leaf)
                    .is_some_and(|fields| fields.contains(&field));
            }
            _ => {}
        }
        cur = p.parent();
    }
    false
}

/// Whether the pattern binds `name`.
fn pattern_binds(pattern: Node, name: &str, code: &[u8]) -> bool {
    if pattern.fkind() == "identifier" && text_of(pattern, code).as_deref() == Some(name) {
        return true;
    }
    let mut c = pattern.walk();
    pattern
        .children(&mut c)
        .any(|ch| pattern_binds(ch, name, code))
}

/// Resolve the local, formal or binding `name` visible at `from`: its
/// annotation, else the initialiser it was bound to.  Any other binding of the
/// name (closure formal, `for` / `match` / `if let` pattern) shadows it.
fn ident_is_connection(from: Node, name: &str, code: &[u8], info: &FileInfo, depth: u32) -> bool {
    let mut child = from;
    let mut cur = from.parent();
    while let Some(p) = cur {
        match p.fkind() {
            "block" => {
                let mut c = p.walk();
                let earlier: Vec<Node> = p
                    .named_children(&mut c)
                    .take_while(|s| s.start_byte() < child.start_byte())
                    .collect();
                for stmt in earlier.into_iter().rev() {
                    let decl = if stmt.fkind() == "let_declaration" {
                        stmt
                    } else {
                        continue;
                    };
                    let Some(pattern) = decl.child_by_field_name("pattern") else {
                        continue;
                    };
                    if !pattern_binds(pattern, name, code) {
                        continue;
                    }
                    if pattern.fkind() != "identifier" {
                        return false;
                    }
                    if let Some(ty) = decl
                        .child_by_field_name("type")
                        .and_then(|t| text_of(t, code))
                    {
                        return type_is_db_connection(&ty, info.rusqlite);
                    }
                    return decl
                        .child_by_field_name("value")
                        .is_some_and(|v| is_db_connection(v, code, info, depth + 1));
                }
            }
            "closure_expression" => {
                if p.child_by_field_name("parameters")
                    .is_some_and(|ps| pattern_binds(ps, name, code))
                {
                    return false;
                }
            }
            "for_expression" | "match_arm" | "let_condition" => {
                if p.child_by_field_name("pattern")
                    .is_some_and(|pat| pattern_binds(pat, name, code))
                {
                    return false;
                }
            }
            "function_item" => {
                let Some(params) = p.child_by_field_name("parameters") else {
                    return false;
                };
                let mut c = params.walk();
                for param in params.named_children(&mut c) {
                    if param.fkind() != "parameter" {
                        continue;
                    }
                    let Some(pattern) = param.child_by_field_name("pattern") else {
                        continue;
                    };
                    if pattern_binds(pattern, name, code) {
                        return pattern.fkind() == "identifier"
                            && param
                                .child_by_field_name("type")
                                .and_then(|t| text_of(t, code))
                                .is_some_and(|ty| type_is_db_connection(&ty, info.rusqlite));
                    }
                }
                return false;
            }
            _ => {}
        }
        child = p;
        cur = p.parent();
    }
    false
}

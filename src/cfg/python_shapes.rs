//! Python call shapes whose flat sink label does not apply at a given call
//! site.
//!
//! `make_response`, `HttpResponse` and `yaml.load` are static sinks, but
//! their idiomatic safe spellings are common enough to drown the real
//! findings: an autoescaped template or a JSON body in the response, and
//! `yaml.load(f, Loader=yaml.SafeLoader)`. Likewise `request.args.get(k,
//! type=int)` is a request accessor that returns a number, and a SQLAlchemy
//! statement built from `select(..).where(Col == value)` binds `value` as a
//! parameter. The label table
//! cannot see an argument, so the shape is recognised here from the call's AST
//! and the node gets a same-node `Sanitizer` for the sink's own cap (all caps,
//! for the accessor). That clears the taint finding and, because a node
//! dominates itself, the structural `cfg-unguarded-sink` one too, while the
//! unsafe spellings keep their label.

use super::{extract_const_keyword_arg, text_of};
use crate::cfg::fast_kind::FastKind;
use crate::labels::{Cap, DataLabel, RuntimeLabelRule, classify_all};
use tree_sitter::Node;

/// Positional arguments of a Python call: every named child of the argument
/// list except keyword arguments and comments. `None` when a `*args` or
/// `**kwargs` splat is present, since positions are no longer reliable.
fn positional_args(call: Node) -> Option<Vec<Node>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let mut out = Vec::new();
    for child in args.named_children(&mut cursor) {
        match child.fkind() {
            "comment" | "keyword_argument" => {}
            "list_splat" | "dictionary_splat" => return None,
            _ => out.push(child),
        }
    }
    Some(out)
}

/// Value node of the keyword argument `name`.
fn keyword_arg_value<'a>(call: Node<'a>, name: &str, code: &[u8]) -> Option<Node<'a>> {
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for child in args.named_children(&mut cursor) {
        if child.fkind() != "keyword_argument" {
            continue;
        }
        let key = child
            .child_by_field_name("name")
            .and_then(|n| text_of(n, code))?;
        if key == name {
            return child.child_by_field_name("value");
        }
    }
    None
}

/// True when `call` is `yaml.load(stream, Loader=<safe loader>)`, with the
/// loader given by keyword or as the second positional argument. Only the
/// loaders that never construct arbitrary Python objects count: `FullLoader`,
/// `Loader`, `UnsafeLoader`, a missing loader and any computed loader are all
/// treated as unsafe.
pub(crate) fn yaml_loader_is_safe(call: Node, code: &[u8]) -> bool {
    let loader = keyword_arg_value(call, "Loader", code)
        .or_else(|| positional_args(call).and_then(|a| a.get(1).copied()));
    let Some(loader) = loader else {
        return false;
    };
    if !matches!(loader.fkind(), "identifier" | "attribute") {
        return false;
    }
    let Some(text) = text_of(loader, code) else {
        return false;
    };
    matches!(
        text.rsplit('.').next().unwrap_or(""),
        "SafeLoader" | "CSafeLoader" | "BaseLoader" | "CBaseLoader"
    )
}

/// True when the source text of a string literal (`"application/json"`,
/// `b'text/plain; charset=utf-8'`) names a media type a browser does not
/// render as HTML.
pub(crate) fn response_content_type_is_non_html(raw: &str) -> bool {
    let body = raw.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let Some(value) = ["\"\"\"", "'''", "\"", "'"]
        .iter()
        .find_map(|q| body.strip_prefix(q)?.strip_suffix(q))
    else {
        return false;
    };
    let media = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        media.as_str(),
        "application/json" | "text/plain" | "text/csv" | "application/octet-stream"
    ) || (media.starts_with("application/")
        && media.ends_with("+json")
        && !media.contains(['{', '}']))
}

/// True when the body argument of a `make_response` / `HttpResponse` call
/// cannot carry markup: it is a `jsonify(..)` result or the output of an
/// HTML-escaping call (`render_template`, `render_to_string`,
/// `html.escape`), or the response declares a non-HTML content type.
fn response_body_is_safe(
    leaf: &str,
    call: Node,
    code: &[u8],
    extra: Option<&[RuntimeLabelRule]>,
) -> bool {
    if let Some(body) = positional_args(call).and_then(|a| a.first().copied()) {
        let mut body = body;
        while body.fkind() == "parenthesized_expression"
            && let Some(inner) = body.named_child(0)
        {
            body = inner;
        }
        if body.fkind() == "call"
            && let Some(callee) = body
                .child_by_field_name("function")
                .and_then(|f| text_of(f, code))
        {
            let callee: String = callee.chars().filter(|c| !c.is_whitespace()).collect();
            if callee.rsplit('.').next() == Some("jsonify") {
                return true;
            }
            if classify_all("python", &callee, extra)
                .iter()
                .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(Cap::HTML_ESCAPE)))
            {
                return true;
            }
        }
    }
    let content_type = ["content_type", "mimetype"]
        .iter()
        .find_map(|kw| extract_const_keyword_arg(call, kw, code))
        .or_else(|| {
            // Django's `HttpResponse(content, content_type)`.
            if leaf != "HttpResponse" {
                return None;
            }
            let second = positional_args(call)?.get(1).copied()?;
            (second.fkind() == "string")
                .then(|| text_of(second, code))
                .flatten()
        });
    content_type.is_some_and(|ct| response_content_type_is_non_html(&ct))
}

/// Calls that start a SQLAlchemy statement.
const STATEMENT_ROOTS: &[&str] = &["select", "insert", "update", "delete", "exists"];

/// Methods that add a clause to a statement. Values given to them are bound
/// as parameters, conditions are built from column expressions.
const STATEMENT_METHODS: &[&str] = &[
    "where",
    "filter",
    "filter_by",
    "having",
    "order_by",
    "group_by",
    "limit",
    "offset",
    "distinct",
    "values",
    "returning",
    "options",
    "select_from",
    "join",
    "outerjoin",
    "with_for_update",
];

/// The clause methods that can continue a statement held in a variable
/// (`stmt = stmt.where(..)`). `join`, `values` and the rest are left out
/// because `" ".join(parts)` and `dict.values()` are not statements.
const VARIABLE_STATEMENT_METHODS: &[&str] = &[
    "where",
    "filter",
    "filter_by",
    "having",
    "order_by",
    "group_by",
    "limit",
    "offset",
];

/// Column methods whose arguments are bound values (`User.name.like(q)`).
const VALUE_METHODS: &[&str] = &[
    "like",
    "ilike",
    "notlike",
    "notilike",
    "contains",
    "startswith",
    "endswith",
    "in_",
    "not_in",
    "notin_",
    "is_",
    "is_not",
    "isnot",
    "between",
];

/// SQLAlchemy constructors that build a column expression from column
/// expressions (`and_(a == 1, b == 2)`, `desc(User.id)`).  Any other call is
/// an arbitrary function whose result is not known to be a bound expression.
/// `func.<name>(..)` is also accepted, see [`is_column_expression`].
const COLUMN_EXPRESSION_CALLS: &[&str] = &[
    "and_",
    "or_",
    "not_",
    "desc",
    "asc",
    "nulls_first",
    "nulls_last",
    "nullsfirst",
    "nullslast",
    "cast",
    "coalesce",
    "any_",
    "all_",
    "tuple_",
    "distinct",
    "case",
];

/// Calls that splice their argument into the SQL text.
const RAW_SQL_CALLS: &[&str] = &["text", "literal_column", "sql_text"];

/// Execution methods whose first argument can be a statement object.
const EXECUTE_METHODS: &[&str] = &["execute", "scalar", "scalars", "exec", "stream"];

/// Last segment of a call's callee: `select` for `select(..)`, `where` for
/// `stmt.where(..)`.
fn call_leaf<'a>(call: Node, code: &'a [u8]) -> Option<&'a str> {
    let func = call.child_by_field_name("function")?;
    let leaf = match func.fkind() {
        "identifier" => func,
        "attribute" => func.child_by_field_name("attribute")?,
        _ => return None,
    };
    std::str::from_utf8(&code[leaf.byte_range()]).ok()
}

/// True when no call under `node` splices text into SQL (`text(f"..")`).
fn has_no_raw_sql_call(node: Node, code: &[u8]) -> bool {
    if node.fkind() == "call" && call_leaf(node, code).is_some_and(|l| RAW_SQL_CALLS.contains(&l)) {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .all(|c| has_no_raw_sql_call(c, code))
}

/// True for a column source or a dotted name that reads one of its columns:
/// a model class (`User`, `User.id`, `models.User.name`), a Core table's
/// column collection (`users.c.name`, `t.columns.id`) or a name bound only to
/// a Core `Table(..)` (`users`). Every segment is an identifier. Any other
/// lowercase-only chain (`form.sort`, `request.args`) can hold a string,
/// which a clause method would splice into SQL text.
fn is_column_reference(node: Node, code: &[u8]) -> bool {
    let mut has_class = false;
    let mut cur = node;
    loop {
        match cur.fkind() {
            "attribute" => {
                let (Some(obj), Some(attr)) = (
                    cur.child_by_field_name("object"),
                    cur.child_by_field_name("attribute"),
                ) else {
                    return false;
                };
                let attr_text = &code[attr.byte_range()];
                has_class |= attr_text.first().is_some_and(u8::is_ascii_uppercase);
                // `table.c.<col>`: the column collection of a Core table.
                has_class |= cur != node && matches!(attr_text, b"c" | b"columns");
                cur = obj;
            }
            "identifier" => {
                has_class |= code[cur.byte_range()]
                    .first()
                    .is_some_and(u8::is_ascii_uppercase);
                return has_class || name_holds_core_table(cur, code);
            }
            _ => return false,
        }
    }
}

/// True when `ident` names a SQLAlchemy Core table: every binding of the name
/// in its function, or failing any there, at module level, is
/// `name = Table(..)` (`sa.Table`, `sqlalchemy.Table`). Any other binding (a
/// parameter, a loop target, a string) leaves it unknown.
fn name_holds_core_table(ident: Node, code: &[u8]) -> bool {
    let name = &code[ident.byte_range()];
    let scope = enclosing_scope(ident);
    let mut root = scope;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut scopes = vec![scope];
    if root != scope {
        scopes.push(root);
    }
    for scope in scopes {
        match core_table_bindings(scope, name, code) {
            Some(only_tables) => return only_tables,
            None => continue,
        }
    }
    false
}

/// `None` when nothing under `scope` binds `name`; otherwise whether every
/// binding is a `Table(..)` call.
fn core_table_bindings(scope: Node, name: &[u8], code: &[u8]) -> Option<bool> {
    let mut found = false;
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            stack.push(c);
        }
        match n.fkind() {
            "assignment" => {
                let Some(left) = n.child_by_field_name("left") else {
                    continue;
                };
                if left.fkind() == "identifier" && &code[left.byte_range()] == name {
                    let is_table = n.child_by_field_name("right").is_some_and(|r| {
                        r.fkind() == "call" && call_leaf(r, code) == Some("Table")
                    });
                    if !is_table {
                        return Some(false);
                    }
                    found = true;
                } else if binds_name(left, name, code) {
                    return Some(false);
                }
            }
            "augmented_assignment" | "named_expression" | "for_statement" | "for_in_clause" => {
                let target = n
                    .child_by_field_name("left")
                    .or_else(|| n.child_by_field_name("name"));
                if target.is_some_and(|t| binds_name(t, name, code)) {
                    return Some(false);
                }
            }
            "parameters"
            | "lambda_parameters"
            | "as_pattern"
            | "global_statement"
            | "nonlocal_statement"
            | "import_statement"
            | "import_from_statement"
            | "delete_statement"
                if binds_name(n, name, code) =>
            {
                return Some(false);
            }
            _ => {}
        }
    }
    found.then_some(true)
}

/// True for an argument of a statement clause that is a column expression:
/// comparisons (their operands are bound values), boolean combinations,
/// model column references and calls over those. A bare string, or a bare
/// variable that may hold one, is raw SQL text (`order_by(sort)`,
/// `where(cond)`), so it is not one.
fn is_column_expression(node: Node, code: &[u8]) -> bool {
    match node.fkind() {
        "attribute" | "identifier" => is_column_reference(node, code),
        "integer" | "float" | "true" | "false" | "none" => true,
        "comparison_operator" => has_no_raw_sql_call(node, code),
        "parenthesized_expression"
        | "not_operator"
        | "unary_operator"
        | "boolean_operator"
        | "list"
        | "tuple" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .all(|c| is_column_expression(c, code))
        }
        // `User.id + 1`, `User.score * weight`: arithmetic on a column
        // binds the other operand. `%` is excluded because `tmpl % value` is
        // string formatting, and an expression with no column operand is not
        // known to be SQL at all.
        "binary_operator" => {
            let is_mod = node
                .child_by_field_name("operator")
                .is_some_and(|o| &code[o.byte_range()] == b"%");
            let mut cursor = node.walk();
            let operands: Vec<Node> = node.named_children(&mut cursor).collect();
            !is_mod
                && operands.iter().any(|c| is_column_expression(*c, code))
                && operands.iter().all(|c| {
                    c.fkind() != "string"
                        && c.fkind() != "concatenated_string"
                        && has_no_raw_sql_call(*c, code)
                })
        }
        "call" => {
            let Some(leaf) = call_leaf(node, code) else {
                return false;
            };
            if RAW_SQL_CALLS.contains(&leaf) {
                return false;
            }
            let on_column = node
                .child_by_field_name("function")
                .is_some_and(|f| f.fkind() == "attribute");
            if on_column && VALUE_METHODS.contains(&leaf) {
                return has_no_raw_sql_call(node, code);
            }
            if is_statement_call(node, code, false) {
                return true;
            }
            let func = node.child_by_field_name("function");
            let is_expression_call = COLUMN_EXPRESSION_CALLS.contains(&leaf)
                || func.is_some_and(|f| {
                    f.fkind() == "attribute"
                        && f.child_by_field_name("object")
                            .is_some_and(|o| &code[o.byte_range()] == b"func")
                });
            is_expression_call && call_args_are_column_expressions(node, code)
        }
        _ => false,
    }
}

fn call_args_are_column_expressions(call: Node, code: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor).all(|a| match a.fkind() {
        "comment" => true,
        // `filter_by(name=name)`, `values(x=value)`: the value is bound.
        "keyword_argument" => has_no_raw_sql_call(a, code),
        _ => is_column_expression(a, code),
    })
}

/// True when `call` is a SQLAlchemy statement (or a clause added to one)
/// whose arguments are column expressions, so every value in it reaches the
/// database as a bound parameter. A clause method counts when its receiver is
/// such a statement, or, with `variable_receiver`, a plain variable and one of
/// [`VARIABLE_STATEMENT_METHODS`].
fn is_statement_call(call: Node, code: &[u8], variable_receiver: bool) -> bool {
    if call.fkind() != "call" {
        return false;
    }
    let Some(leaf) = call_leaf(call, code) else {
        return false;
    };
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let rooted = match func.fkind() {
        // `from sqlalchemy import select`; a bare `delete(..)` or `update(..)`
        // from anywhere else is an ordinary function.
        "identifier" => {
            STATEMENT_ROOTS.contains(&leaf)
                && crate::ssa::type_facts::file_import_path(leaf)
                    .is_some_and(|p| p.starts_with("sqlalchemy") || p.starts_with("sqlmodel"))
        }
        "attribute" => {
            let Some(object) = func.child_by_field_name("object") else {
                return false;
            };
            if STATEMENT_ROOTS.contains(&leaf) {
                // `sa.select(..)`, `sqlalchemy.update(..)`.
                matches!(
                    std::str::from_utf8(&code[object.byte_range()]),
                    Ok("sa" | "sqlalchemy" | "sql")
                )
            } else if STATEMENT_METHODS.contains(&leaf) {
                match object.fkind() {
                    "call" => is_statement_call(object, code, variable_receiver),
                    "identifier" => {
                        variable_receiver
                            && VARIABLE_STATEMENT_METHODS.contains(&leaf)
                            && variable_holds_bound_statement(object, code)
                    }
                    _ => false,
                }
            } else {
                false
            }
        }
        _ => false,
    };
    rooted && clause_args_are_bound(call, code)
}

/// True when every argument of a statement or clause call is bound by the
/// driver rather than spliced into the SQL text.
fn clause_args_are_bound(call: Node, code: &[u8]) -> bool {
    if matches!(call_leaf(call, code), Some("limit" | "offset")) {
        // SQLAlchemy turns the argument into a bound integer parameter.
        has_no_raw_sql_call(call, code)
    } else {
        call_args_are_column_expressions(call, code)
    }
}

/// The scope a variable is looked up in: the nearest enclosing function, or
/// the module.
fn enclosing_scope(node: Node) -> Node {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if parent.fkind() == "function_definition" {
            return parent;
        }
        cur = parent;
    }
    cur
}

/// True when `ident` is a name read as a statement and every binding of that
/// name in its scope is a bound statement: at least one plain assignment from
/// a rooted statement call (`stmt = select(User)`), the others continuing it
/// (`stmt = stmt.where(..)`).
///
/// A clause added to a statement keeps whatever the statement already holds,
/// so the clause only gets a sanitizer when nothing raw can have reached the
/// variable. Any other binding (a parameter, a loop target, `+=`, an
/// unpacking, a statement that splices `text(..)`) leaves the variable
/// unknown and the clause unsanitised.
fn variable_holds_bound_statement(ident: Node, code: &[u8]) -> bool {
    let name = &code[ident.byte_range()];
    let scope = enclosing_scope(ident);
    let mut has_root = false;
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            stack.push(c);
        }
        match n.fkind() {
            "assignment" => {
                let Some(left) = n.child_by_field_name("left") else {
                    continue;
                };
                if left.fkind() == "identifier" && &code[left.byte_range()] == name {
                    let Some(right) = n.child_by_field_name("right") else {
                        return false;
                    };
                    if !is_statement_call(right, code, false) {
                        // `stmt = stmt.where(..)`: the receiver is the same
                        // variable, which this loop is already checking.
                        let continues_self = chain_continues_variable(right, name, code);
                        if !continues_self {
                            return false;
                        }
                    } else {
                        has_root = true;
                    }
                } else if binds_name(left, name, code) {
                    return false;
                }
            }
            "augmented_assignment" | "named_expression" | "for_statement" | "for_in_clause" => {
                let target = n
                    .child_by_field_name("left")
                    .or_else(|| n.child_by_field_name("name"));
                if target.is_some_and(|t| binds_name(t, name, code)) {
                    return false;
                }
            }
            "parameters"
            | "lambda_parameters"
            | "as_pattern"
            | "global_statement"
            | "nonlocal_statement"
            | "import_statement"
            | "import_from_statement"
            | "delete_statement"
                if binds_name(n, name, code) =>
            {
                return false;
            }
            _ => {}
        }
    }
    has_root
}

/// True when `call` is a chain of clause calls whose innermost receiver is
/// the variable `name` and whose arguments are all bound
/// (`stmt.where(..).limit(n)`).
fn chain_continues_variable(call: Node, name: &[u8], code: &[u8]) -> bool {
    let mut cur = call;
    loop {
        if cur.fkind() != "call"
            || !call_leaf(cur, code).is_some_and(|l| VARIABLE_STATEMENT_METHODS.contains(&l))
            || !clause_args_are_bound(cur, code)
        {
            return false;
        }
        let Some(object) = cur
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("object"))
        else {
            return false;
        };
        match object.fkind() {
            "identifier" => return &code[object.byte_range()] == name,
            "call" => cur = object,
            _ => return false,
        }
    }
}

/// True when an identifier equal to `name` occurs anywhere under `node`.
fn binds_name(node: Node, name: &[u8], code: &[u8]) -> bool {
    if node.fkind() == "identifier" && &code[node.byte_range()] == name {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|c| binds_name(c, name, code))
}

/// The first positional argument of `call`, unwrapping nothing.
fn first_positional(call: Node) -> Option<Node> {
    positional_args(call).and_then(|a| a.first().copied())
}

/// The same-node sanitizer a Python call node should carry because its call
/// shape neutralises the sink it matched, or `None` to leave the labels as
/// they are.
///
/// `text` is the callee text the node was classified under and `call` the
/// call node it was read from; `labels` are the labels classification gave
/// the node.
pub(super) fn safe_shape_sanitizer(
    text: &str,
    call: Node,
    code: &[u8],
    extra: Option<&[RuntimeLabelRule]>,
    labels: &[DataLabel],
) -> Option<DataLabel> {
    let has_sink = |cap: Cap| {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sink(c) if c.contains(cap)))
    };
    let has_sanitizer = |cap: Cap| {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(cap)))
    };
    let html = has_sink(Cap::HTML_ESCAPE) && !has_sanitizer(Cap::HTML_ESCAPE);
    let deser = has_sink(Cap::DESERIALIZE) && !has_sanitizer(Cap::DESERIALIZE);
    let source = labels.iter().any(|l| matches!(l, DataLabel::Source(_)))
        && !labels.iter().any(|l| matches!(l, DataLabel::Sanitizer(_)));
    let sql = !has_sanitizer(Cap::SQL_QUERY);
    let sql_sink = sql && has_sink(Cap::SQL_QUERY);
    // A statement-building call is cheap to rule out from its name alone.
    let written_leaf = text.rsplit('.').next().unwrap_or(text);
    let written_leaf = written_leaf.split('(').next().unwrap_or(written_leaf);
    let statement_node = sql
        && (STATEMENT_METHODS.contains(&written_leaf) || STATEMENT_ROOTS.contains(&written_leaf));
    if !html && !deser && !source && !sql_sink && !statement_node {
        return None;
    }
    // `text` can name an inner call the node was rebound to; the shape below
    // is only read off the call that `text` is the callee of.
    let call_callee = call
        .child_by_field_name("function")
        .and_then(|f| text_of(f, code))?;
    let call_callee: String = call_callee.chars().filter(|c| !c.is_whitespace()).collect();
    if call_callee.rsplit('.').next() != Some(written_leaf) {
        return None;
    }
    if source && source_value_is_coerced(call, code) {
        return Some(DataLabel::Sanitizer(Cap::all()));
    }
    // `session.execute(select(User).where(User.name == name))`: the statement
    // binds `name`. The statement held in a variable gets the same treatment
    // on the line that builds it.
    if sql_sink
        && EXECUTE_METHODS.contains(&written_leaf)
        && first_positional(call).is_some_and(|a| is_statement_call(a, code, false))
    {
        return Some(DataLabel::Sanitizer(Cap::SQL_QUERY));
    }
    if statement_node && is_statement_call(call, code, true) {
        return Some(DataLabel::Sanitizer(Cap::SQL_QUERY));
    }
    let qualified = crate::labels::python_import_qualified(text);
    let callee = qualified.as_deref().unwrap_or(text);
    let leaf = callee.rsplit('.').next().unwrap_or(callee);
    if html
        && matches!(leaf, "make_response" | "HttpResponse")
        && response_body_is_safe(leaf, call, code, extra)
    {
        return Some(DataLabel::Sanitizer(Cap::HTML_ESCAPE));
    }
    if deser
        && (callee == "yaml.load" || callee.ends_with(".yaml.load"))
        && yaml_loader_is_safe(call, code)
    {
        return Some(DataLabel::Sanitizer(Cap::DESERIALIZE));
    }
    None
}

/// True for a request accessor that converts what it returns with a numeric
/// `type=`, as werkzeug's `MultiDict.get(key, default, type=int)` does
/// (`request.args.get("page", 1, type=int)`). The value is a number or the
/// literal default, the same as the result of `int(..)`.
fn source_value_is_coerced(call: Node, code: &[u8]) -> bool {
    keyword_arg_value(call, "type", code)
        .filter(|v| v.fkind() == "identifier")
        .and_then(|v| text_of(v, code))
        .is_some_and(|t| matches!(t.as_str(), "int" | "float" | "bool"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse(src: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    /// The first `call` node in the source.
    fn first_call(tree: &Tree) -> Node<'_> {
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if n.fkind() == "call" {
                return n;
            }
            let mut c = n.walk();
            let mut kids: Vec<_> = n.named_children(&mut c).collect();
            kids.reverse();
            stack.extend(kids);
        }
        panic!("no call in source");
    }

    fn yaml_safe(src: &str) -> bool {
        let tree = parse(src);
        yaml_loader_is_safe(first_call(&tree), src.as_bytes())
    }

    #[test]
    fn yaml_safe_loaders_by_keyword_and_position() {
        assert!(yaml_safe("yaml.load(f, Loader=yaml.SafeLoader)"));
        assert!(yaml_safe("yaml.load(f, Loader=SafeLoader)"));
        assert!(yaml_safe("yaml.load(f, Loader=yaml.CSafeLoader)"));
        assert!(yaml_safe("yaml.load(f, yaml.SafeLoader)"));
        assert!(yaml_safe("yaml.load(stream=f, Loader=yaml.BaseLoader)"));
    }

    #[test]
    fn yaml_unsafe_or_unknown_loaders_are_not_safe() {
        assert!(!yaml_safe("yaml.load(f)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.Loader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.FullLoader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=yaml.UnsafeLoader)"));
        assert!(!yaml_safe("yaml.load(f, Loader=getattr(yaml, name))"));
        assert!(!yaml_safe("yaml.load(f, Loader=loader_cls)"));
        assert!(!yaml_safe("yaml.load(*args)"));
    }

    #[test]
    fn non_html_content_types() {
        assert!(response_content_type_is_non_html("\"application/json\""));
        assert!(response_content_type_is_non_html(
            "'text/plain; charset=utf-8'"
        ));
        assert!(response_content_type_is_non_html("b\"text/csv\""));
        assert!(response_content_type_is_non_html(
            "\"application/vnd.api+json\""
        ));
        assert!(!response_content_type_is_non_html("\"text/html\""));
        assert!(!response_content_type_is_non_html(
            "\"text/html; charset=utf-8\""
        ));
        assert!(!response_content_type_is_non_html("\"image/svg+xml\""));
        assert!(!response_content_type_is_non_html(
            "\"application/xhtml+xml\""
        ));
        assert!(!response_content_type_is_non_html("content_type_var"));
        assert!(!response_content_type_is_non_html("\"\""));
    }

    fn body_safe(src: &str, leaf: &str) -> bool {
        let tree = parse(src);
        response_body_is_safe(leaf, first_call(&tree), src.as_bytes(), None)
    }

    #[test]
    fn response_body_shapes() {
        assert!(body_safe(
            "make_response(render_template('x.html', q=q))",
            "make_response"
        ));
        assert!(body_safe(
            "make_response(jsonify({'q': q}), 200)",
            "make_response"
        ));
        assert!(body_safe(
            "HttpResponse(render_to_string('x.html', {'q': q}))",
            "HttpResponse"
        ));
        assert!(body_safe(
            "HttpResponse(html.escape(q), status=200)",
            "HttpResponse"
        ));
        assert!(body_safe(
            "HttpResponse(json.dumps({'q': q}), content_type='application/json')",
            "HttpResponse"
        ));
        assert!(body_safe("HttpResponse(q, 'text/plain')", "HttpResponse"));
        // Not safe: default text/html, an explicit HTML type, a computed
        // type, a concatenation around an escape call, a plain value.
        assert!(!body_safe(
            "HttpResponse(json.dumps({'q': q}))",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "HttpResponse(q, content_type='text/html')",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "HttpResponse(q, content_type=ct)",
            "HttpResponse"
        ));
        assert!(!body_safe(
            "make_response('<p>' + html.escape(q) + tail)",
            "make_response"
        ));
        assert!(!body_safe("make_response(q)", "make_response"));
        assert!(!body_safe(
            "make_response(render_template_string(q))",
            "make_response"
        ));
        // Flask's `make_response` has no positional content type.
        assert!(!body_safe(
            "make_response(q, 'text/plain')",
            "make_response"
        ));
    }
}

#[cfg(test)]
mod cfg_tests {
    use crate::labels::{Cap, DataLabel};

    /// Labels of every CFG node whose callee ends in `leaf`, one entry per node.
    fn labels_of(src: &str, leaf: &str) -> Vec<Vec<DataLabel>> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let mut out = Vec::new();
        for body in &file.bodies {
            for idx in body.graph.node_indices() {
                let node = &body.graph[idx];
                if node
                    .call
                    .callee
                    .as_deref()
                    .is_some_and(|c| c.rsplit('.').next() == Some(leaf))
                {
                    out.push(node.taint.labels.to_vec());
                }
            }
        }
        assert!(!out.is_empty(), "no `{leaf}` node in:\n{src}");
        out
    }

    /// True when no CFG node of `src` carries a sanitizer for `cap`.  Used
    /// when the statement is not a node of its own (a raw-text call nested in
    /// it is the node's callee).
    fn no_node_sanitizes(src: &str, cap: Cap) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        file.bodies
            .iter()
            .flat_map(|b| b.graph.node_weights())
            .all(|n| !sanitizes(&n.taint.labels, cap))
    }

    fn sanitizes(labels: &[DataLabel], cap: Cap) -> bool {
        labels
            .iter()
            .any(|l| matches!(l, DataLabel::Sanitizer(c) if c.contains(cap)))
    }

    fn all_sanitize(src: &str, leaf: &str, cap: Cap) -> bool {
        labels_of(src, leaf).iter().all(|l| sanitizes(l, cap))
    }

    fn none_sanitize(src: &str, leaf: &str, cap: Cap) -> bool {
        labels_of(src, leaf).iter().all(|l| !sanitizes(l, cap))
    }

    #[test]
    fn response_sinks_with_safe_bodies_carry_a_sanitizer() {
        for src in [
            "def f(q):\n    return make_response(render_template('x.html', q=q))\n",
            "def f(q):\n    return make_response(jsonify({'q': q}), 200)\n",
            "def f(q):\n    return HttpResponse(json.dumps({'q': q}), content_type='application/json')\n",
            "def f(q):\n    return HttpResponse(render_to_string('x.html', {'q': q}))\n",
            "def f(q):\n    return HttpResponse(q, content_type='text/plain; charset=utf-8')\n",
            "def f(q):\n    return HttpResponse(html.escape(q), status=200)\n",
        ] {
            let leaf = if src.contains("make_response") {
                "make_response"
            } else {
                "HttpResponse"
            };
            assert!(all_sanitize(src, leaf, Cap::HTML_ESCAPE), "{src}");
        }
    }

    #[test]
    fn response_sinks_with_unsafe_bodies_keep_their_sink_alone() {
        for src in [
            "def f(q):\n    return HttpResponse(json.dumps({'q': q}))\n",
            "def f(q):\n    return HttpResponse(q, content_type='text/html')\n",
            "def f(q):\n    return HttpResponse(q, content_type=ct)\n",
            "def f(q):\n    return HttpResponse('<p>' + html.escape(q) + tail)\n",
        ] {
            assert!(
                none_sanitize(src, "HttpResponse", Cap::HTML_ESCAPE),
                "{src}"
            );
        }
        for src in [
            "def f(q):\n    return make_response('<h1>' + q + '</h1>')\n",
            "def f(q):\n    return make_response(render_template_string(q))\n",
        ] {
            assert!(
                none_sanitize(src, "make_response", Cap::HTML_ESCAPE),
                "{src}"
            );
        }
    }

    #[test]
    fn yaml_load_with_safe_loader_carries_a_sanitizer() {
        for src in [
            "def f(b):\n    return yaml.load(b, Loader=yaml.SafeLoader)\n",
            "def f(b):\n    return yaml.load(b, yaml.CSafeLoader)\n",
            "from yaml import load\ndef f(b):\n    return load(b, Loader=SafeLoader)\n",
        ] {
            assert!(all_sanitize(src, "load", Cap::DESERIALIZE), "{src}");
        }
        for src in [
            "def f(b):\n    return yaml.load(b)\n",
            "def f(b):\n    return yaml.load(b, Loader=yaml.Loader)\n",
            "def f(b):\n    return yaml.load(b, Loader=yaml.FullLoader)\n",
        ] {
            assert!(none_sanitize(src, "load", Cap::DESERIALIZE), "{src}");
        }
    }

    #[test]
    fn numeric_type_coerced_request_accessor_is_neutralised() {
        for src in [
            "def f():\n    page = request.args.get('page', 1, type=int)\n    return page\n",
            "def f():\n    p = request.args.get('p', type=float)\n    return p\n",
        ] {
            assert!(all_sanitize(src, "get", Cap::all()), "{src}");
        }
        for src in [
            "def f():\n    p = request.args.get('p', type=str)\n    return p\n",
            "def f():\n    p = request.args.get('p')\n    return p\n",
            "def f():\n    p = request.args.get('p', type=parse_page)\n    return p\n",
        ] {
            assert!(none_sanitize(src, "get", Cap::all()), "{src}");
        }
    }

    #[test]
    fn from_imported_callees_carry_the_qualified_labels() {
        let src = "from subprocess import check_output\nfrom html import escape\n\
                   def f(d):\n    safe = escape(d)\n    return check_output(safe, shell=True)\n";
        assert!(
            labels_of(src, "check_output")
                .iter()
                .all(|l| l.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)))
        );
        assert!(all_sanitize(src, "escape", Cap::HTML_ESCAPE));
        // The same name without an import binding classifies as nothing.
        let unbound = "def f(d):\n    return check_output(d, shell=True)\n";
        assert!(
            labels_of(unbound, "check_output")
                .iter()
                .all(|l| !l.contains(&DataLabel::Sink(Cap::SHELL_ESCAPE)))
        );
    }

    #[test]
    fn chained_sql_execute_is_rebound_to_the_execute_call() {
        let src = "def f(conn, uid):\n    rows = conn.execute('SELECT * FROM t WHERE id = ?', (uid,)).fetchall()\n    return rows\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let node = file.bodies[1]
            .graph
            .node_indices()
            .map(|i| &file.bodies[1].graph[i])
            .find(|n| n.call.callee.as_deref() == Some("conn.execute"))
            .expect("the sink node is named after the execute call, not the whole chain");
        assert_eq!(node.call.sink_payload_args.as_deref(), Some(&[0usize][..]));
        assert!(node.parameterized_query);
        assert!(node.call.outer_callee.is_some());
    }

    #[test]
    fn inline_source_beside_a_keyword_argument_binds_to_its_position() {
        let src = "def f():\n    return check_output('ls ' + request.args.get('d'), shell=True)\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter::Language::from(tree_sitter_python::LANGUAGE))
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let file = crate::cfg::build_cfg(&tree, src.as_bytes(), "python", "t.py", None);
        let body = &file.bodies[1];
        let has_synth_source = body.graph.node_indices().any(|i| {
            let n = &body.graph[i];
            n.taint
                .defines
                .as_deref()
                .is_some_and(|d| d.starts_with("__nyx_src_"))
                && n.taint
                    .labels
                    .iter()
                    .any(|l| matches!(l, DataLabel::Source(_)))
        });
        assert!(has_synth_source);
    }

    #[test]
    fn bound_statement_builders_carry_a_sql_sanitizer() {
        let imports = "from sqlalchemy import select, update, text\n";
        for (body, leaf) in [
            ("stmt = select(User).where(User.name == name)", "where"),
            (
                "stmt = select(User).where(User.name == name).order_by(User.id).limit(10)",
                "limit",
            ),
            (
                "stmt = select(User)\n    stmt = stmt.where(User.age > limit)",
                "where",
            ),
            (
                "stmt = select(User)\n    stmt = stmt.filter_by(name=name)",
                "filter_by",
            ),
            (
                "stmt = select(User).order_by(User.id)\n    stmt = stmt.limit(limit).offset(uid)",
                "offset",
            ),
            ("stmt = select(User).where(User.score + limit > 1)", "where"),
            (
                "stmt = update(User).where(User.id == uid).values(name=name)",
                "values",
            ),
            (
                "stmt = select(User).where(User.name.like(f'%{q}%'))",
                "where",
            ),
            (
                "stmt = select(User).where(and_(User.a == a, User.b.in_(bs)))",
                "where",
            ),
        ] {
            let src =
                format!("{imports}def f(name, limit, uid, q):\n    {body}\n    return stmt\n");
            assert!(all_sanitize(&src, leaf, Cap::SQL_QUERY), "{body}");
        }
    }

    #[test]
    fn statements_with_raw_sql_text_are_left_alone() {
        let imports = "from sqlalchemy import select, text\n";
        for body in [
            "stmt = select(User).where(text(f\"n = '{name}'\"))",
            "stmt = select(User).where(\"n = '%s'\" % name)",
            "stmt = select(User).where(\"n = 1\")",
            "stmt = select(User).order_by(text(sort))",
            "stmt = select(User).where(User.id == text(name))",
            "stmt = select(User).order_by(request.args.get('sort'))",
            // An arbitrary function may return SQL text.
            "stmt = select(User).where(build_condition(name))",
            // A variable that may hold a string is SQL text as a whole clause.
            "stmt = select(User).order_by(sort)",
            "stmt = select(User).group_by(sort)",
            "stmt = select(User).where(cond)",
            "stmt = select(User).where(cond % name)",
            "stmt = select(User).where(sort + name)",
            // Not a statement: `join` on a string, no receiver chain.
            "stmt = ', '.join(parts)",
        ] {
            let src = format!(
                "{imports}def f(name, sort, parts, cond, stmt):\n    {body}\n    return stmt\n"
            );
            assert!(no_node_sanitizes(&src, Cap::SQL_QUERY), "{body}");
        }
    }

    #[test]
    fn core_tables_are_column_sources() {
        let header = "from sqlalchemy import Table, select\nusers = Table('users', meta)\n";
        for (body, leaf) in [
            (
                "stmt = select(users).where(users.c.id == uid).order_by(users.c.name)",
                "order_by",
            ),
            (
                "stmt = select(users.c.id, users.c.name).where(users.c.id == uid)",
                "where",
            ),
            (
                "stmt = select(users).order_by(users.columns.name)",
                "order_by",
            ),
        ] {
            let src = format!("{header}def f(uid):\n    {body}\n    return stmt\n");
            assert!(!labels_of(&src, leaf).is_empty(), "{body}");
            assert!(all_sanitize(&src, leaf, Cap::SQL_QUERY), "{body}");
        }
        // A name that is a parameter, or is also bound to something else, is
        // not known to be a table.
        for (header, params) in [
            ("from sqlalchemy import Table, select\n", "uid, users"),
            (
                "from sqlalchemy import Table, select\nusers = Table('users', meta)\nusers = 'users'\n",
                "uid",
            ),
        ] {
            let src = format!(
                "{header}def f({params}):\n    stmt = select(User).order_by(users)\n    return stmt\n"
            );
            assert!(no_node_sanitizes(&src, Cap::SQL_QUERY), "{header} {params}");
        }
    }

    #[test]
    fn clause_on_a_statement_variable_needs_a_bound_history() {
        let imports = "from sqlalchemy import select, text\n";
        // The clause is only neutralised when every binding of the variable is
        // a bound statement; anything else may already hold raw SQL.
        for body in [
            // A parameter.
            "stmt = stmt.where(User.id == name)",
            // A raw splice earlier in the chain.
            "stmt = select(User).where(text(f\"n = '{name}'\"))\n    stmt = stmt.where(User.id == 1)",
            // Rebound to text.
            "stmt = select(User)\n    stmt = text(name)\n    stmt = stmt.where(User.id == 1)",
            "stmt = select(User)\n    stmt += text(name)\n    stmt = stmt.where(User.id == 1)",
            // A loop target.
            "stmt = select(User)\n    for stmt in parts:\n        stmt = stmt.where(User.id == 1)",
        ] {
            let src = format!("{imports}def f(name, parts, stmt):\n    {body}\n    return stmt\n");
            assert!(none_sanitize(&src, "where", Cap::SQL_QUERY), "{body}");
        }
    }

    #[test]
    fn statement_roots_need_a_sqlalchemy_import() {
        let src = "def f(url):\n    r = delete(url)\n    return r\n";
        assert!(none_sanitize(src, "delete", Cap::SQL_QUERY));
        let src =
            "from sqlalchemy import delete\ndef f(uid):\n    r = delete(User)\n    return r\n";
        assert!(all_sanitize(src, "delete", Cap::SQL_QUERY));
        let src = "from requests import delete\ndef f(url):\n    r = delete(url)\n    return r\n";
        assert!(none_sanitize(src, "delete", Cap::SQL_QUERY));
    }

    #[test]
    fn executing_a_bound_statement_is_neutralised_but_raw_text_is_not() {
        let imports = "from sqlalchemy import select, text\n";
        for body in [
            "return session.execute(select(User).where(User.name == name))",
            "return session.execute(select(User).where(User.name == name), {'x': 1})",
            "return session.execute(select(User).where(User.name == name).order_by(User.id))",
        ] {
            let src = format!("{imports}def f(session, name):\n    {body}\n");
            assert!(all_sanitize(&src, "execute", Cap::SQL_QUERY), "{body}");
        }
        for body in [
            "return session.execute(select(User).where(text(f\"n = '{name}'\")))",
            "return session.execute(text(f\"select 1 where n = '{name}'\"))",
            "return session.execute(f\"select 1 where n = '{name}'\")",
            "return session.execute(stmt)",
        ] {
            let src = format!("{imports}def f(session, name, stmt):\n    {body}\n");
            assert!(none_sanitize(&src, "execute", Cap::SQL_QUERY), "{body}");
        }
    }
}

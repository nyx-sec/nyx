//! Lossless-cast recogniser for `rs.memory.narrow_cast`.
//!
//! The pattern query is purely syntactic and matches every `as u8/i8/u16/i16`.
//! A cast is only a truncation risk when the value can be out of range for the
//! target.  This module suppresses the casts whose range is provable from the
//! local syntax alone, with no type guessing:
//!
//! * a unit variant of an enum declared in the same file (`Kind::A as u8`,
//!   `*self as u8` or `Self::A as u8` inside `impl Kind`) when the enum has a
//!   `#[repr(int)]` no wider than the target, or has no repr, no explicit
//!   discriminants, no fields and at most 128 variants;
//! * an integer literal, or a same-file `const` with an integer literal
//!   initialiser, that fits the target;
//! * `expr & LIT` where `LIT` fits the target (the mask bounds the result);
//! * a comparison or `&&` / `||` expression, and `true` / `false` (a `bool`);
//! * an ASCII character literal.
//!
//! Everything else (`v.len() as u16`, `n as u8`, `x as i16`) keeps firing.

use tree_sitter::Node;

/// Inclusive upper bound of the non-negative range shared by the target type.
fn target_max(to: &str) -> Option<u128> {
    match to {
        "u8" => Some(u8::MAX as u128),
        "i8" => Some(i8::MAX as u128),
        "u16" => Some(u16::MAX as u128),
        "i16" => Some(i16::MAX as u128),
        _ => None,
    }
}

fn int_bits(ty: &str) -> Option<(u32, bool)> {
    match ty {
        "u8" => Some((8, false)),
        "i8" => Some((8, true)),
        "u16" => Some((16, false)),
        "i16" => Some((16, true)),
        "u32" => Some((32, false)),
        "i32" => Some((32, true)),
        "u64" => Some((64, false)),
        "i64" => Some((64, true)),
        "u128" => Some((128, false)),
        "i128" => Some((128, true)),
        "usize" => Some((64, false)),
        "isize" => Some((64, true)),
        _ => None,
    }
}

fn unwrap_parens(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(c) => n = c,
            None => break,
        }
    }
    n
}

fn parse_int_literal(text: &str) -> Option<u128> {
    let t: String = text.chars().filter(|c| *c != '_').collect();
    let (digits, radix) = if let Some(r) = t.strip_prefix("0x") {
        (r.to_string(), 16)
    } else if let Some(r) = t.strip_prefix("0b") {
        (r.to_string(), 2)
    } else if let Some(r) = t.strip_prefix("0o") {
        (r.to_string(), 8)
    } else {
        (t, 10)
    };
    // Drop an integer type suffix (`255u8`).  For radix 16 the digits include
    // `a-f`, so cut at the first `u`/`i`, which are not hex digits.
    let end = digits.find(['u', 'i']).unwrap_or(digits.len());
    u128::from_str_radix(&digits[..end], radix).ok()
}

/// True when the `as` cast at `cast` (a `type_cast_expression`) provably fits.
pub fn is_provably_lossless_cast(cast: Node, bytes: &[u8]) -> bool {
    let (Some(value), Some(ty)) = (
        cast.child_by_field_name("value"),
        cast.child_by_field_name("type"),
    ) else {
        return false;
    };
    let Ok(to) = ty.utf8_text(bytes) else {
        return false;
    };
    let Some(max) = target_max(to) else {
        return false;
    };
    value_fits(unwrap_parens(value), to, max, bytes)
}

fn value_fits(value: Node, to: &str, max: u128, bytes: &[u8]) -> bool {
    match value.kind() {
        "integer_literal" => value
            .utf8_text(bytes)
            .ok()
            .and_then(parse_int_literal)
            .is_some_and(|v| v <= max),
        "boolean_literal" => true,
        "char_literal" => value
            .utf8_text(bytes)
            .is_ok_and(|t| t.is_ascii() && (t.len() == 3 || (t.len() == 4 && t.starts_with("b'")))),
        "identifier" => value
            .utf8_text(bytes)
            .ok()
            .filter(|n| is_screaming_case(n))
            .and_then(|n| const_literal_value(value, n, bytes))
            .is_some_and(|v| v <= max),
        "binary_expression" => {
            let Some(op) = value.child_by_field_name("operator") else {
                return false;
            };
            match op.kind() {
                "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => true,
                "&" => ["left", "right"].iter().any(|f| {
                    value
                        .child_by_field_name(f)
                        .map(unwrap_parens)
                        .is_some_and(|side| mask_literal_fits(side, max, bytes))
                }),
                _ => false,
            }
        }
        "scoped_identifier" => enum_variant_fits(value, to, bytes),
        "unary_expression" => {
            // `*self` inside `impl Enum`
            let is_deref = value.child(0).is_some_and(|c| c.kind() == "*");
            is_deref
                && value
                    .named_child(0)
                    .is_some_and(|inner| inner.kind() == "self" && self_enum_fits(inner, to, bytes))
        }
        "self" => self_enum_fits(value, to, bytes),
        _ => false,
    }
}

fn mask_literal_fits(side: Node, max: u128, bytes: &[u8]) -> bool {
    match side.kind() {
        "integer_literal" => side
            .utf8_text(bytes)
            .ok()
            .and_then(parse_int_literal)
            .is_some_and(|v| v <= max),
        "identifier" => side
            .utf8_text(bytes)
            .ok()
            .filter(|n| is_screaming_case(n))
            .and_then(|n| const_literal_value(side, n, bytes))
            .is_some_and(|v| v <= max),
        _ => false,
    }
}

fn is_screaming_case(name: &str) -> bool {
    name.len() > 1
        && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn root_of(mut n: Node) -> Node {
    while let Some(p) = n.parent() {
        n = p;
    }
    n
}

/// Collect every node of `kind` below `root`.
fn nodes_of_kind<'a>(root: Node<'a>, kind: &str) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == kind {
            out.push(n);
        }
        let mut w = n.walk();
        stack.extend(n.children(&mut w));
    }
    out
}

/// Value of the one `const NAME: T = <integer literal>;` in the file.
fn const_literal_value(at: Node, name: &str, bytes: &[u8]) -> Option<u128> {
    let mut found: Option<u128> = None;
    let mut count = 0;
    for c in nodes_of_kind(root_of(at), "const_item") {
        if c.child_by_field_name("name")?.utf8_text(bytes).ok()? == name {
            count += 1;
            let v = c.child_by_field_name("value")?;
            found = (v.kind() == "integer_literal")
                .then(|| parse_int_literal(v.utf8_text(bytes).ok()?))
                .flatten();
        }
    }
    if count == 1 { found } else { None }
}

/// `repr` integer types attached to an enum item, via preceding attributes.
fn enum_repr(item: Node, bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut prev = item.prev_named_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {
                if let Ok(t) = p.utf8_text(bytes)
                    && let Some(i) = t.find("repr(")
                {
                    let rest = &t[i + 5..];
                    if let Some(j) = rest.find(')') {
                        out.extend(rest[..j].split(',').map(|s| s.trim().to_string()));
                    }
                }
            }
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        prev = p.prev_named_sibling();
    }
    out
}

/// True when casting a unit variant of enum `item` to `to` cannot truncate.
fn enum_fits(item: Node, to: &str, bytes: &[u8]) -> bool {
    let Some(list) = item.child_by_field_name("body") else {
        return false;
    };
    let mut variants = 0usize;
    let mut plain = true;
    for i in 0..list.named_child_count() as u32 {
        let Some(v) = list.named_child(i as _) else {
            continue;
        };
        if v.kind() != "enum_variant" {
            continue;
        }
        variants += 1;
        if v.child_by_field_name("body").is_some() || v.child_by_field_name("value").is_some() {
            plain = false;
        }
    }
    let reprs = enum_repr(item, bytes);
    let int_repr = reprs
        .iter()
        .find_map(|r| int_bits(r).map(|b| (r.as_str(), b)));
    let Some((to_bits, to_signed)) = int_bits(to) else {
        return false;
    };
    match int_repr {
        Some((_, (bits, signed))) => {
            // Every discriminant fits `repr`; it fits `to` when `to` is at
            // least as wide and, for a signed repr, also signed.
            if signed {
                to_signed && to_bits >= bits
            } else {
                to_bits > bits || (to_bits == bits && !to_signed)
            }
        }
        // No integer repr: sequential discriminants from 0, so they fit any
        // 8 or 16 bit target while there are at most 128 variants.
        None => reprs.is_empty() && plain && variants <= 128,
    }
}

fn unique_enum<'a>(at: Node<'a>, name: &str, bytes: &[u8]) -> Option<Node<'a>> {
    let mut hit = None;
    for e in nodes_of_kind(root_of(at), "enum_item") {
        if e.child_by_field_name("name")?.utf8_text(bytes).ok()? == name {
            if hit.is_some() {
                return None;
            }
            hit = Some(e);
        }
    }
    hit
}

fn enum_has_unit_variant(item: Node, variant: &str, bytes: &[u8]) -> bool {
    let Some(list) = item.child_by_field_name("body") else {
        return false;
    };
    (0..list.named_child_count() as u32).any(|i| {
        list.named_child(i as _).is_some_and(|v| {
            v.kind() == "enum_variant"
                && v.child_by_field_name("body").is_none()
                && v.child_by_field_name("name")
                    .and_then(|n| n.utf8_text(bytes).ok())
                    == Some(variant)
        })
    })
}

/// Name of the type the nearest enclosing `impl` is for.
fn enclosing_impl_type<'a>(mut n: Node<'a>, bytes: &'a [u8]) -> Option<&'a str> {
    while let Some(p) = n.parent() {
        if p.kind() == "impl_item" {
            let t = p.child_by_field_name("type")?;
            return (t.kind() == "type_identifier")
                .then(|| t.utf8_text(bytes).ok())
                .flatten();
        }
        n = p;
    }
    None
}

fn enum_variant_fits(path: Node, to: &str, bytes: &[u8]) -> bool {
    let (Some(prefix), Some(variant)) = (
        path.child_by_field_name("path"),
        path.child_by_field_name("name"),
    ) else {
        return false;
    };
    let (Ok(prefix_text), Ok(variant_text)) = (prefix.utf8_text(bytes), variant.utf8_text(bytes))
    else {
        return false;
    };
    let ty = if prefix_text == "Self" {
        match enclosing_impl_type(path, bytes) {
            Some(t) => t,
            None => return false,
        }
    } else {
        // `Kind` or `module::Kind`: the last path segment names the enum.
        prefix_text.rsplit("::").next().unwrap_or(prefix_text)
    };
    unique_enum(path, ty, bytes)
        .is_some_and(|e| enum_has_unit_variant(e, variant_text, bytes) && enum_fits(e, to, bytes))
}

fn self_enum_fits(self_node: Node, to: &str, bytes: &[u8]) -> bool {
    enclosing_impl_type(self_node, bytes)
        .and_then(|t| unique_enum(self_node, t, bytes))
        .is_some_and(|e| enum_fits(e, to, bytes))
}

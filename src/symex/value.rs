//! Symbolic value expression trees.
#![allow(clippy::collapsible_if)]

use std::fmt;

use crate::cfg;
use crate::ssa::ir::{BlockId, SsaValue};
use crate::utils::snippet::truncate_at_char_boundary;

/// Maximum expression tree depth before collapsing to `Unknown`.
pub const MAX_EXPR_DEPTH: u32 = 32;

/// Binary operator for symbolic expressions.
///
/// Local to the symex module; converted from `cfg::BinOp` via `From`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    LeftShift,
    RightShift,
    // Comparison (produce 1/0 as integer values)
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
}

impl From<cfg::BinOp> for Op {
    fn from(b: cfg::BinOp) -> Self {
        match b {
            cfg::BinOp::Add => Op::Add,
            cfg::BinOp::Sub => Op::Sub,
            cfg::BinOp::Mul => Op::Mul,
            cfg::BinOp::Div => Op::Div,
            cfg::BinOp::Mod => Op::Mod,
            cfg::BinOp::BitAnd => Op::BitAnd,
            cfg::BinOp::BitOr => Op::BitOr,
            cfg::BinOp::BitXor => Op::BitXor,
            cfg::BinOp::LeftShift => Op::LeftShift,
            cfg::BinOp::RightShift => Op::RightShift,
            cfg::BinOp::Eq => Op::Eq,
            cfg::BinOp::NotEq => Op::NotEq,
            cfg::BinOp::Lt => Op::Lt,
            cfg::BinOp::LtEq => Op::LtEq,
            cfg::BinOp::Gt => Op::Gt,
            cfg::BinOp::GtEq => Op::GtEq,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Add => write!(f, "+"),
            Op::Sub => write!(f, "-"),
            Op::Mul => write!(f, "*"),
            Op::Div => write!(f, "/"),
            Op::Mod => write!(f, "%"),
            Op::BitAnd => write!(f, "&"),
            Op::BitOr => write!(f, "|"),
            Op::BitXor => write!(f, "^"),
            Op::LeftShift => write!(f, "<<"),
            Op::RightShift => write!(f, ">>"),
            Op::Eq => write!(f, "=="),
            Op::NotEq => write!(f, "!="),
            Op::Lt => write!(f, "<"),
            Op::LtEq => write!(f, "<="),
            Op::Gt => write!(f, ">"),
            Op::GtEq => write!(f, ">="),
        }
    }
}

/// A symbolic expression tree representing how a value is computed.
///
/// Expression trees are depth-bounded by [`MAX_EXPR_DEPTH`]; all construction
/// goes through smart constructors ([`mk_binop`], [`mk_concat`], [`mk_call`],
/// [`mk_phi`]) that enforce this limit.
#[derive(Clone, Debug, PartialEq)]
pub enum SymbolicValue {
    /// Known integer constant.
    Concrete(i64),
    /// Known string constant (quotes already stripped).
    ConcreteStr(String),
    /// Unconstrained symbolic input tied to an SSA value.
    Symbol(SsaValue),
    /// Arithmetic binary operation.
    BinOp(Op, Box<SymbolicValue>, Box<SymbolicValue>),
    /// String concatenation.
    Concat(Box<SymbolicValue>, Box<SymbolicValue>),
    /// Uninterpreted function application.
    Call(String, Vec<SymbolicValue>),
    /// Phi merge (stored structurally; not resolved in single-path mode).
    Phi(Vec<(BlockId, SymbolicValue)>),
    // ── String operations ─────────────────────────────────────
    /// String substring extraction: `str.substring(start, end?)`.
    Substr(
        Box<SymbolicValue>,
        Box<SymbolicValue>,
        Option<Box<SymbolicValue>>,
    ),
    /// String replacement with concrete pattern/replacement: `str.replace(pat, rep)`.
    Replace(Box<SymbolicValue>, String, String),
    /// To lowercase: `str.toLowerCase()`.
    ToLower(Box<SymbolicValue>),
    /// To uppercase: `str.toUpperCase()`.
    ToUpper(Box<SymbolicValue>),
    /// Whitespace trim: `str.trim()`.
    Trim(Box<SymbolicValue>),
    /// String length (returns integer): `strlen(str)`.
    StrLen(Box<SymbolicValue>),
    // ── Encoding/decoding transforms ───────────────────────────
    /// Protective or representation transform applied to inner value.
    /// Preserves taint unconditionally, does NOT sanitize in symex.
    Encode(super::strings::TransformKind, Box<SymbolicValue>),
    /// Decoding/reverse transform applied to inner value.
    Decode(super::strings::TransformKind, Box<SymbolicValue>),
    /// No information (top).
    Unknown,
}

impl SymbolicValue {
    /// Compute the depth of this expression tree.
    ///
    /// Leaf nodes (`Concrete`, `ConcreteStr`, `Symbol`, `Unknown`) have depth 0.
    /// Compound nodes have depth 1 + max(children).
    pub fn depth(&self) -> u32 {
        match self {
            SymbolicValue::Concrete(_)
            | SymbolicValue::ConcreteStr(_)
            | SymbolicValue::Symbol(_)
            | SymbolicValue::Unknown => 0,
            SymbolicValue::BinOp(_, l, r) | SymbolicValue::Concat(l, r) => {
                1 + l.depth().max(r.depth())
            }
            SymbolicValue::Call(_, args) => 1 + args.iter().map(|a| a.depth()).max().unwrap_or(0),
            SymbolicValue::Phi(operands) => {
                1 + operands.iter().map(|(_, v)| v.depth()).max().unwrap_or(0)
            }
            SymbolicValue::ToLower(s)
            | SymbolicValue::ToUpper(s)
            | SymbolicValue::Trim(s)
            | SymbolicValue::StrLen(s)
            | SymbolicValue::Replace(s, _, _)
            | SymbolicValue::Encode(_, s)
            | SymbolicValue::Decode(_, s) => 1 + s.depth(),
            SymbolicValue::Substr(s, start, end) => {
                let max_child = s
                    .depth()
                    .max(start.depth())
                    .max(end.as_ref().map(|e| e.depth()).unwrap_or(0));
                1 + max_child
            }
        }
    }

    /// Returns `true` if this is a known concrete value (int or string).
    pub fn is_concrete(&self) -> bool {
        matches!(
            self,
            SymbolicValue::Concrete(_) | SymbolicValue::ConcreteStr(_)
        )
    }

    /// Extract a concrete integer if this is `Concrete(n)`.
    pub fn as_concrete_int(&self) -> Option<i64> {
        match self {
            SymbolicValue::Concrete(n) => Some(*n),
            _ => None,
        }
    }

    /// Extract a concrete string reference if this is `ConcreteStr(s)`.
    pub fn as_concrete_str(&self) -> Option<&str> {
        match self {
            SymbolicValue::ConcreteStr(s) => Some(s),
            _ => None,
        }
    }
}

//  Smart constructors, all tree-building goes through these

/// Build a binary arithmetic expression with concrete folding and depth bounding.
///
/// - If both operands are `Concrete`, folds via `checked_*` arithmetic.
///   Overflow or division by zero produces `Unknown`.
/// - If the resulting tree exceeds `MAX_EXPR_DEPTH`, returns `Unknown`.
pub fn mk_binop(op: Op, lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    // Concrete folding
    if let (SymbolicValue::Concrete(a), SymbolicValue::Concrete(b)) = (&lhs, &rhs) {
        let result = match op {
            Op::Add => a.checked_add(*b),
            Op::Sub => a.checked_sub(*b),
            Op::Mul => a.checked_mul(*b),
            Op::Div => {
                if *b == 0 {
                    None
                } else {
                    a.checked_div(*b)
                }
            }
            Op::Mod => {
                if *b == 0 {
                    None
                } else {
                    a.checked_rem(*b)
                }
            }
            // Bitwise, &, |, ^ cannot overflow on i64
            Op::BitAnd => Some(*a & *b),
            Op::BitOr => Some(*a | *b),
            Op::BitXor => Some(*a ^ *b),
            // Shifts, bounds-checked to 0..=63 (i64 width)
            Op::LeftShift => {
                if *b < 0 || *b > 63 {
                    None
                } else {
                    a.checked_shl(*b as u32)
                }
            }
            Op::RightShift => {
                if *b < 0 || *b > 63 {
                    None
                } else {
                    a.checked_shr(*b as u32)
                }
            }
            // Comparisons, produce 1 (true) or 0 (false)
            Op::Eq => Some(if *a == *b { 1 } else { 0 }),
            Op::NotEq => Some(if *a != *b { 1 } else { 0 }),
            Op::Lt => Some(if *a < *b { 1 } else { 0 }),
            Op::LtEq => Some(if *a <= *b { 1 } else { 0 }),
            Op::Gt => Some(if *a > *b { 1 } else { 0 }),
            Op::GtEq => Some(if *a >= *b { 1 } else { 0 }),
        };
        return match result {
            Some(n) => SymbolicValue::Concrete(n),
            None => SymbolicValue::Unknown,
        };
    }

    // Depth check
    let depth = 1 + lhs.depth().max(rhs.depth());
    if depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::BinOp(op, Box::new(lhs), Box::new(rhs))
}

/// Build a string concatenation expression with concrete folding and depth bounding.
///
/// - If both operands are `ConcreteStr`, folds to a single `ConcreteStr`.
/// - If the resulting tree exceeds `MAX_EXPR_DEPTH`, returns `Unknown`.
pub fn mk_concat(lhs: SymbolicValue, rhs: SymbolicValue) -> SymbolicValue {
    // Concrete folding: ConcreteStr + ConcreteStr
    if let (SymbolicValue::ConcreteStr(a), SymbolicValue::ConcreteStr(b)) = (&lhs, &rhs) {
        return SymbolicValue::ConcreteStr(format!("{}{}", a, b));
    }

    // Depth check
    let depth = 1 + lhs.depth().max(rhs.depth());
    if depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Concat(Box::new(lhs), Box::new(rhs))
}

/// Build an uninterpreted function call expression with depth bounding.
pub fn mk_call(name: String, args: Vec<SymbolicValue>) -> SymbolicValue {
    let max_arg_depth = args.iter().map(|a| a.depth()).max().unwrap_or(0);
    if 1 + max_arg_depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Call(name, args)
}

/// Build a phi merge expression with simplification and depth bounding.
///
/// - Single operand: unwrap to the operand value.
/// - All operands identical: fold to one value.
/// - Otherwise: build `Phi(...)` with depth check.
pub fn mk_phi(operands: Vec<(BlockId, SymbolicValue)>) -> SymbolicValue {
    if operands.is_empty() {
        return SymbolicValue::Unknown;
    }
    if operands.len() == 1 {
        return operands.into_iter().next().unwrap().1;
    }
    // All-same fold
    if operands.windows(2).all(|w| w[0].1 == w[1].1) {
        return operands.into_iter().next().unwrap().1;
    }

    // Depth check
    let max_depth = operands.iter().map(|(_, v)| v.depth()).max().unwrap_or(0);
    if 1 + max_depth > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }

    SymbolicValue::Phi(operands)
}

//  String operation smart constructors

/// Build a `Trim` expression with concrete folding and depth bounding.
pub fn mk_trim(s: SymbolicValue) -> SymbolicValue {
    if let Some(result) = s.as_concrete_str().and_then(|cs| {
        super::strings::evaluate_string_op_concrete(&super::strings::StringMethod::Trim, cs)
    }) {
        return result;
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::Trim(Box::new(s))
}

/// Build a `ToLower` expression with concrete folding and depth bounding.
pub fn mk_to_lower(s: SymbolicValue) -> SymbolicValue {
    if let Some(result) = s.as_concrete_str().and_then(|cs| {
        super::strings::evaluate_string_op_concrete(&super::strings::StringMethod::ToLower, cs)
    }) {
        return result;
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::ToLower(Box::new(s))
}

/// Build a `ToUpper` expression with concrete folding and depth bounding.
pub fn mk_to_upper(s: SymbolicValue) -> SymbolicValue {
    if let Some(result) = s.as_concrete_str().and_then(|cs| {
        super::strings::evaluate_string_op_concrete(&super::strings::StringMethod::ToUpper, cs)
    }) {
        return result;
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::ToUpper(Box::new(s))
}

/// Build a `Replace` expression with concrete folding and depth bounding.
pub fn mk_replace(s: SymbolicValue, pattern: String, replacement: String) -> SymbolicValue {
    if let Some(result) = s.as_concrete_str().and_then(|cs| {
        super::strings::evaluate_string_op_concrete(
            &super::strings::StringMethod::Replace {
                pattern: pattern.clone(),
                replacement: replacement.clone(),
            },
            cs,
        )
    }) {
        return result;
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::Replace(Box::new(s), pattern, replacement)
}

/// Build a `Substr` expression with concrete folding and depth bounding.
pub fn mk_substr(
    s: SymbolicValue,
    start: SymbolicValue,
    end: Option<SymbolicValue>,
) -> SymbolicValue {
    // Concrete folding: all three are concrete
    if let Some(cs) = s.as_concrete_str() {
        if let Some(i) = start.as_concrete_int() {
            let i = i.max(0) as usize;
            match end.as_ref().and_then(|e| e.as_concrete_int()) {
                Some(j) => {
                    let j = j.max(0) as usize;
                    let result = cs.get(i..j.min(cs.len())).unwrap_or("");
                    return SymbolicValue::ConcreteStr(result.to_owned());
                }
                None if end.is_none() => {
                    let result = cs.get(i..).unwrap_or("");
                    return SymbolicValue::ConcreteStr(result.to_owned());
                }
                _ => {} // end is Some but not concrete, can't fold
            }
        }
    }

    let max_child = s
        .depth()
        .max(start.depth())
        .max(end.as_ref().map(|e| e.depth()).unwrap_or(0));
    if 1 + max_child > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::Substr(Box::new(s), Box::new(start), end.map(Box::new))
}

/// Build a `StrLen` expression with concrete folding and depth bounding.
pub fn mk_strlen(s: SymbolicValue) -> SymbolicValue {
    if let Some(result) = s.as_concrete_str().and_then(|cs| {
        super::strings::evaluate_string_op_concrete(&super::strings::StringMethod::StrLen, cs)
    }) {
        return result;
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::StrLen(Box::new(s))
}

// ── Encoding/decoding smart constructors ───────────────────────────

/// Build an `Encode` expression with concrete folding and depth bounding.
///
/// When `s` is a `ConcreteStr`, applies the encoding via witness-quality
/// helpers and returns a folded `ConcreteStr`. Otherwise returns a
/// structured `Encode` node.
pub fn mk_encode(kind: super::strings::TransformKind, s: SymbolicValue) -> SymbolicValue {
    if let Some(cs) = s.as_concrete_str() {
        if let Some(encoded) = super::strings::encode_concrete_for_witness(kind, cs) {
            return SymbolicValue::ConcreteStr(encoded);
        }
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::Encode(kind, Box::new(s))
}

/// Build a `Decode` expression with concrete folding and depth bounding.
pub fn mk_decode(kind: super::strings::TransformKind, s: SymbolicValue) -> SymbolicValue {
    if let Some(cs) = s.as_concrete_str() {
        if let Some(decoded) = super::strings::decode_concrete_for_witness(kind, cs) {
            return SymbolicValue::ConcreteStr(decoded);
        }
    }
    if 1 + s.depth() > MAX_EXPR_DEPTH {
        return SymbolicValue::Unknown;
    }
    SymbolicValue::Decode(kind, Box::new(s))
}

//  Display, human-readable witness strings

/// Maximum length for the Display output before truncation.
const MAX_DISPLAY_LEN: usize = 256;
/// Maximum length for inline string constants in Display.
const MAX_STR_DISPLAY_LEN: usize = 64;

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use an internal formatter, then truncate if needed.  UTF-8-safe
        // truncation, `ConcreteStr` may carry localised text from source
        // (e.g. Cyrillic / Gurmukhi regex literals).
        let s = display_inner(self);
        if s.len() > MAX_DISPLAY_LEN {
            write!(f, "{}...", truncate_at_char_boundary(&s, MAX_DISPLAY_LEN))
        } else {
            write!(f, "{}", s)
        }
    }
}

fn display_inner(val: &SymbolicValue) -> String {
    match val {
        SymbolicValue::Concrete(n) => format!("{}", n),
        SymbolicValue::ConcreteStr(s) => {
            if s.len() > MAX_STR_DISPLAY_LEN {
                format!(
                    "\"{}...\"",
                    truncate_at_char_boundary(s, MAX_STR_DISPLAY_LEN)
                )
            } else {
                format!("\"{}\"", s)
            }
        }
        SymbolicValue::Symbol(v) => format!("sym(v{})", v.0),
        SymbolicValue::BinOp(op, l, r) => {
            format!("({} {} {})", display_inner(l), op, display_inner(r))
        }
        SymbolicValue::Concat(l, r) => {
            format!("({} ++ {})", display_inner(l), display_inner(r))
        }
        SymbolicValue::Call(name, args) => {
            let arg_strs: Vec<String> = args.iter().map(display_inner).collect();
            format!("{}({})", name, arg_strs.join(", "))
        }
        SymbolicValue::Phi(operands) => {
            let parts: Vec<String> = operands
                .iter()
                .map(|(bid, v)| format!("B{}:{}", bid.0, display_inner(v)))
                .collect();
            format!("phi({})", parts.join(", "))
        }
        SymbolicValue::Trim(s) => format!("{}.trim()", display_inner(s)),
        SymbolicValue::ToLower(s) => format!("{}.toLowerCase()", display_inner(s)),
        SymbolicValue::ToUpper(s) => format!("{}.toUpperCase()", display_inner(s)),
        SymbolicValue::Replace(s, pat, rep) => {
            format!("{}.replace(\"{}\", \"{}\")", display_inner(s), pat, rep)
        }
        SymbolicValue::Substr(s, start, end) => match end {
            Some(e) => format!(
                "{}.substr({}, {})",
                display_inner(s),
                display_inner(start),
                display_inner(e)
            ),
            None => format!("{}.substr({})", display_inner(s), display_inner(start)),
        },
        SymbolicValue::StrLen(s) => format!("strlen({})", display_inner(s)),
        SymbolicValue::Encode(kind, s) => {
            format!("{}({})", kind.display_name(), display_inner(s))
        }
        SymbolicValue::Decode(kind, s) => {
            format!("decode_{}({})", kind.display_name(), display_inner(s))
        }
        SymbolicValue::Unknown => "?".to_string(),
    }
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_fold_add() {
        assert_eq!(
            mk_binop(
                Op::Add,
                SymbolicValue::Concrete(3),
                SymbolicValue::Concrete(5)
            ),
            SymbolicValue::Concrete(8)
        );
    }

    #[test]
    fn concrete_fold_sub() {
        assert_eq!(
            mk_binop(
                Op::Sub,
                SymbolicValue::Concrete(10),
                SymbolicValue::Concrete(3)
            ),
            SymbolicValue::Concrete(7)
        );
    }

    #[test]
    fn concrete_fold_mul() {
        assert_eq!(
            mk_binop(
                Op::Mul,
                SymbolicValue::Concrete(4),
                SymbolicValue::Concrete(7)
            ),
            SymbolicValue::Concrete(28)
        );
    }

    #[test]
    fn concrete_fold_div() {
        assert_eq!(
            mk_binop(
                Op::Div,
                SymbolicValue::Concrete(15),
                SymbolicValue::Concrete(3)
            ),
            SymbolicValue::Concrete(5)
        );
    }

    #[test]
    fn concrete_fold_mod() {
        assert_eq!(
            mk_binop(
                Op::Mod,
                SymbolicValue::Concrete(17),
                SymbolicValue::Concrete(5)
            ),
            SymbolicValue::Concrete(2)
        );
    }

    #[test]
    fn overflow_add() {
        assert_eq!(
            mk_binop(
                Op::Add,
                SymbolicValue::Concrete(i64::MAX),
                SymbolicValue::Concrete(1)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn overflow_sub() {
        assert_eq!(
            mk_binop(
                Op::Sub,
                SymbolicValue::Concrete(i64::MIN),
                SymbolicValue::Concrete(1)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn overflow_mul() {
        assert_eq!(
            mk_binop(
                Op::Mul,
                SymbolicValue::Concrete(i64::MAX),
                SymbolicValue::Concrete(2)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn div_by_zero() {
        assert_eq!(
            mk_binop(
                Op::Div,
                SymbolicValue::Concrete(10),
                SymbolicValue::Concrete(0)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn mod_by_zero() {
        assert_eq!(
            mk_binop(
                Op::Mod,
                SymbolicValue::Concrete(10),
                SymbolicValue::Concrete(0)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn min_mod_neg_one() {
        // i64::MIN % -1 overflows
        assert_eq!(
            mk_binop(
                Op::Mod,
                SymbolicValue::Concrete(i64::MIN),
                SymbolicValue::Concrete(-1)
            ),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn depth_bounding() {
        // Build a chain of depth 33, should collapse to Unknown
        let mut val = SymbolicValue::Symbol(SsaValue(0));
        for _ in 0..MAX_EXPR_DEPTH {
            val = mk_binop(Op::Add, val, SymbolicValue::Concrete(1));
        }
        // At depth == MAX_EXPR_DEPTH, should still be fine (depth check is >)
        assert_ne!(val, SymbolicValue::Unknown);
        assert_eq!(val.depth(), MAX_EXPR_DEPTH);

        // One more pushes past the limit
        val = mk_binop(Op::Add, val, SymbolicValue::Concrete(1));
        assert_eq!(val, SymbolicValue::Unknown);
    }

    #[test]
    fn concat_fold() {
        assert_eq!(
            mk_concat(
                SymbolicValue::ConcreteStr("hello ".into()),
                SymbolicValue::ConcreteStr("world".into()),
            ),
            SymbolicValue::ConcreteStr("hello world".into())
        );
    }

    #[test]
    fn concat_no_int_coercion() {
        // ConcreteStr + Concrete(int) should NOT fold, no type coercion
        let result = mk_concat(
            SymbolicValue::ConcreteStr("val=".into()),
            SymbolicValue::Concrete(42),
        );
        assert!(matches!(result, SymbolicValue::Concat(_, _)));
    }

    #[test]
    fn concat_depth_bounding() {
        let mut val = SymbolicValue::ConcreteStr("a".into());
        for _ in 0..MAX_EXPR_DEPTH {
            val = mk_concat(val, SymbolicValue::Symbol(SsaValue(0)));
        }
        assert_eq!(val.depth(), MAX_EXPR_DEPTH);
        val = mk_concat(val, SymbolicValue::Symbol(SsaValue(0)));
        assert_eq!(val, SymbolicValue::Unknown);
    }

    #[test]
    fn phi_single_operand_unwrap() {
        let v = SymbolicValue::Concrete(42);
        assert_eq!(mk_phi(vec![(BlockId(0), v.clone())]), v);
    }

    #[test]
    fn phi_all_same_fold() {
        let v = SymbolicValue::Concrete(7);
        assert_eq!(
            mk_phi(vec![(BlockId(0), v.clone()), (BlockId(1), v.clone())]),
            v
        );
    }

    #[test]
    fn phi_different_values() {
        let result = mk_phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Concrete(2)),
        ]);
        assert!(matches!(result, SymbolicValue::Phi(_)));
    }

    #[test]
    fn phi_empty() {
        assert_eq!(mk_phi(vec![]), SymbolicValue::Unknown);
    }

    #[test]
    fn call_depth_bounding() {
        let deep = {
            let mut v = SymbolicValue::Symbol(SsaValue(0));
            for _ in 0..MAX_EXPR_DEPTH {
                v = mk_binop(Op::Add, v, SymbolicValue::Concrete(1));
            }
            v
        };
        // deep has depth == MAX_EXPR_DEPTH; wrapping in Call would exceed
        let result = mk_call("f".into(), vec![deep]);
        assert_eq!(result, SymbolicValue::Unknown);
    }

    #[test]
    fn depth_leaf_nodes() {
        assert_eq!(SymbolicValue::Concrete(0).depth(), 0);
        assert_eq!(SymbolicValue::ConcreteStr("x".into()).depth(), 0);
        assert_eq!(SymbolicValue::Symbol(SsaValue(0)).depth(), 0);
        assert_eq!(SymbolicValue::Unknown.depth(), 0);
    }

    #[test]
    fn depth_nested() {
        let v = mk_binop(
            Op::Add,
            mk_binop(
                Op::Mul,
                SymbolicValue::Concrete(2),
                SymbolicValue::Symbol(SsaValue(0)),
            ),
            SymbolicValue::Concrete(1),
        );
        assert_eq!(v.depth(), 2);
    }

    #[test]
    fn is_concrete_checks() {
        assert!(SymbolicValue::Concrete(1).is_concrete());
        assert!(SymbolicValue::ConcreteStr("x".into()).is_concrete());
        assert!(!SymbolicValue::Symbol(SsaValue(0)).is_concrete());
        assert!(!SymbolicValue::Unknown.is_concrete());
    }

    #[test]
    fn as_concrete_int_checks() {
        assert_eq!(SymbolicValue::Concrete(42).as_concrete_int(), Some(42));
        assert_eq!(
            SymbolicValue::ConcreteStr("x".into()).as_concrete_int(),
            None
        );
        assert_eq!(SymbolicValue::Unknown.as_concrete_int(), None);
    }

    #[test]
    fn as_concrete_str_checks() {
        assert_eq!(
            SymbolicValue::ConcreteStr("hi".into()).as_concrete_str(),
            Some("hi")
        );
        assert_eq!(SymbolicValue::Concrete(1).as_concrete_str(), None);
    }

    #[test]
    fn display_concrete() {
        assert_eq!(format!("{}", SymbolicValue::Concrete(42)), "42");
    }

    #[test]
    fn display_concrete_str() {
        assert_eq!(
            format!("{}", SymbolicValue::ConcreteStr("hello".into())),
            "\"hello\""
        );
    }

    #[test]
    fn display_symbol() {
        assert_eq!(format!("{}", SymbolicValue::Symbol(SsaValue(3))), "sym(v3)");
    }

    #[test]
    fn display_binop() {
        let v = mk_binop(
            Op::Add,
            SymbolicValue::Symbol(SsaValue(1)),
            SymbolicValue::Concrete(2),
        );
        assert_eq!(format!("{}", v), "(sym(v1) + 2)");
    }

    #[test]
    fn display_concat() {
        let v = mk_concat(
            SymbolicValue::ConcreteStr("SELECT ".into()),
            SymbolicValue::Symbol(SsaValue(5)),
        );
        assert_eq!(format!("{}", v), "(\"SELECT \" ++ sym(v5))");
    }

    #[test]
    fn display_call() {
        let v = mk_call("parseInt".into(), vec![SymbolicValue::Symbol(SsaValue(2))]);
        assert_eq!(format!("{}", v), "parseInt(sym(v2))");
    }

    #[test]
    fn display_phi() {
        let v = mk_phi(vec![
            (BlockId(0), SymbolicValue::Concrete(1)),
            (BlockId(1), SymbolicValue::Symbol(SsaValue(3))),
        ]);
        assert_eq!(format!("{}", v), "phi(B0:1, B1:sym(v3))");
    }

    #[test]
    fn display_unknown() {
        assert_eq!(format!("{}", SymbolicValue::Unknown), "?");
    }

    #[test]
    fn display_truncation() {
        // Build a very long expression
        let mut v = SymbolicValue::Symbol(SsaValue(0));
        for i in 1..30 {
            v = mk_binop(Op::Add, v, SymbolicValue::Symbol(SsaValue(i)));
        }
        let s = format!("{}", v);
        assert!(s.len() <= MAX_DISPLAY_LEN + 3); // +3 for "..."
        if s.len() > MAX_DISPLAY_LEN {
            assert!(s.ends_with("..."));
        }
    }

    #[test]
    fn display_long_string_truncation() {
        let long = "a".repeat(100);
        let v = SymbolicValue::ConcreteStr(long);
        let s = format!("{}", v);
        assert!(s.contains("..."));
        assert!(s.len() <= MAX_STR_DISPLAY_LEN + 6); // quotes + "..."
    }

    #[test]
    fn op_from_cfg_binop() {
        assert_eq!(Op::from(cfg::BinOp::Add), Op::Add);
        assert_eq!(Op::from(cfg::BinOp::Sub), Op::Sub);
        assert_eq!(Op::from(cfg::BinOp::Mul), Op::Mul);
        assert_eq!(Op::from(cfg::BinOp::Div), Op::Div);
        assert_eq!(Op::from(cfg::BinOp::Mod), Op::Mod);
    }

    // ── Bitwise and comparison operation tests ──────────────

    #[test]
    fn op_from_cfg_binop_extended() {
        assert_eq!(Op::from(cfg::BinOp::BitAnd), Op::BitAnd);
        assert_eq!(Op::from(cfg::BinOp::BitOr), Op::BitOr);
        assert_eq!(Op::from(cfg::BinOp::BitXor), Op::BitXor);
        assert_eq!(Op::from(cfg::BinOp::LeftShift), Op::LeftShift);
        assert_eq!(Op::from(cfg::BinOp::RightShift), Op::RightShift);
        assert_eq!(Op::from(cfg::BinOp::Eq), Op::Eq);
        assert_eq!(Op::from(cfg::BinOp::NotEq), Op::NotEq);
        assert_eq!(Op::from(cfg::BinOp::Lt), Op::Lt);
        assert_eq!(Op::from(cfg::BinOp::LtEq), Op::LtEq);
        assert_eq!(Op::from(cfg::BinOp::Gt), Op::Gt);
        assert_eq!(Op::from(cfg::BinOp::GtEq), Op::GtEq);
    }

    #[test]
    fn display_bitwise_ops() {
        assert_eq!(format!("{}", Op::BitAnd), "&");
        assert_eq!(format!("{}", Op::BitOr), "|");
        assert_eq!(format!("{}", Op::BitXor), "^");
        assert_eq!(format!("{}", Op::LeftShift), "<<");
        assert_eq!(format!("{}", Op::RightShift), ">>");
    }

    #[test]
    fn display_comparison_ops() {
        assert_eq!(format!("{}", Op::Eq), "==");
        assert_eq!(format!("{}", Op::NotEq), "!=");
        assert_eq!(format!("{}", Op::Lt), "<");
        assert_eq!(format!("{}", Op::LtEq), "<=");
        assert_eq!(format!("{}", Op::Gt), ">");
        assert_eq!(format!("{}", Op::GtEq), ">=");
    }

    #[test]
    fn concrete_fold_bit_and() {
        assert_eq!(mk_binop(Op::BitAnd, c(0xFF), c(0x0F)), c(0x0F));
        assert_eq!(mk_binop(Op::BitAnd, c(-1), c(0x07)), c(0x07));
    }

    #[test]
    fn concrete_fold_bit_or() {
        assert_eq!(mk_binop(Op::BitOr, c(0xF0), c(0x0F)), c(0xFF));
    }

    #[test]
    fn concrete_fold_bit_xor() {
        assert_eq!(mk_binop(Op::BitXor, c(0xFF), c(0x0F)), c(0xF0));
        // x ^ x = 0
        assert_eq!(mk_binop(Op::BitXor, c(42), c(42)), c(0));
    }

    #[test]
    fn concrete_fold_left_shift() {
        assert_eq!(mk_binop(Op::LeftShift, c(1), c(3)), c(8));
        assert_eq!(mk_binop(Op::LeftShift, c(0x0F), c(4)), c(0xF0));
    }

    #[test]
    fn concrete_fold_right_shift() {
        assert_eq!(mk_binop(Op::RightShift, c(16), c(2)), c(4));
        assert_eq!(mk_binop(Op::RightShift, c(0xFF), c(4)), c(0x0F));
    }

    #[test]
    fn left_shift_negative_amount() {
        assert_eq!(mk_binop(Op::LeftShift, c(1), c(-1)), SymbolicValue::Unknown);
    }

    #[test]
    fn left_shift_amount_64() {
        assert_eq!(mk_binop(Op::LeftShift, c(1), c(64)), SymbolicValue::Unknown);
    }

    #[test]
    fn left_shift_amount_63() {
        // Max valid shift, should not panic
        let result = mk_binop(Op::LeftShift, c(1), c(63));
        assert_eq!(result, c(1i64 << 63));
    }

    #[test]
    fn right_shift_negative_amount() {
        assert_eq!(
            mk_binop(Op::RightShift, c(1), c(-1)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn right_shift_amount_64() {
        assert_eq!(
            mk_binop(Op::RightShift, c(1), c(64)),
            SymbolicValue::Unknown
        );
    }

    #[test]
    fn concrete_fold_eq_true() {
        assert_eq!(mk_binop(Op::Eq, c(5), c(5)), c(1));
    }

    #[test]
    fn concrete_fold_eq_false() {
        assert_eq!(mk_binop(Op::Eq, c(5), c(3)), c(0));
    }

    #[test]
    fn concrete_fold_neq() {
        assert_eq!(mk_binop(Op::NotEq, c(5), c(3)), c(1));
        assert_eq!(mk_binop(Op::NotEq, c(5), c(5)), c(0));
    }

    #[test]
    fn concrete_fold_lt() {
        assert_eq!(mk_binop(Op::Lt, c(3), c(5)), c(1));
        assert_eq!(mk_binop(Op::Lt, c(5), c(3)), c(0));
        assert_eq!(mk_binop(Op::Lt, c(5), c(5)), c(0));
    }

    #[test]
    fn concrete_fold_lteq() {
        assert_eq!(mk_binop(Op::LtEq, c(3), c(3)), c(1));
        assert_eq!(mk_binop(Op::LtEq, c(4), c(3)), c(0));
    }

    #[test]
    fn concrete_fold_gt() {
        assert_eq!(mk_binop(Op::Gt, c(5), c(3)), c(1));
        assert_eq!(mk_binop(Op::Gt, c(3), c(5)), c(0));
    }

    #[test]
    fn concrete_fold_gteq() {
        assert_eq!(mk_binop(Op::GtEq, c(3), c(3)), c(1));
        assert_eq!(mk_binop(Op::GtEq, c(2), c(3)), c(0));
    }

    /// Helper: shorthand for `SymbolicValue::Concrete`.
    fn c(n: i64) -> SymbolicValue {
        SymbolicValue::Concrete(n)
    }

    // ── String operation tests ──────────────────────────────

    #[test]
    fn mk_trim_concrete_fold() {
        assert_eq!(
            mk_trim(SymbolicValue::ConcreteStr("  hello  ".into())),
            SymbolicValue::ConcreteStr("hello".into())
        );
    }

    #[test]
    fn mk_trim_symbolic() {
        let v = mk_trim(SymbolicValue::Symbol(SsaValue(0)));
        assert!(matches!(v, SymbolicValue::Trim(_)));
        assert_eq!(v.depth(), 1);
    }

    #[test]
    fn mk_to_lower_concrete_fold() {
        assert_eq!(
            mk_to_lower(SymbolicValue::ConcreteStr("ABC".into())),
            SymbolicValue::ConcreteStr("abc".into())
        );
    }

    #[test]
    fn mk_to_upper_concrete_fold() {
        assert_eq!(
            mk_to_upper(SymbolicValue::ConcreteStr("abc".into())),
            SymbolicValue::ConcreteStr("ABC".into())
        );
    }

    #[test]
    fn mk_replace_concrete_fold() {
        assert_eq!(
            mk_replace(
                SymbolicValue::ConcreteStr("a<script>b".into()),
                "<script>".into(),
                "".into(),
            ),
            SymbolicValue::ConcreteStr("ab".into())
        );
    }

    #[test]
    fn mk_replace_symbolic() {
        let v = mk_replace(
            SymbolicValue::Symbol(SsaValue(0)),
            "<".into(),
            "&lt;".into(),
        );
        assert!(matches!(v, SymbolicValue::Replace(_, _, _)));
        assert_eq!(v.depth(), 1);
    }

    #[test]
    fn mk_substr_concrete_fold() {
        assert_eq!(
            mk_substr(
                SymbolicValue::ConcreteStr("hello world".into()),
                SymbolicValue::Concrete(0),
                Some(SymbolicValue::Concrete(5)),
            ),
            SymbolicValue::ConcreteStr("hello".into())
        );
    }

    #[test]
    fn mk_substr_no_end() {
        assert_eq!(
            mk_substr(
                SymbolicValue::ConcreteStr("hello world".into()),
                SymbolicValue::Concrete(6),
                None,
            ),
            SymbolicValue::ConcreteStr("world".into())
        );
    }

    #[test]
    fn mk_strlen_concrete_fold() {
        assert_eq!(
            mk_strlen(SymbolicValue::ConcreteStr("hello".into())),
            SymbolicValue::Concrete(5)
        );
    }

    #[test]
    fn mk_strlen_symbolic() {
        let v = mk_strlen(SymbolicValue::Symbol(SsaValue(0)));
        assert!(matches!(v, SymbolicValue::StrLen(_)));
        assert_eq!(v.depth(), 1);
    }

    #[test]
    fn string_ops_depth_bounding() {
        let mut val = SymbolicValue::Symbol(SsaValue(0));
        for _ in 0..MAX_EXPR_DEPTH {
            val = mk_trim(val);
        }
        // At depth == MAX_EXPR_DEPTH, should still be fine
        assert_eq!(val.depth(), MAX_EXPR_DEPTH);
        // One more pushes past the limit
        val = mk_trim(val);
        assert_eq!(val, SymbolicValue::Unknown);
    }

    #[test]
    fn display_string_ops() {
        let v = mk_trim(SymbolicValue::Symbol(SsaValue(1)));
        assert_eq!(format!("{}", v), "sym(v1).trim()");

        let v = mk_to_lower(SymbolicValue::Symbol(SsaValue(2)));
        assert_eq!(format!("{}", v), "sym(v2).toLowerCase()");

        let v = mk_to_upper(SymbolicValue::Symbol(SsaValue(3)));
        assert_eq!(format!("{}", v), "sym(v3).toUpperCase()");

        let v = mk_replace(
            SymbolicValue::Symbol(SsaValue(4)),
            "<".into(),
            "&lt;".into(),
        );
        assert_eq!(format!("{}", v), "sym(v4).replace(\"<\", \"&lt;\")");

        let v = mk_strlen(SymbolicValue::Symbol(SsaValue(5)));
        assert_eq!(format!("{}", v), "strlen(sym(v5))");

        let v = mk_substr(
            SymbolicValue::Symbol(SsaValue(6)),
            SymbolicValue::Concrete(0),
            Some(SymbolicValue::Concrete(5)),
        );
        assert_eq!(format!("{}", v), "sym(v6).substr(0, 5)");
    }

    // ── Encode/Decode ──────────────────────────────────────────

    #[test]
    fn mk_encode_concrete_folding() {
        use super::super::strings::TransformKind;
        let v = mk_encode(
            TransformKind::HtmlEscape,
            SymbolicValue::ConcreteStr("<b>".into()),
        );
        assert_eq!(v, SymbolicValue::ConcreteStr("&lt;b&gt;".into()));
    }

    #[test]
    fn mk_encode_symbolic_preserves_structure() {
        use super::super::strings::TransformKind;
        let v = mk_encode(TransformKind::UrlEncode, SymbolicValue::Symbol(SsaValue(7)));
        match v {
            SymbolicValue::Encode(kind, inner) => {
                assert_eq!(kind, TransformKind::UrlEncode);
                assert_eq!(*inner, SymbolicValue::Symbol(SsaValue(7)));
            }
            other => panic!("expected Encode, got {:?}", other),
        }
    }

    #[test]
    fn mk_encode_depth_bounding() {
        use super::super::strings::TransformKind;
        // Build a deeply nested expression
        let mut v = SymbolicValue::Symbol(SsaValue(0));
        for _ in 0..MAX_EXPR_DEPTH {
            v = SymbolicValue::Encode(TransformKind::HtmlEscape, Box::new(v));
        }
        // One more should hit the depth bound
        let result = mk_encode(TransformKind::HtmlEscape, v);
        assert_eq!(result, SymbolicValue::Unknown);
    }

    #[test]
    fn mk_decode_concrete_folding() {
        use super::super::strings::TransformKind;
        let v = mk_decode(
            TransformKind::Base64Decode,
            SymbolicValue::ConcreteStr("aGVsbG8=".into()),
        );
        assert_eq!(v, SymbolicValue::ConcreteStr("hello".into()));
    }

    #[test]
    fn mk_decode_url_concrete() {
        use super::super::strings::TransformKind;
        let v = mk_decode(
            TransformKind::UrlDecode,
            SymbolicValue::ConcreteStr("hello%20world".into()),
        );
        assert_eq!(v, SymbolicValue::ConcreteStr("hello world".into()));
    }

    #[test]
    fn encode_display_format() {
        use super::super::strings::TransformKind;
        let v = mk_encode(
            TransformKind::HtmlEscape,
            SymbolicValue::Symbol(SsaValue(0)),
        );
        assert_eq!(format!("{}", v), "htmlEscape(sym(v0))");

        let v = mk_decode(
            TransformKind::Base64Decode,
            SymbolicValue::Symbol(SsaValue(1)),
        );
        assert_eq!(format!("{}", v), "decode_base64Decode(sym(v1))");
    }

    #[test]
    fn encode_depth() {
        use super::super::strings::TransformKind;
        let inner = SymbolicValue::Symbol(SsaValue(0));
        let v = mk_encode(TransformKind::UrlEncode, inner);
        assert_eq!(v.depth(), 1);
    }

    /// `mk_binop(Add, ConcreteStr, Concrete(int))` must not silently
    /// coerce types. The fold path only triggers when *both* operands
    /// are `Concrete(i64)`; mixed-type operands must build a symbolic
    /// `BinOp` so downstream witness rendering / type analysis can
    /// reject the bogus arithmetic.
    #[test]
    fn binop_mixed_str_int_does_not_coerce() {
        let v = mk_binop(
            Op::Add,
            SymbolicValue::ConcreteStr("price=".into()),
            SymbolicValue::Concrete(42),
        );
        assert!(
            matches!(v, SymbolicValue::BinOp(Op::Add, _, _)),
            "mixed-type Add must produce a symbolic BinOp, not silently fold"
        );
    }

    /// `mk_phi` must not fold when operands have differing types
    /// (e.g. one branch returns a Concrete int, another returns
    /// ConcreteStr). The result is genuinely uncertain, a Phi node
    /// must be preserved to expose the type-conflict to downstream
    /// witness logic, not collapse to one operand.
    #[test]
    fn phi_mixed_types_keeps_phi() {
        let v = mk_phi(vec![
            (BlockId(0), SymbolicValue::Concrete(7)),
            (BlockId(1), SymbolicValue::ConcreteStr("x".into())),
        ]);
        assert!(
            matches!(v, SymbolicValue::Phi(_)),
            "phi over mixed types must NOT fold to a single operand"
        );
    }
}

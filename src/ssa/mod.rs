//! SSA IR, lowering, and optimization passes.
//!
//! The pipeline converts a CFG into a pruned SSA body consumed by the taint
//! analysis engine. [`lower_to_ssa`] inserts phi nodes via Cytron's algorithm
//! and renames variables along the dominator tree. [`optimize_ssa`] runs
//! constant propagation, branch pruning, copy propagation, DCE, and type
//! fact analysis in sequence.
//!
//! Key submodules:
//! - [`ir`]: core types (`SsaValue`, `SsaOp`, `SsaInst`, `SsaBlock`, `SsaBody`)
//! - [`lower`]: CFG-to-SSA lowering with Cytron phi insertion and dominator-tree rename
//! - [`const_prop`]: sparse conditional constant propagation with branch pruning
//! - [`copy_prop`]: copy and alias propagation
//! - [`dce`]: dead definition elimination
//! - [`type_facts`]: per-value type inference (`TypeKind`, `TypeFactResult`)
//! - [`heap`]: abstract heap for container element abstractions
//! - [`alias`]: base-variable alias groups from copy propagation

#[allow(dead_code)] // IR types, fields used by Display impl, tests, and downstream analyses
pub mod alias;
pub mod const_prop;
pub mod copy_prop;
pub mod dce;
pub mod display;
pub mod heap;
pub mod invariants;
#[allow(dead_code)]
pub mod ir;
pub mod lower;
pub mod param_points_to;
pub mod pointsto;
pub mod static_map;
pub mod type_facts;
pub mod xml_config;
pub mod xpath_config;

#[allow(unused_imports)]
pub use ir::*;
pub use lower::lower_to_ssa;
pub use lower::lower_to_ssa_scoped_nop;
pub use lower::lower_to_ssa_with_params;

use crate::cfg::Cfg;
use crate::ssa::type_facts::TypeKind;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of SSA optimization passes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimizeResult {
    /// Per-SSA-value constant lattice values.
    pub const_values: HashMap<SsaValue, const_prop::ConstLattice>,
    /// Type fact analysis results.
    pub type_facts: type_facts::TypeFactResult,
    /// XML-parser configuration facts (Phase 07): per-receiver SSA value
    /// `secure_processing` / `disallow_doctype` / `external_entities`
    /// flags carried forward from setter calls and constructor kwargs.
    /// Consumed by the SSA taint engine to suppress XXE on parse-class
    /// sinks whose receiver was provably hardened.
    #[serde(default)]
    pub xml_parser_config: xml_config::XmlParserConfigResult,
    /// XPath-receiver configuration facts: per-receiver SSA value
    /// `has_resolver` flag set by `setXPathVariableResolver` calls.
    /// Consumed by the SSA taint engine to suppress XPATH_INJECTION on
    /// `evaluate` / `compile` sinks whose receiver was provably bound
    /// to a variable resolver (parameterised XPath shape).
    #[serde(default)]
    pub xpath_config: xpath_config::XPathConfigResult,
    /// Base-variable alias groups from copy propagation.
    pub alias_result: alias::BaseAliasResult,
    /// Points-to analysis: per-SSA-value abstract heap object sets.
    pub points_to: heap::PointsToResult,
    /// Module aliases from `require()` calls: SSA value → possible module names.
    /// Used to resolve dynamic dispatch like `lib.request()` where `lib = require("http")`.
    pub module_aliases: HashMap<SsaValue, smallvec::SmallVec<[String; 2]>>,
    /// Number of branches pruned by constant propagation.
    pub branches_pruned: usize,
    /// Number of copies eliminated.
    pub copies_eliminated: usize,
    /// Number of dead definitions removed.
    pub dead_defs_removed: usize,
}

/// Run all SSA optimization passes on a body.
///
/// Pipeline: const propagation → branch pruning → copy propagation → DCE → type facts.
pub fn optimize_ssa(body: &mut SsaBody, cfg: &Cfg, lang: Option<Lang>) -> OptimizeResult {
    optimize_ssa_with_param_types(body, cfg, lang, &[])
}

/// Same as [`optimize_ssa`] but seeds [`SsaOp::Param`] values with
/// per-position [`TypeKind`] facts derived from the function's
/// `BodyMeta.param_types`.  Strictly additive: an empty slice or
/// `None` entries leave the type-fact analysis behaviour unchanged.
pub fn optimize_ssa_with_param_types(
    body: &mut SsaBody,
    cfg: &Cfg,
    lang: Option<Lang>,
    param_types: &[Option<TypeKind>],
) -> OptimizeResult {
    // 1. Constant propagation (SCCP)
    let cp = const_prop::const_propagate(body);
    let branches_pruned = const_prop::apply_const_prop(body, &cp);

    // 2. Copy propagation
    let (copies_eliminated, copy_map) = copy_prop::copy_propagate(body, cfg);

    // 3. Alias analysis (uses copy_map before DCE removes dead defs)
    let alias_result = alias::compute_base_aliases(&copy_map, body);

    // 4. Dead code elimination
    let dead_defs_removed = dce::eliminate_dead_defs(body, cfg);

    // 5. Type fact analysis (uses const prop results + language for constructor inference)
    let type_facts =
        type_facts::analyze_types_with_param_types(body, cfg, &cp.values, lang, param_types);

    // 5b. XML-parser config analysis (Phase 07).  Tracks per-receiver
    // hardening flags so XXE sinks can be suppressed when the parser was
    // provably configured for secure processing.
    let xml_parser_config = xml_config::analyze_xml_parser_config(body, cfg, &cp.values, lang);

    // 5c. XPath-receiver config analysis.  Tracks per-receiver
    // `has_resolver` flag so `XPath.evaluate(taintedExpr, ...)` sinks
    // can be suppressed when the receiver was bound to an
    // `XPathVariableResolver` (parameterised-XPath shape).
    let xpath_config = xpath_config::analyze_xpath_config(body, cfg, lang);

    // 6. Points-to analysis (uses allocation site detection + SSA def-use)
    let points_to = heap::analyze_points_to(body, cfg, lang);

    // 7. Module alias analysis (require() tracking for JS/TS)
    let module_aliases = if matches!(lang, Some(Lang::JavaScript) | Some(Lang::TypeScript)) {
        const_prop::collect_module_aliases(body, &cp.values)
    } else {
        HashMap::new()
    };

    OptimizeResult {
        const_values: cp.values,
        type_facts,
        xml_parser_config,
        xpath_config,
        alias_result,
        points_to,
        module_aliases,
        branches_pruned,
        copies_eliminated,
        dead_defs_removed,
    }
}

//! Per-SSA-value XML-parser configuration tracking.
//!
//! Phase 07: tracks "is this XML parser configured to disable external
//! entities / DTD resolution" facts on parser-receiver SSA values.  When a
//! parse-class sink is reached and the receiver is provably configured for
//! secure processing, the XXE bit is stripped from the sink's cap mask.
//!
//! The pass is intentionally a small forward dataflow run alongside
//! type-fact analysis — it does NOT flow through the SSA taint engine's
//! worklist.  Phi nodes propagate the meet of operand configs (a flag is
//! "set" only when all reaching operands set it), and copy assignments
//! propagate the receiver's config.  Recognised setter calls update the
//! receiver's config in place; identity-style transformer calls that
//! produce a child parser (e.g. `factory.newDocumentBuilder()`) inherit
//! the receiver's config into the result value.

use std::collections::HashMap;

use super::const_prop::ConstLattice;
use super::ir::*;
use crate::cfg::Cfg;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};

/// Receiver-instance config carried forward from setter calls.
///
/// All flags default to `false` (parser may be unsafe).  A `true` flag
/// means: we have proven this parser was hardened along this control-flow
/// path.  The XXE-suppression check is `secure_processing ||
/// disallow_doctype` — either gate is sufficient to neutralise external
/// entity resolution in JAXP / lxml / xml2js.
///
/// `external_entities` is the *unsafe* polarity: when set to `true`, the
/// parser was explicitly opted into external-entity resolution (e.g.
/// `XMLParser(resolve_entities=True)`).  A parse call with this flag
/// retains XXE even if the language default would otherwise be safe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlParserConfig {
    pub secure_processing: bool,
    pub disallow_doctype: bool,
    pub external_entities: bool,
}

impl XmlParserConfig {
    /// True when the parser is provably hardened against XXE.
    pub fn is_secure(&self) -> bool {
        (self.secure_processing || self.disallow_doctype) && !self.external_entities
    }

    /// Phi-meet: a flag survives only when *both* operands set it.  Used
    /// when the parser variable was reassigned across branches.
    fn meet(&self, other: &Self) -> Self {
        XmlParserConfig {
            secure_processing: self.secure_processing && other.secure_processing,
            disallow_doctype: self.disallow_doctype && other.disallow_doctype,
            // Unsafe polarity: ANY branch enabling external entities
            // contaminates the join.  Conservative w.r.t. XXE.
            external_entities: self.external_entities || other.external_entities,
        }
    }

    /// Union: caller updates the same receiver across multiple setter
    /// calls.  All known-safe flags accumulate; unsafe is sticky.
    fn union(&self, other: &Self) -> Self {
        XmlParserConfig {
            secure_processing: self.secure_processing || other.secure_processing,
            disallow_doctype: self.disallow_doctype || other.disallow_doctype,
            external_entities: self.external_entities || other.external_entities,
        }
    }
}

/// Result of XML-parser config analysis.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XmlParserConfigResult {
    pub configs: HashMap<SsaValue, XmlParserConfig>,
}

impl XmlParserConfigResult {
    /// True when the value carries a config fact proving secure processing.
    pub fn is_secure(&self, v: SsaValue) -> bool {
        self.configs.get(&v).is_some_and(|c| c.is_secure())
    }

    /// True when the value was explicitly opted into external-entity
    /// resolution (e.g. lxml `resolve_entities=True`).
    pub fn is_unsafe_explicit(&self, v: SsaValue) -> bool {
        self.configs.get(&v).is_some_and(|c| c.external_entities)
    }
}

/// Suppress the `Cap::XXE` bit when the receiver of an XXE-class sink
/// was provably hardened.  Returns `true` when XXE should be stripped
/// from the sink's cap mask.
///
/// Conservative defaults:
/// * No receiver SSA value (free function) → returns `false` (cannot
///   prove safety, fall through to existing classification).
/// * Receiver carries no config fact → returns `false`.
/// * `external_entities` flag is set → returns `false` even if a safe
///   flag is also set, since the unsafe opt-in dominates.
pub fn xxe_safe(receiver: Option<SsaValue>, xml_config: &XmlParserConfigResult) -> bool {
    let Some(rv) = receiver else {
        return false;
    };
    xml_config.is_secure(rv)
}

/// Per-call analysis result: how this call mutates the parser-config
/// universe.
#[allow(dead_code)] // SeedResult reserved for future constructor-driven seeding
enum ConfigEffect {
    /// No effect on parser configuration.
    None,
    /// Update the call's receiver in place by OR-ing the supplied config
    /// into its current config.  Used for setter calls
    /// (`factory.setFeature(FEATURE_SECURE_PROCESSING, true)`).
    UpdateReceiver(XmlParserConfig),
    /// Inherit the receiver's config into the call's result value.
    /// Used for identity-style transformer calls
    /// (`factory.newDocumentBuilder()` returns a builder that shares
    /// the factory's hardening state).
    InheritFromReceiver,
    /// Initialise the call's result value with the supplied config.
    /// Used for constructor calls whose options reveal the unsafe-explicit
    /// opt-in (`new XMLParser({ processEntities: true })`,
    /// `lxml.etree.XMLParser(resolve_entities=True)`).
    SeedResult(XmlParserConfig),
}

/// Classify a Call instruction's effect on the parser-config universe.
///
/// `arg_const` looks up the const-lattice value for an SSA arg position
/// (returns `None` if the position is out of range or the SSA value is
/// not a known constant).  Setter detection consults arg-0 (the feature
/// name) and arg-1 (the boolean flag).
///
/// `arg_idents` is the matching CFG-level [`info.call.arg_uses`] vector
/// (per-position identifier text from the source AST).  Used to recover
/// non-literal feature names like `XMLConstants.FEATURE_SECURE_PROCESSING`
/// or bare identifiers (`FEATURE_SECURE_PROCESSING`, `Boolean.TRUE`)
/// that const-propagation cannot fold to a literal.
///
/// `arg_literals` is the matching CFG-level
/// [`info.call.arg_string_literals`] vector (per-position literal text;
/// strings, booleans, and null/nil/None tokens).  Used to recover the
/// boolean polarity of `setFeature(NAME, true)` since SSA lowering does
/// not bind boolean arg literals to any SSA value (`arg_uses` skips them
/// because they are not identifiers).
fn classify_call(
    lang: Lang,
    callee: &str,
    args: &[smallvec::SmallVec<[SsaValue; 2]>],
    receiver: Option<SsaValue>,
    consts: &HashMap<SsaValue, ConstLattice>,
    arg_idents: &[Vec<String>],
    arg_literals: &[Option<String>],
) -> ConfigEffect {
    let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);

    // Helper: lookup the const lattice for arg N's first SSA value.
    let arg_const = |n: usize| -> Option<&ConstLattice> {
        args.get(n)
            .and_then(|vals| vals.first())
            .and_then(|v| consts.get(v))
    };
    // Helper: text of the const lattice (for string/identifier comparison).
    let arg_text = |n: usize| -> Option<String> {
        match arg_const(n)? {
            ConstLattice::Str(s) => Some(s.clone()),
            ConstLattice::Bool(b) => Some(b.to_string()),
            ConstLattice::Int(i) => Some(i.to_string()),
            _ => None,
        }
    };
    // Helper: textual identifier(s) at arg N from the CFG node.  Non-literal
    // feature names (`XMLConstants.FEATURE_SECURE_PROCESSING`, bare
    // `FEATURE_SECURE_PROCESSING`, etc.) surface here.
    let arg_ident_text = |n: usize| -> Vec<&str> {
        arg_idents
            .get(n)
            .map(|v| v.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    };
    let arg_bool = |n: usize| -> Option<bool> {
        if let Some(b) = arg_const(n).and_then(|c| match c {
            ConstLattice::Bool(b) => Some(*b),
            ConstLattice::Str(s) => match s.as_str() {
                "True" | "true" => Some(true),
                "False" | "false" => Some(false),
                _ => None,
            },
            _ => None,
        }) {
            return Some(b);
        }
        // Fallback: tree-sitter classifies `true` / `false` as bare
        // identifiers in some grammars.  Inspect the arg's use list.
        for tok in arg_ident_text(n) {
            match tok {
                "true" | "True" | "Boolean.TRUE" => return Some(true),
                "false" | "False" | "Boolean.FALSE" => return Some(false),
                _ => {}
            }
        }
        // Fallback: literal tokens lifted by `extract_arg_string_literals`
        // (booleans / null / numeric tokens).  Java `setFeature(NAME, true)`
        // does not bind the `true` token to any SSA value, but the literal
        // surfaces here so the polarity can still be read.
        if let Some(Some(lit)) = arg_literals.get(n) {
            match lit.as_str() {
                "true" | "True" | "Boolean.TRUE" => return Some(true),
                "false" | "False" | "Boolean.FALSE" => return Some(false),
                _ => {}
            }
        }
        None
    };

    match lang {
        Lang::Java => match suffix {
            // `factory.setFeature(NAME, BOOL)` — the canonical JAXP
            // hardening switch.  Three feature names matter:
            //   * `FEATURE_SECURE_PROCESSING` (XMLConstants.FEATURE_SECURE_PROCESSING)
            //   * `http://apache.org/xml/features/disallow-doctype-decl`
            //   * `http://xml.org/sax/features/external-general-entities`
            //   * `http://xml.org/sax/features/external-parameter-entities`
            // The first two harden by being SET TRUE; the entity ones
            // harden by being SET FALSE.
            "setFeature" => {
                if receiver.is_none() {
                    return ConfigEffect::None;
                }
                let name_lit = arg_text(0).unwrap_or_default();
                let name_idents = arg_ident_text(0);
                let value = arg_bool(1);
                let any_ident = |needle: &str| name_idents.iter().any(|s| s.contains(needle));
                let mut cfg = XmlParserConfig::default();
                if name_lit == "FEATURE_SECURE_PROCESSING"
                    || name_lit.contains("XMLConstants.FEATURE_SECURE_PROCESSING")
                    || name_lit.contains("javax.xml.XMLConstants/feature/secure-processing")
                    || any_ident("FEATURE_SECURE_PROCESSING")
                {
                    if value == Some(true) {
                        cfg.secure_processing = true;
                    }
                } else if name_lit.contains("disallow-doctype-decl")
                    || any_ident("disallow-doctype-decl")
                {
                    if value == Some(true) {
                        cfg.disallow_doctype = true;
                    }
                } else if (name_lit.contains("external-general-entities")
                    || name_lit.contains("external-parameter-entities")
                    || name_lit.contains("load-external-dtd")
                    || any_ident("external-general-entities")
                    || any_ident("external-parameter-entities")
                    || any_ident("load-external-dtd"))
                    && value == Some(false)
                {
                    cfg.disallow_doctype = true;
                }
                if cfg == XmlParserConfig::default() {
                    ConfigEffect::None
                } else {
                    ConfigEffect::UpdateReceiver(cfg)
                }
            }
            // `factory.setExpandEntityReferences(false)` —
            // DocumentBuilderFactory legacy hardening switch.
            "setExpandEntityReferences" => {
                if receiver.is_none() {
                    return ConfigEffect::None;
                }
                if arg_bool(0) == Some(false) {
                    ConfigEffect::UpdateReceiver(XmlParserConfig {
                        disallow_doctype: true,
                        ..Default::default()
                    })
                } else {
                    ConfigEffect::None
                }
            }
            // `factory.newDocumentBuilder()` / `factory.newSAXParser()` /
            // `parser.getXMLReader()` propagate the hardening state from
            // the factory (receiver) onto the produced parser instance
            // (return value).  Without this propagation, a hardened
            // factory's child builder would parse with no config.
            "newDocumentBuilder" | "newSAXParser" | "getXMLReader" | "newXMLReader" => {
                if receiver.is_some() {
                    ConfigEffect::InheritFromReceiver
                } else {
                    ConfigEffect::None
                }
            }
            _ => ConfigEffect::None,
        },
        Lang::Python => {
            // `lxml.etree.XMLParser(resolve_entities=False)` — the lxml
            // parser default resolves entities; the keyword argument
            // changes that.  Const-propagation will not generally see the
            // kwarg value here (kwargs land in `info.call.kwargs`, not
            // positional args), so we treat the constructor as a
            // best-effort initialiser keyed off the keyword's literal
            // text via the static-map.  When neither keyword surfaces,
            // the parser keeps the default-empty config.
            if callee.ends_with("etree.XMLParser") || suffix == "XMLParser" {
                // Positional kwargs aren't reliable here; rely on the
                // call's static-map kwargs (handled by the per-callsite
                // pass below).  Fall through to None at this layer.
                ConfigEffect::None
            } else {
                ConfigEffect::None
            }
        }
        _ => ConfigEffect::None,
    }
}

/// Run the XML-parser config analysis on an SSA body.
pub fn analyze_xml_parser_config(
    body: &SsaBody,
    cfg: &Cfg,
    consts: &HashMap<SsaValue, ConstLattice>,
    lang: Option<Lang>,
) -> XmlParserConfigResult {
    let Some(lang) = lang else {
        return XmlParserConfigResult::default();
    };

    let mut configs: HashMap<SsaValue, XmlParserConfig> = HashMap::new();

    // Helper: read the kwargs attached to the original CFG node for the
    // call instruction at hand.  Used for languages where parser
    // hardening flags arrive as keyword arguments (Python lxml).
    let lookup_kwargs = |node_idx: petgraph::graph::NodeIndex| -> Vec<(String, Vec<String>)> {
        cfg.node_weight(node_idx)
            .map(|ni| ni.call.kwargs.clone())
            .unwrap_or_default()
    };
    // Helper: read the positional arg-use identifier vectors (e.g.
    // `XMLConstants.FEATURE_SECURE_PROCESSING` surfaces as a dotted path
    // here even when const-prop folds it to nothing).
    let lookup_arg_idents = |node_idx: petgraph::graph::NodeIndex| -> Vec<Vec<String>> {
        cfg.node_weight(node_idx)
            .map(|ni| ni.call.arg_uses.clone())
            .unwrap_or_default()
    };
    // Helper: read the per-position literal-token vector
    // (`arg_string_literals` lifts strings, booleans, null tokens, and
    // numeric tokens — see `extract_arg_string_literals`).
    let lookup_arg_literals = |node_idx: petgraph::graph::NodeIndex| -> Vec<Option<String>> {
        cfg.node_weight(node_idx)
            .map(|ni| ni.call.arg_string_literals.clone())
            .unwrap_or_default()
    };

    // Pass 1 — direct effects from Call instructions in source order.
    // Setter updates and constructor seeds are effectively monotone
    // (we OR safe flags onto the receiver / value), so a single pass is
    // sufficient when phi nodes only appear after the setter.  Pass 2
    // below handles phi/copy propagation.
    for block in &body.blocks {
        for inst in block.body.iter() {
            if let SsaOp::Call {
                callee,
                args,
                receiver,
                ..
            } = &inst.op
            {
                // Python lxml.etree.XMLParser(resolve_entities=...): the
                // kwarg lives on the CFG node's `kwargs` list, not in
                // the SSA Call args.  Inspect it directly.
                if matches!(lang, Lang::Python)
                    && (callee.ends_with("etree.XMLParser")
                        || callee.rsplit(['.', ':']).next() == Some("XMLParser"))
                {
                    let kwargs = lookup_kwargs(inst.cfg_node);
                    for (name, values) in &kwargs {
                        if name == "resolve_entities" {
                            // Look up the literal text on the matching
                            // argument; tree-sitter-python keywords surface
                            // the value identifier in the `values` slot.
                            if values.iter().any(|v| v == "True" || v == "true") {
                                let entry = configs.entry(inst.value).or_default();
                                entry.external_entities = true;
                            } else if values.iter().any(|v| v == "False" || v == "false") {
                                let entry = configs.entry(inst.value).or_default();
                                entry.disallow_doctype = true;
                            }
                        }
                        if name == "no_network" && values.iter().any(|v| v == "True" || v == "true")
                        {
                            let entry = configs.entry(inst.value).or_default();
                            entry.disallow_doctype = true;
                        }
                    }
                    continue;
                }

                // JS/TS: `new XMLParser({ processEntities: true, ... })`.
                // The fast-xml-parser constructor's option-object fields
                // are not exposed via const-prop, but the CFG layer
                // captures string-literal kwargs in the call's
                // `arg_string_literals` for object-literal positions.
                // For now, mark the result as unsafe-explicit only when
                // the static-kwargs list carries `processEntities=true`.
                if matches!(lang, Lang::JavaScript | Lang::TypeScript)
                    && (callee.ends_with("XMLParser") || callee.ends_with(".XMLParser"))
                {
                    let kwargs = lookup_kwargs(inst.cfg_node);
                    for (name, values) in &kwargs {
                        if name == "processEntities" && values.iter().any(|v| v == "true") {
                            let entry = configs.entry(inst.value).or_default();
                            entry.external_entities = true;
                        }
                    }
                    continue;
                }

                let arg_idents = lookup_arg_idents(inst.cfg_node);
                let arg_literals = lookup_arg_literals(inst.cfg_node);
                match classify_call(
                    lang,
                    callee,
                    args,
                    *receiver,
                    consts,
                    &arg_idents,
                    &arg_literals,
                ) {
                    ConfigEffect::None => {}
                    ConfigEffect::UpdateReceiver(delta) => {
                        if let Some(rv) = *receiver {
                            let entry = configs.entry(rv).or_default();
                            *entry = entry.union(&delta);
                        }
                    }
                    ConfigEffect::InheritFromReceiver => {
                        if let Some(rv) = *receiver
                            && let Some(parent) = configs.get(&rv).copied()
                        {
                            let entry = configs.entry(inst.value).or_default();
                            *entry = entry.union(&parent);
                        }
                    }
                    ConfigEffect::SeedResult(seed) => {
                        let entry = configs.entry(inst.value).or_default();
                        *entry = entry.union(&seed);
                    }
                }
            }
        }
    }

    // Pass 2 — fixed-point propagation through copy assignments and phi
    // joins.  Caps the iteration count: in practice 2-3 rounds suffice
    // on intra-procedural shapes.
    for _ in 0..6 {
        let mut changed = false;
        for block in &body.blocks {
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut acc: Option<XmlParserConfig> = None;
                    for (_, val) in operands {
                        let cfg_val = configs.get(val).copied().unwrap_or_default();
                        acc = Some(match acc {
                            None => cfg_val,
                            Some(prev) => prev.meet(&cfg_val),
                        });
                    }
                    if let Some(joined) = acc
                        && joined != XmlParserConfig::default()
                    {
                        let prev = configs.get(&inst.value).copied();
                        if prev != Some(joined) {
                            configs.insert(inst.value, joined);
                            changed = true;
                        }
                    }
                }
            }
            for inst in &block.body {
                if let SsaOp::Assign(uses) = &inst.op
                    && uses.len() == 1
                    && let Some(src_cfg) = configs.get(&uses[0]).copied()
                    && src_cfg != XmlParserConfig::default()
                {
                    let prev = configs.get(&inst.value).copied().unwrap_or_default();
                    let new_cfg = prev.union(&src_cfg);
                    if Some(new_cfg) != configs.get(&inst.value).copied() {
                        configs.insert(inst.value, new_cfg);
                        changed = true;
                    }
                }
                // InheritFromReceiver may need a re-pass when the
                // receiver's config was set after the call itself was
                // visited (e.g. the call appears in a later block whose
                // dominator chain only resolves on the second iteration).
                if let SsaOp::Call {
                    callee,
                    receiver: Some(rv),
                    ..
                } = &inst.op
                {
                    let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);
                    let inherit = matches!(lang, Lang::Java)
                        && matches!(
                            suffix,
                            "newDocumentBuilder" | "newSAXParser" | "getXMLReader" | "newXMLReader"
                        );
                    if inherit
                        && let Some(parent) = configs.get(rv).copied()
                    {
                        let prev = configs.get(&inst.value).copied().unwrap_or_default();
                        let new_cfg = prev.union(&parent);
                        if Some(new_cfg) != configs.get(&inst.value).copied()
                            && new_cfg != XmlParserConfig::default()
                        {
                            configs.insert(inst.value, new_cfg);
                            changed = true;
                        }
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    XmlParserConfigResult { configs }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_unsafe() {
        let c = XmlParserConfig::default();
        assert!(!c.is_secure());
    }

    #[test]
    fn secure_processing_alone_is_safe() {
        let c = XmlParserConfig {
            secure_processing: true,
            ..Default::default()
        };
        assert!(c.is_secure());
    }

    #[test]
    fn external_entities_overrides_safe_flag() {
        let c = XmlParserConfig {
            secure_processing: true,
            external_entities: true,
            ..Default::default()
        };
        assert!(!c.is_secure());
    }

    #[test]
    fn meet_keeps_only_intersection_of_safe_flags() {
        let a = XmlParserConfig {
            secure_processing: true,
            disallow_doctype: true,
            ..Default::default()
        };
        let b = XmlParserConfig {
            secure_processing: true,
            ..Default::default()
        };
        let m = a.meet(&b);
        assert!(m.secure_processing);
        assert!(!m.disallow_doctype);
    }

    #[test]
    fn meet_propagates_unsafe_flag() {
        let a = XmlParserConfig {
            secure_processing: true,
            ..Default::default()
        };
        let b = XmlParserConfig {
            external_entities: true,
            ..Default::default()
        };
        let m = a.meet(&b);
        // Unsafe sticky → no longer secure even though one branch was.
        assert!(!m.is_secure());
    }

    #[test]
    fn xxe_safe_returns_false_without_receiver() {
        let result = XmlParserConfigResult::default();
        assert!(!xxe_safe(None, &result));
    }

    #[test]
    fn xxe_safe_uses_receiver_config() {
        let mut configs = HashMap::new();
        configs.insert(
            SsaValue(7),
            XmlParserConfig {
                secure_processing: true,
                ..Default::default()
            },
        );
        let result = XmlParserConfigResult { configs };
        assert!(xxe_safe(Some(SsaValue(7)), &result));
        assert!(!xxe_safe(Some(SsaValue(8)), &result));
    }
}

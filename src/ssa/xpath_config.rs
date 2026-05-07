//! Per-SSA-value XPath-receiver configuration tracking.
//!
//! Mirrors [`crate::ssa::xml_config`] but for `XPath` instances rather
//! than JAXP parser instances.  Tracks "is this XPath receiver bound to
//! an `XPathVariableResolver`" along the control-flow path: when a
//! resolver has been bound, subsequent `xpath.evaluate(expr, ...)` calls
//! are treated as parameterised and the `XPATH_INJECTION` bit is
//! stripped from the sink's cap mask.
//!
//! Same engine shape as Phase 07's `XmlParserConfigResult`: a small
//! forward dataflow run alongside type-fact analysis.  Phi nodes
//! propagate the meet of operand configs (a flag is "set" only when all
//! reaching operands set it), copy assignments propagate the receiver's
//! config, and `setXPathVariableResolver` calls update the receiver's
//! config in place.

use std::collections::HashMap;

use super::ir::*;
use crate::cfg::Cfg;
use crate::symbol::Lang;
use serde::{Deserialize, Serialize};

/// Receiver-instance config carried forward from `setXPathVariableResolver`
/// calls.  All flags default to `false` (resolver not bound).  A `true`
/// flag means: we have proven this XPath receiver was configured for
/// parameterised evaluation along this control-flow path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XPathReceiverConfig {
    /// True when `xpath.setXPathVariableResolver(...)` has been called
    /// on this receiver.  Set by Pass 1 on the receiver SSA value;
    /// propagated through phi joins (meet) and copy assignments (union).
    pub has_resolver: bool,
}

impl XPathReceiverConfig {
    /// True when the receiver is provably bound to a variable resolver.
    pub fn is_parameterised(&self) -> bool {
        self.has_resolver
    }

    /// Phi-meet: a flag survives only when *both* operands set it.  Used
    /// when the XPath variable was reassigned across branches and only
    /// some branches bound a resolver.
    fn meet(&self, other: &Self) -> Self {
        XPathReceiverConfig {
            has_resolver: self.has_resolver && other.has_resolver,
        }
    }

    /// Union: caller binds a resolver after a copy / phi-join.  Any
    /// branch setting the flag wins for the union (used for copy
    /// propagation, which preserves the source value's flags).
    fn union(&self, other: &Self) -> Self {
        XPathReceiverConfig {
            has_resolver: self.has_resolver || other.has_resolver,
        }
    }
}

/// Result of XPath-receiver config analysis.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XPathConfigResult {
    pub configs: HashMap<SsaValue, XPathReceiverConfig>,
}

impl XPathConfigResult {
    /// True when the value carries a config fact proving resolver
    /// binding.
    pub fn is_parameterised(&self, v: SsaValue) -> bool {
        self.configs.get(&v).is_some_and(|c| c.is_parameterised())
    }
}

/// Suppress the `Cap::XPATH_INJECTION` bit when the receiver of an XPath
/// `evaluate` / `compile` sink was provably bound to a variable
/// resolver.  Returns `true` when XPATH_INJECTION should be stripped
/// from the sink's cap mask.
///
/// Conservative defaults:
/// * No receiver SSA value (free function) → returns `false` (cannot
///   prove safety, fall through to existing classification).
/// * Receiver carries no config fact → returns `false`.
pub fn xpath_safe(receiver: Option<SsaValue>, xpath_config: &XPathConfigResult) -> bool {
    let Some(rv) = receiver else {
        return false;
    };
    xpath_config.is_parameterised(rv)
}

/// Run the XPath-receiver config analysis on an SSA body.
///
/// Currently models Java's `setXPathVariableResolver` only — the only
/// language-level resolver-binding API for XPath in the existing
/// detection corpus.  PHP's `DOMXPath::registerPhpFunctions()` is a
/// different mechanism (PHP function registration) and not modelled
/// here.
pub fn analyze_xpath_config(body: &SsaBody, cfg: &Cfg, lang: Option<Lang>) -> XPathConfigResult {
    let Some(lang) = lang else {
        return XPathConfigResult::default();
    };
    if !matches!(lang, Lang::Java) {
        return XPathConfigResult::default();
    }

    let mut configs: HashMap<SsaValue, XPathReceiverConfig> = HashMap::new();

    // Pass 1 — direct effects from Call instructions in source order.
    // `setXPathVariableResolver` updates the call's receiver in place;
    // any non-null argument is treated as a resolver binding.  Argument
    // null-check would require a const-prop fact, but the conservative
    // direction here is to assume the bound value is non-null (matches
    // Phase 07 setter semantics).
    for block in &body.blocks {
        for inst in block.body.iter() {
            if let SsaOp::Call {
                callee, receiver, ..
            } = &inst.op
            {
                let suffix = callee.rsplit(['.', ':']).next().unwrap_or(callee);
                if suffix == "setXPathVariableResolver"
                    && let Some(rv) = receiver
                {
                    let entry = configs.entry(*rv).or_default();
                    entry.has_resolver = true;
                }
            }
        }
    }

    if configs.is_empty() {
        return XPathConfigResult::default();
    }

    // Pass 2 — fixed-point propagation through copy assignments and
    // phi joins.  Caps the iteration count: in practice 2-3 rounds
    // suffice on intra-procedural shapes.
    let _ = cfg; // CFG retained for parity with `xml_config`; reserved for
    // future kwarg-driven seeds (e.g. constructor options).
    for _ in 0..6 {
        let mut changed = false;
        for block in &body.blocks {
            for inst in &block.phis {
                if let SsaOp::Phi(operands) = &inst.op {
                    let mut acc: Option<XPathReceiverConfig> = None;
                    for (_, val) in operands {
                        let cfg_val = configs.get(val).copied().unwrap_or_default();
                        acc = Some(match acc {
                            None => cfg_val,
                            Some(prev) => prev.meet(&cfg_val),
                        });
                    }
                    if let Some(joined) = acc
                        && joined != XPathReceiverConfig::default()
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
                    && src_cfg != XPathReceiverConfig::default()
                {
                    let prev = configs.get(&inst.value).copied().unwrap_or_default();
                    let new_cfg = prev.union(&src_cfg);
                    if Some(new_cfg) != configs.get(&inst.value).copied() {
                        configs.insert(inst.value, new_cfg);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    XPathConfigResult { configs }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_unparameterised() {
        let c = XPathReceiverConfig::default();
        assert!(!c.is_parameterised());
    }

    #[test]
    fn has_resolver_marks_parameterised() {
        let c = XPathReceiverConfig { has_resolver: true };
        assert!(c.is_parameterised());
    }

    #[test]
    fn meet_keeps_intersection() {
        let a = XPathReceiverConfig { has_resolver: true };
        let b = XPathReceiverConfig {
            has_resolver: false,
        };
        let m = a.meet(&b);
        assert!(!m.has_resolver);
    }

    #[test]
    fn meet_both_set_keeps_set() {
        let a = XPathReceiverConfig { has_resolver: true };
        let b = XPathReceiverConfig { has_resolver: true };
        let m = a.meet(&b);
        assert!(m.has_resolver);
    }

    #[test]
    fn xpath_safe_returns_false_without_receiver() {
        let result = XPathConfigResult::default();
        assert!(!xpath_safe(None, &result));
    }

    #[test]
    fn xpath_safe_uses_receiver_config() {
        let mut configs = HashMap::new();
        configs.insert(SsaValue(7), XPathReceiverConfig { has_resolver: true });
        let result = XPathConfigResult { configs };
        assert!(xpath_safe(Some(SsaValue(7)), &result));
        assert!(!xpath_safe(Some(SsaValue(8)), &result));
    }
}

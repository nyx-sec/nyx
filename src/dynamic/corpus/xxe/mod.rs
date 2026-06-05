//! XML External Entity expansion (`Cap::XXE`) per-language payload slices.
//!
//! Phase 05 (Track J.3) carves XXE across the five most-common XML
//! parser stacks: Java (`DocumentBuilderFactory`), Python
//! (`lxml.etree.XMLParser`), PHP (`simplexml_load_string` under
//! `libxml_disable_entity_loader(false)`), Ruby (REXML / Nokogiri), and
//! Go (`encoding/xml.Decoder`).  Every vuln payload ships an XML
//! document declaring an external entity (`<!ENTITY xxe SYSTEM "…">`)
//! that the engine expands inside an element body.  The paired benign
//! control omits the doctype + entity so the parser has nothing to
//! resolve; the oracle's
//! [`crate::dynamic::oracle::ProbePredicate::XxeEntityExpanded`] check
//! satisfies on the vuln run (`entity_expanded: true`) and stays clear
//! on the benign run, fulfilling the §4.1 differential rule.
//!
//! C# is intentionally omitted: the [`crate::symbol::Lang`] enum has
//! no `CSharp` variant, so the corpus has nowhere to register it.
//! Tracked in `.pitboss/play/deferred.md`.

pub mod go;
pub mod java;
pub mod php;
pub mod python;
pub mod ruby;

//! Cross-file callee bodies as [`super::GlobalSummaries`] stores them.
//!
//! A body loaded from the index stays MessagePack-encoded until something
//! reads it.  Its fingerprints, parameter count and block count are stored
//! beside the encoding, so the pass-2 reuse check, key reconciliation and
//! leaf lookup never decode it, and a rescan that reuses every unit decodes
//! and frees no body at all.

use std::sync::OnceLock;

use serde::{Serialize, Serializer};

use super::deps::{self, Fp};
use crate::taint::ssa_transfer::CalleeSsaBody;

/// A callee body in its persisted form: the MessagePack encoding plus the
/// facts readers need without decoding it.
#[derive(Clone, Debug)]
pub struct EncodedBody {
    pub bytes: Vec<u8>,
    pub param_count: usize,
    pub block_count: usize,
    /// [`deps::fp_value`] of the body.
    pub fp: Fp,
    /// [`deps::fp_value_rebased`] of the body over [`deps::POSITION_FIELDS`].
    pub shape_fp: Fp,
}

impl EncodedBody {
    /// Encode `body` and compute the facts stored beside it.
    pub fn encode(body: &CalleeSsaBody) -> Result<Self, rmp_serde::encode::Error> {
        Ok(Self {
            bytes: rmp_serde::to_vec_named(body)?,
            param_count: body.param_count,
            block_count: body.ssa.blocks.len(),
            fp: deps::fp_value(body),
            shape_fp: deps::fp_value_rebased(body, deps::POSITION_FIELDS),
        })
    }

    /// Decode the body and rebuild its proxy CFG.
    pub fn decode(&self) -> Result<CalleeSsaBody, rmp_serde::decode::Error> {
        decode_body(&self.bytes)
    }
}

fn decode_body(bytes: &[u8]) -> Result<CalleeSsaBody, rmp_serde::decode::Error> {
    let mut body: CalleeSsaBody = rmp_serde::from_slice(bytes)?;
    // Rehydrate a proxy Cfg from node_meta so the cross-file inline path
    // can index `cfg[inst.cfg_node]` uniformly.
    crate::taint::ssa_transfer::rebuild_body_graph(&mut body);
    Ok(body)
}

/// A body held in memory, or still encoded and decoded on first read.
#[derive(Clone)]
pub(super) struct BodyCell {
    param_count: usize,
    block_count: usize,
    /// The decoded body; `None` inside when the encoding does not decode.
    body: OnceLock<Option<CalleeSsaBody>>,
    encoded: Option<Box<[u8]>>,
}

impl BodyCell {
    pub(super) fn decoded(body: CalleeSsaBody) -> Self {
        let cell = Self {
            param_count: body.param_count,
            block_count: body.ssa.blocks.len(),
            body: OnceLock::new(),
            encoded: None,
        };
        let _ = cell.body.set(Some(body));
        cell
    }

    pub(super) fn encoded(body: EncodedBody) -> Self {
        Self {
            param_count: body.param_count,
            block_count: body.block_count,
            body: OnceLock::new(),
            encoded: Some(body.bytes.into_boxed_slice()),
        }
    }

    pub(super) fn param_count(&self) -> usize {
        self.param_count
    }

    pub(super) fn block_count(&self) -> usize {
        self.block_count
    }

    #[cfg(test)]
    pub(super) fn is_decoded(&self) -> bool {
        self.body.get().is_some()
    }

    /// The body, decoding it on first use.  `None` when the stored
    /// encoding does not decode (a damaged index row).
    pub(super) fn get(&self) -> Option<&CalleeSsaBody> {
        self.body
            .get_or_init(|| {
                let bytes = self.encoded.as_deref()?;
                decode_body(bytes)
                    .map_err(|e| tracing::warn!("failed to deserialize SSA body: {e}"))
                    .ok()
            })
            .as_ref()
    }
}

impl std::fmt::Debug for BodyCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyCell")
            .field("param_count", &self.param_count)
            .field("block_count", &self.block_count)
            .field("decoded", &self.body.get().is_some())
            .finish()
    }
}

/// Serializes exactly as the body itself, so the fingerprint of an
/// in-memory cell equals [`EncodedBody::fp`] for the same body.
impl Serialize for BodyCell {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.get() {
            Some(body) => body.serialize(s),
            None => s.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(param_count: usize) -> CalleeSsaBody {
        crate::summary::tests::make_callee_body(3, param_count)
    }

    #[test]
    fn encoded_facts_match_the_body() {
        let b = body(2);
        let enc = EncodedBody::encode(&b).unwrap();
        assert_eq!(enc.param_count, 2);
        assert_eq!(enc.block_count, b.ssa.blocks.len());
        assert_eq!(enc.fp, deps::fp_value(&b));
        assert_eq!(
            enc.shape_fp,
            deps::fp_value_rebased(&b, deps::POSITION_FIELDS)
        );
    }

    #[test]
    fn decoded_body_has_the_stored_fingerprints() {
        let enc = EncodedBody::encode(&body(3)).unwrap();
        let back = enc.decode().unwrap();
        assert_eq!(deps::fp_value(&back), enc.fp);
        assert_eq!(
            deps::fp_value_rebased(&back, deps::POSITION_FIELDS),
            enc.shape_fp
        );
    }

    #[test]
    fn cell_serializes_as_its_body() {
        let b = body(1);
        let fp = deps::fp_value(&b);
        assert_eq!(deps::fp_value(&BodyCell::decoded(b.clone())), fp);
        let lazy = BodyCell::encoded(EncodedBody::encode(&b).unwrap());
        assert!(lazy.body.get().is_none(), "encoded cell starts undecoded");
        assert_eq!(deps::fp_value(&lazy), fp);
        assert_eq!(lazy.get().map(|b| b.param_count), Some(1));
    }

    #[test]
    fn damaged_encoding_reads_as_absent() {
        let mut enc = EncodedBody::encode(&body(1)).unwrap();
        enc.bytes.truncate(3);
        let cell = BodyCell::encoded(enc);
        assert_eq!(cell.param_count(), 1);
        assert!(cell.get().is_none());
    }
}

//! Flat hash vector commitment: the commitment is ONE hash over the node's immediate children
//! essentially a merkle style Digest, if we have C = {c1, c2, ..., cn} be the children of node v
//! Then v.digest = H(c1.digest, c2.digest, ..., cn.digest)

use crate::field::NodeDigest;
use crate::hashes::{Blake3Hash, Hash, PoseidonHash, RescueFlatHash, Sha256Hash};
use crate::vc::VectorCommitment;

use std::fmt::Debug;
use std::marker::PhantomData;

pub struct FlatHashVc<H: Hash> {
    max_width: usize,
    _hash: PhantomData<H>,
}

pub struct FlatHashOpener<H: Hash> {
    nodes: Vec<H::Digest>,
}

/// Every slot EXCEPT the opened one, in slot order.
pub struct FlatHashWitness<H: Hash> {
    siblings: Vec<H::Digest>,
}

impl<H: Hash> FlatHashWitness<H> {
    /// The sibling slots in slot order (all slots except the opened one) —
    /// what `stark::flat` folds into merge cycles.
    pub fn siblings(&self) -> &[H::Digest] {
        &self.siblings
    }
}

// Manual impls: a derive would demand `H: Clone`/`H: Debug` on the marker
// hash types (same issue as MerklePath in merkle.rs).
impl<H: Hash> Clone for FlatHashWitness<H> {
    fn clone(&self) -> Self {
        FlatHashWitness { siblings: self.siblings.clone() }
    }
}

impl<H: Hash> Debug for FlatHashWitness<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlatHashWitness").field("siblings", &self.siblings).finish()
    }
}

pub type Sha2FlatHashVc = FlatHashVc<Sha256Hash>;
pub type Blake3FlatHashVc = FlatHashVc<Blake3Hash>;
pub type PoseidonFlatHashVc = FlatHashVc<PoseidonHash>;
/// Over Winterfell's f128, chain-fold Rescue merges; its proofs are what
/// `stark::flat` re-verifies inside a STARK.
pub type RescueFlatHashVc = FlatHashVc<RescueFlatHash>;
/// The M31 twin of `RescueFlatHashVc`: chain-fold Poseidon2 merges over
/// Mersenne-31, the field Stwo works in. Its proofs are what
/// `stark::stwo` re-verifies inside a Circle STARK.
#[cfg(feature = "stwo")]
pub type Poseidon2FlatHashVc = FlatHashVc<crate::hashes::Poseidon2FlatHash>;

impl<H: Hash> VectorCommitment for FlatHashVc<H>
where
    H::Digest: NodeDigest,
{
    type DigestType = H::Digest;
    type Commitment = H::Digest;
    type Witness = FlatHashWitness<H>;
    type Opener = FlatHashOpener<H>;

    fn setup(width: usize) -> Self {
        FlatHashVc {
            max_width: width,
            _hash: PhantomData,
        }
    }

    fn empty_commitment() -> Self::Commitment {
        H::empty()
    }

    fn commit(&self, values: &[H::Digest]) -> (Self::Commitment, Self::Opener) {
        assert!(values.len() <= self.max_width);
        let com = H::node(values);
        (com, FlatHashOpener { nodes: values.to_vec() })
    }

    fn open(&self, opener: &Self::Opener, i: usize) -> Self::Witness {
        let siblings = opener
            .nodes
            .iter()
            .enumerate()
            .filter(|&(idx, _)| idx != i)
            .map(|(_, d)| *d)
            .collect();
        FlatHashWitness { siblings }
    }

    fn check(&self, com: &Self::Commitment, i: usize, value: H::Digest, w: &Self::Witness) -> bool {
        // The witness carries every slot but the opened one, so the committed
        // width is siblings + 1; the opened slot must fit in it, and the whole
        // vector must fit the setup bound.
        if i > w.siblings.len() || w.siblings.len() >= self.max_width {
            return false;
        }
        let mut hash_input: Vec<H::Digest> = w.siblings[..i].to_vec();
        hash_input.push(value);
        hash_input.extend_from_slice(&w.siblings[i..]);

        H::node(&hash_input) == *com
    }

    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8> {
        H::digest_bytes(c)
    }

    /// Static: the commitment is one hash digest.
    fn commitment_size(_c: &Self::Commitment) -> usize {
        H::digest_size()
    }

    /// The witness is every sibling slot's digest.
    fn witness_size(w: &Self::Witness) -> usize {
        w.siblings.len() * H::digest_size()
    }

    /// A commitment already is a slot value: hash goes into hash, untranslated.
    fn to_field(c: &Self::Commitment) -> Self::DigestType {
        *c
    }
}

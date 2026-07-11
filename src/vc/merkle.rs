//! Vector commitment from a Merkle tree, generic over the hash
//! (see `crate::hashes` for the available ones).
//!
//! The vector (m_0, ..., m_{d-1}) is padded with zeros to
//! `width.next_power_of_two()` leaves; leaf i is H_leaf(m_i) and inner nodes
//! are H_node(left, right) (separate domains, so a leaf can never be
//! reinterpreted as an inner node). The commitment is the root, and opening
//! slot i is the usual Merkle authentication path of sibling hashes.
//!
//! Unlike KZG this needs no trusted setup, but a witness is log2(width)
//! digests instead of one group element.

use crate::field::IbslField;
use crate::hashes::{Blake3Hash, Hash, PoseidonHash, RescueHash, Sha256Hash};
use crate::vc::VectorCommitment;
use std::fmt::Debug;
use std::marker::PhantomData;

pub struct MerkleVc<H: Hash> {
    /// Number of leaves; a power of two.
    leaves: usize,
    _hash: PhantomData<H>,
}

pub type Sha2MerkleVc = MerkleVc<Sha256Hash>;
pub type Blake3MerkleVc = MerkleVc<Blake3Hash>;
pub type PoseidonMerkleVc = MerkleVc<PoseidonHash>;
/// Over Winterfell's f128; its proofs are what `crate::stark` re-verifies.
pub type RescueMerkleVc = MerkleVc<RescueHash>;

/// Sibling digests along the path, leaf level first.
pub struct MerklePath<H: Hash> {
    pub siblings: Vec<H::Digest>,
}

// Manual impls: deriving would demand H itself be Clone/Debug.
impl<H: Hash> Clone for MerklePath<H> {
    fn clone(&self) -> Self {
        MerklePath {
            siblings: self.siblings.clone(),
        }
    }
}

impl<H: Hash> Debug for MerklePath<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerklePath").field("siblings", &self.siblings).finish()
    }
}

impl<H: Hash> MerkleVc<H> {
    /// All tree layers, bottom (leaves) to top (root).
    fn layers(&self, values: &[H::Field]) -> Vec<Vec<H::Digest>> {
        assert!(values.len() <= self.leaves);
        let mut layers = Vec::new();
        let mut cur: Vec<H::Digest> = (0..self.leaves)
            .map(|i| H::leaf(&values.get(i).copied().unwrap_or_else(H::Field::zero)))
            .collect();
        while cur.len() > 1 {
            let next = cur.chunks(2).map(|p| H::node(&p[0], &p[1])).collect();
            layers.push(cur);
            cur = next;
        }
        layers.push(cur);
        layers
    }
}

impl<H: Hash> VectorCommitment for MerkleVc<H> {
    type Field = H::Field;
    type Commitment = H::Digest;
    type Witness = MerklePath<H>;

    fn setup(width: usize) -> Self {
        MerkleVc {
            leaves: width.next_power_of_two().max(2),
            _hash: PhantomData,
        }
    }

    fn empty_commitment() -> Self::Commitment {
        H::empty()
    }

    fn commit(&self, values: &[H::Field]) -> Self::Commitment {
        self.layers(values).last().unwrap()[0].clone()
    }

    fn open(&self, values: &[H::Field], i: usize) -> Self::Witness {
        assert!(i < self.leaves);
        let layers = self.layers(values);
        let mut idx = i;
        let mut siblings = Vec::new();
        for layer in &layers[..layers.len() - 1] {
            siblings.push(layer[idx ^ 1].clone());
            idx >>= 1;
        }
        MerklePath { siblings }
    }

    fn check(&self, c: &Self::Commitment, i: usize, value: H::Field, w: &Self::Witness) -> bool {
        if i >= self.leaves || w.siblings.len() != self.leaves.trailing_zeros() as usize {
            return false;
        }
        let mut h = H::leaf(&value);
        let mut idx = i;
        for sib in &w.siblings {
            h = if idx & 1 == 0 {
                H::node(&h, sib)
            } else {
                H::node(sib, &h)
            };
            idx >>= 1;
        }
        h == *c
    }

    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8> {
        H::digest_bytes(c)
    }

    fn to_field(c: &Self::Commitment) -> H::Field {
        H::digest_to_field(c)
    }
}

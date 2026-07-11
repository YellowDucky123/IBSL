//! Vector commitment from a Merkle tree, generic over the hash
//! (see `crate::hashes` for the available ones).
//!
//! The vector (m_0, ..., m_{d-1}) is padded with zeros to
//! `d.next_power_of_two()` leaves — the tree is sized to the vector actually
//! committed, NOT to the setup width, which is only an upper bound. (Padding
//! every commit to the full setup width made each IBSL node commit cost 1023
//! hashes regardless of its fan-out; see README.md.) Leaf i is H_leaf(m_i)
//! and inner nodes are H_node(left, right) (separate domains, so a leaf can
//! never be reinterpreted as an inner node). The commitment is the root, and
//! opening slot i is the usual Merkle authentication path of sibling hashes.
//!
//! The tree width is not part of the commitment; a witness carries it as its
//! length (the verifier recomputes a 2^len-leaf root). Distinct widths
//! produce structurally distinct hash inputs, so cross-width forgeries
//! reduce to hash collisions, same as any other tampering.
//!
//! Unlike KZG this needs no trusted setup, but a witness is log2(width)
//! digests instead of one group element.

use crate::field::IbslField;
use crate::hashes::{Blake3Hash, Hash, PoseidonHash, RescueHash, Sha256Hash};
use crate::vc::VectorCommitment;
use std::fmt::Debug;
use std::marker::PhantomData;

pub struct MerkleVc<H: Hash> {
    /// Maximum vector length committable (the setup width bound); actual
    /// trees are sized to each committed vector.
    max_width: usize,
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

/// Prover-side state: the whole tree, so opening any slot is a matter of
/// copying sibling digests out of the stored layers — zero hashing.
pub struct MerkleOpener<H: Hash> {
    layers: Vec<Vec<H::Digest>>,
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
    /// Leaf count for a vector of length `len`: sized to the vector, with a
    /// floor of 2 so a root is always a node digest, never a bare leaf.
    fn width(len: usize) -> usize {
        len.next_power_of_two().max(2)
    }

    /// All tree layers, bottom (leaves) to top (root).
    fn layers(&self, values: &[H::Field]) -> Vec<Vec<H::Digest>> {
        assert!(values.len() <= self.max_width);
        let mut layers = Vec::new();
        let mut cur: Vec<H::Digest> = (0..Self::width(values.len()))
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
    type Opener = MerkleOpener<H>;

    fn setup(width: usize) -> Self {
        MerkleVc {
            max_width: width.next_power_of_two().max(2),
            _hash: PhantomData,
        }
    }

    fn empty_commitment() -> Self::Commitment {
        H::empty()
    }

    fn commit(&self, values: &[H::Field]) -> (Self::Commitment, Self::Opener) {
        let layers = self.layers(values);
        let root = layers.last().unwrap()[0].clone();
        (root, MerkleOpener { layers })
    }

    fn open(&self, opener: &Self::Opener, i: usize) -> Self::Witness {
        assert!(i < opener.layers[0].len());
        let mut idx = i;
        let mut siblings = Vec::new();
        for layer in &opener.layers[..opener.layers.len() - 1] {
            siblings.push(layer[idx ^ 1].clone());
            idx >>= 1;
        }
        MerklePath { siblings }
    }

    fn check(&self, c: &Self::Commitment, i: usize, value: H::Field, w: &Self::Witness) -> bool {
        // The witness length names the tree width (2^depth leaves): at least
        // one merge (roots are node digests), at most the setup bound, and
        // the opened slot must exist in a tree of that width.
        let depth = w.siblings.len();
        if depth == 0
            || depth > self.max_width.trailing_zeros() as usize
            || i >= (1usize << depth)
        {
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

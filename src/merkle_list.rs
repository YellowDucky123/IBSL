//! Benchmark baseline: a plain Merkle tree membership list — no skip list,
//! no levels, no commitments-of-commitments. The whole membership set is one
//! tree: the sorted keys are the leaves (embedded in the field via the same
//! `Key` map the IBSL uses), the root is sigma, and a membership proof is a
//! single authentication path.
//!
//! That single-path shape is exactly the circuit of Winterfell's original
//! merkle example, so `crate::stark::path` can re-verify these proofs with
//! the same `MerkleAir` the IBSL chain uses — a one-segment, seam-free trace.
//!
//! Insert/delete rebuild the whole tree: O(n) hashing, the honest baseline
//! for a static sorted-leaf Merkle set. (The IBSL implementation also
//! recomputes globally after updates — a documented simplification — so the
//! benchmark compares like with like.)

use crate::field::IbslField;
use crate::hashes::Hash;
use crate::ibsl::Key;
use std::fmt::Debug;

pub struct MerkleList<H: Hash> {
    /// Sorted, deduplicated member keys; leaf i of the tree is keys[i].
    keys: Vec<u64>,
    /// Tree layers bottom-up: layers[0] = padded leaves, last = [root].
    layers: Vec<Vec<H::Digest>>,
}

/// A membership proof: the leaf index plus the sibling digests up the tree.
pub struct PathProof<H: Hash> {
    pub position: usize,
    pub siblings: Vec<H::Digest>,
}

// Manual impls: deriving would demand H itself be Clone/Debug.
impl<H: Hash> Clone for PathProof<H> {
    fn clone(&self) -> Self {
        PathProof {
            position: self.position,
            siblings: self.siblings.clone(),
        }
    }
}

impl<H: Hash> Debug for PathProof<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathProof")
            .field("position", &self.position)
            .field("siblings", &self.siblings)
            .finish()
    }
}

impl<H: Hash> MerkleList<H> {
    pub fn new(keys: &[u64]) -> Self {
        let mut ks = keys.to_vec();
        ks.sort_unstable();
        ks.dedup();
        let mut s = MerkleList { keys: ks, layers: Vec::new() };
        s.rebuild();
        s
    }

    /// Leaves are the keys embedded via `Key` (k -> k + 1), padded with
    /// zero-leaves (the image of -inf) to a power of two — so padding can
    /// never be proven as a member key.
    fn rebuild(&mut self) {
        let width = self.keys.len().next_power_of_two().max(2);
        let mut cur: Vec<H::Digest> = (0..width)
            .map(|i| match self.keys.get(i) {
                Some(&k) => H::leaf(&Key::Val(k).field()),
                None => H::leaf(&H::Field::zero()),
            })
            .collect();
        let mut layers = Vec::new();
        while cur.len() > 1 {
            let next = cur.chunks(2).map(|p| H::node(&p[0], &p[1])).collect();
            layers.push(cur);
            cur = next;
        }
        layers.push(cur);
        self.layers = layers;
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// sigma: the Merkle root over the whole membership set.
    pub fn root(&self) -> H::Digest {
        self.layers.last().unwrap()[0].clone()
    }

    pub fn search(&self, k: u64) -> bool {
        self.keys.binary_search(&k).is_ok()
    }

    /// Returns true if k was newly inserted; rebuilds the tree.
    pub fn insert(&mut self, k: u64) -> bool {
        match self.keys.binary_search(&k) {
            Ok(_) => false,
            Err(i) => {
                self.keys.insert(i, k);
                self.rebuild();
                true
            }
        }
    }

    /// Returns true if k was a member; rebuilds the tree.
    pub fn delete(&mut self, k: u64) -> bool {
        match self.keys.binary_search(&k) {
            Ok(i) => {
                self.keys.remove(i);
                self.rebuild();
                true
            }
            Err(_) => false,
        }
    }

    pub fn prove(&self, k: u64) -> Option<PathProof<H>> {
        let position = self.keys.binary_search(&k).ok()?;
        let mut idx = position;
        let mut siblings = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            siblings.push(layer[idx ^ 1].clone());
            idx >>= 1;
        }
        Some(PathProof { position, siblings })
    }

    /// Recomputes the path from H::leaf(k) and compares against the root.
    pub fn verify(root: &H::Digest, k: u64, p: &PathProof<H>) -> bool {
        let mut h = H::leaf(&Key::Val(k).field());
        let mut idx = p.position;
        for sib in &p.siblings {
            h = if idx & 1 == 0 { H::node(&h, sib) } else { H::node(sib, &h) };
            idx >>= 1;
        }
        // idx must be exhausted: position < 2^depth, so it names a real leaf.
        idx == 0 && h == *root
    }
}

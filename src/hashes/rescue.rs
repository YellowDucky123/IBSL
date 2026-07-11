//! Rescue tree hash over Winterfell's f128: leaf = R([v]), node = R(l || r).
//!
//! This is the hash the STARK AIR in `crate::stark` arithmetises, kept
//! bit-for-bit identical so a real `Ibsl<RescueMerkleVc>` proof can be
//! re-verified inside a STARK:
//!   - `leaf(v)`  = one Rescue permutation of the state [v, 0, 0, 0 | 0, 0]
//!     (a "seam" cycle in the AIR);
//!   - `node(l,r)` = one permutation of [l0, l1, r0, r1 | 0, 0]
//!     (a merge cycle in the AIR).
//!
//! Unlike the other backends there are NO leaf/node domain tags: the AIR's
//! hash cycles have nowhere to absorb a tag without widening the trace. The
//! two domains still differ structurally (a leaf state has three zeroed rate
//! slots), but a node whose right child digest is all-zero collides with a
//! leaf — acceptable for this demo, don't ship it.
//!
//! `digest_to_field` truncates the 2-element digest to its first element,
//! matching the AIR's per-level seam; this halves collision resistance at
//! level boundaries (~64 bits over f128).

use crate::hashes::Hash;
use crate::stark::rescue::{Hash as RescueDigest, Rescue128};
use winterfell::crypto::Hasher;
use winterfell::math::fields::f128::BaseElement;

pub struct RescueHash;

impl Hash for RescueHash {
    type Field = BaseElement;
    type Digest = RescueDigest;

    fn empty() -> Self::Digest {
        RescueDigest::default()
    }

    fn leaf(value: &BaseElement) -> Self::Digest {
        Rescue128::digest(&[*value])
    }

    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        Rescue128::merge(&[*left, *right])
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_bytes().to_vec()
    }

    /// First digest element only — must match the AIR's seam constraint.
    fn digest_to_field(d: &Self::Digest) -> BaseElement {
        d.to_elements()[0]
    }
}

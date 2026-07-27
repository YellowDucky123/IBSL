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

    /// The AIR's merge cycle is fixed 2-to-1; wider nodes have no arithmetised
    /// counterpart, so anything but arity 2 is a bug.
    fn node(values: &[Self::Digest]) -> Self::Digest {
        assert_eq!(values.len(), 2, "Rescue merge is fixed at arity 2");
        Rescue128::merge(&[values[0], values[1]])
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_bytes().to_vec()
    }

    /// Rescue-128 (Winterfell): digest is 2 f128 elements = 256 bits.
    fn digest_size() -> usize {
        32
    }

    /// First digest element only — must match the AIR's seam constraint.
    fn digest_to_field(d: &Self::Digest) -> BaseElement {
        d.to_elements()[0]
    }
}

/// Chain ("caterpillar") Rescue hash for the flat-hash VC: a node's
/// commitment is the LEFT-FOLD of 2-to-1 Rescue merges over its slots,
///   com(s_0..s_{w-1}) = merge(...merge(merge(s_0, s_1), s_2)..., s_{w-1}),
/// with the 1-slot case com([s]) = merge(s, ZERO) — one permutation, and
/// for a leaf vector [key] bit-for-bit the AIR's leaf-hash cycle
/// P([k,0,0,0|0,0]).
///
/// Slots are FULL digests (`FlatHashVc`'s `to_field` is the identity), so an
/// IBSL chain over this hash is one seamless run of merge cycles — exactly
/// what `stark::flat` re-verifies with the existing `MerkleAir`, and with no
/// per-level truncation (full 2-element digests cross level boundaries,
/// unlike `RescueHash`'s first-element seam).
///
/// Same collision caveats as `RescueHash` (no leaf/node domain tags), plus
/// the fold's own: com([s]) == com([s, ZERO]). Demo-grade, don't ship.
pub struct RescueFlatHash;

impl Hash for RescueFlatHash {
    type Field = BaseElement;
    type Digest = RescueDigest;

    fn empty() -> Self::Digest {
        RescueDigest::default()
    }

    /// Unused by `FlatHashVc` (keys embed via `NodeDigest::from_u128` on the
    /// digest type); present to satisfy the trait.
    fn leaf(value: &BaseElement) -> Self::Digest {
        Rescue128::digest(&[*value])
    }

    fn node(values: &[Self::Digest]) -> Self::Digest {
        match values {
            [] => Self::empty(),
            [s] => Rescue128::merge(&[*s, RescueDigest::default()]),
            [first, rest @ ..] => rest
                .iter()
                .fold(*first, |acc, s| Rescue128::merge(&[acc, *s])),
        }
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_bytes().to_vec()
    }

    /// Rescue-128: digest is 2 f128 elements = 256 bits.
    fn digest_size() -> usize {
        32
    }

    /// Unused by `FlatHashVc` (`to_field` is the identity on digests);
    /// present to satisfy the trait.
    fn digest_to_field(d: &Self::Digest) -> BaseElement {
        d.to_elements()[0]
    }
}

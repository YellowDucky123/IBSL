//! Pluggable slot-value type for the IBSL.
//!
//! `NodeDigest` is the type one slot of a committed node vector holds — a
//! key embedded as a number, or a child commitment mapped down by the
//! backend's `to_field`. Despite typical implementors being field elements
//! (arkworks' BLS12-381 Fr for the KZG / Poseidon / byte-hash stacks,
//! Winterfell's f128 for the Rescue/STARK stack), the trait demands no
//! field structure at all — no addition, no multiplication — only the two
//! tiny operations the IBSL itself needs: embed a key (a u64-ish integer)
//! and produce zero for padding. Scheme-specific arithmetic (pairings,
//! FFTs, permutations) stays inside the respective backend.

use std::fmt::Debug;

pub trait NodeDigest: Copy + PartialEq + Debug {
    /// Embeds an integer. Callers only pass values well below any
    /// implementor's range (at most 2^64 + 1, from `Key::field`).
    fn from_u128(v: u128) -> Self;

    /// The padding value for committed vectors.
    fn zero() -> Self;
}

impl NodeDigest for ark_bls12_381::Fr {
    fn from_u128(v: u128) -> Self {
        ark_bls12_381::Fr::from(v)
    }

    fn zero() -> Self {
        <Self as ark_ff::Zero>::zero()
    }
}

impl NodeDigest for winterfell::math::fields::f128::BaseElement {
    fn from_u128(v: u128) -> Self {
        Self::new(v)
    }

    fn zero() -> Self {
        <Self as winterfell::math::FieldElement>::ZERO
    }
}

/// Rescue digests as slot values, for the flat-hash chain backend
/// (`RescueFlatHashVc`): slots hold FULL 2-element digests — `to_field` is
/// the identity there, so the parent-child chain never truncates (unlike
/// the Rescue Merkle backend's first-element seam).
impl NodeDigest for crate::stark::rescue::Hash {
    fn from_u128(v: u128) -> Self {
        use winterfell::math::FieldElement;
        Self::new(
            winterfell::math::fields::f128::BaseElement::new(v),
            winterfell::math::fields::f128::BaseElement::ZERO,
        )
    }

    fn zero() -> Self {
        Self::default()
    }
}

/// Byte digests (SHA-256, BLAKE3) as slot values — the proof that
/// `NodeDigest` is not a mathematical field: no arithmetic exists here at
/// all. Keys embed as little-endian bytes into the low 16 bytes (injective,
/// so distinct keys stay distinct slots).
impl NodeDigest for [u8; 32] {
    fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        b[..16].copy_from_slice(&v.to_le_bytes());
        b
    }

    fn zero() -> Self {
        [0u8; 32]
    }
}

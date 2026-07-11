//! Pluggable scalar field for the IBSL.
//!
//! Everything the structure itself needs from a field is tiny: embed a key
//! (a u64-ish integer) into the field and produce zero for padding. Any field
//! library exposing that can back an IBSL instantiation — arkworks'
//! BLS12-381 Fr for the KZG / Poseidon / byte-hash stacks, or Winterfell's
//! f128 for the Rescue/STARK stack. Scheme-specific arithmetic (pairings,
//! FFTs, permutations) stays inside the respective backend.

use std::fmt::Debug;

pub trait IbslField: Copy + PartialEq + Debug {
    /// Embeds an integer into the field. Callers only pass values well below
    /// any implementor's modulus (at most 2^64 + 1, from `Key::field`).
    fn from_u128(v: u128) -> Self;

    /// Additive identity (used to pad committed vectors).
    fn zero() -> Self;
}

impl IbslField for ark_bls12_381::Fr {
    fn from_u128(v: u128) -> Self {
        ark_bls12_381::Fr::from(v)
    }

    fn zero() -> Self {
        <Self as ark_ff::Zero>::zero()
    }
}

impl IbslField for winterfell::math::fields::f128::BaseElement {
    fn from_u128(v: u128) -> Self {
        Self::new(v)
    }

    fn zero() -> Self {
        <Self as winterfell::math::FieldElement>::ZERO
    }
}

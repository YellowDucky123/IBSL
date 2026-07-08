//! Pluggable vector-commitment abstraction for the IBSL.
//!
//! An IBSL leaf commits to its key; an upper node commits to the vector of
//! its children's compact commitment values, and a proof step opens one
//! position of that vector. Any scheme that can bind a short vector of
//! field elements and open one slot at a time works: this crate ships a
//! KZG10 one (kzg.rs) and a Merkle tree one (merkle.rs) generic over the
//! hashes in `crate::hashes`.

pub mod kzg;
pub mod merkle;

pub use kzg::KzgVc;
pub use merkle::{Blake3MerkleVc, PoseidonMerkleVc, Sha2MerkleVc};

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use sha2::{Digest as _, Sha256};
use std::fmt::Debug;

pub trait VectorCommitment: Sized {
    type Commitment: Clone + Debug;
    type Witness: Clone + Debug;

    /// Public parameters for committing to vectors of length <= `width`.
    fn setup(width: usize) -> Self;

    /// Placeholder for nodes whose commitment has not been computed yet.
    fn empty_commitment() -> Self::Commitment;

    /// C = Com(m_0, ..., m_{d-1}).
    fn commit(&self, values: &[Fr]) -> Self::Commitment;

    /// Opening proof that slot `i` of the vector holds `values[i]`.
    fn open(&self, values: &[Fr], i: usize) -> Self::Witness;

    /// Verifies an opening of slot `i` to `value` against commitment `c`.
    fn check(&self, c: &Self::Commitment, i: usize, value: Fr, w: &Self::Witness) -> bool;

    /// Canonical byte encoding of a commitment (display, and the default
    /// `to_field`).
    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8>;

    /// Maps a child commitment into the scalar field so it can be a slot of
    /// the parent's vector. Collision resistance of this map is what keeps
    /// the parent-child chain binding.
    fn to_field(c: &Self::Commitment) -> Fr {
        Fr::from_le_bytes_mod_order(&Sha256::digest(Self::commitment_bytes(c)))
    }
}

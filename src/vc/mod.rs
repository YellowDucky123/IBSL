//! Pluggable vector-commitment abstraction for the IBSL.
//!
//! An IBSL leaf commits to its key; an upper node commits to the vector of
//! its children's compact commitment values, and a proof step opens one
//! position of that vector. Any scheme that can bind a short vector of
//! field elements and open one slot at a time works — and the field itself
//! is pluggable (`crate::field::IbslField`): this crate ships a KZG10
//! backend over BLS12-381 Fr (kzg.rs), a transparent Ligero backend over Fr
//! (ligero.rs), and a Merkle tree backend (merkle.rs) generic over the
//! hashes in `crate::hashes`, which span Fr (SHA-256, BLAKE3, Poseidon) and
//! Winterfell's f128 (Rescue, STARK-provable).

pub mod kzg;
pub mod ligero;
pub mod merkle;

pub use kzg::KzgVc;
pub use ligero::LigeroVc;
pub use merkle::{Blake3MerkleVc, PoseidonMerkleVc, RescueMerkleVc, Sha2MerkleVc};

use crate::field::IbslField;
use std::fmt::Debug;

pub trait VectorCommitment: Sized {
    /// The field the committed vectors live in.
    type Field: IbslField;
    type Commitment: Clone + Debug;
    type Witness: Clone + Debug;

    /// Public parameters for committing to vectors of length <= `width`.
    fn setup(width: usize) -> Self;

    /// Placeholder for nodes whose commitment has not been computed yet.
    fn empty_commitment() -> Self::Commitment;

    /// C = Com(m_0, ..., m_{d-1}).
    fn commit(&self, values: &[Self::Field]) -> Self::Commitment;

    /// Opening proof that slot `i` of the vector holds `values[i]`.
    fn open(&self, values: &[Self::Field], i: usize) -> Self::Witness;

    /// Verifies an opening of slot `i` to `value` against commitment `c`.
    fn check(&self, c: &Self::Commitment, i: usize, value: Self::Field, w: &Self::Witness) -> bool;

    /// Canonical byte encoding of a commitment (display, equality).
    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8>;

    /// Maps a child commitment into the field so it can be a slot of the
    /// parent's vector. Collision resistance of this map is what keeps the
    /// parent-child chain binding.
    fn to_field(c: &Self::Commitment) -> Self::Field;
}

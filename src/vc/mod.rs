//! Pluggable vector-commitment abstraction for the IBSL.
//!
//! An IBSL leaf commits to its key; an upper node commits to the vector of
//! its children's compact commitment values, and a proof step opens one
//! position of that vector. Any scheme that can bind a short vector of
//! slot values and open one slot at a time works — and the slot type itself
//! is pluggable (`crate::field::NodeDigest`): this crate ships a KZG10
//! backend over BLS12-381 Fr (kzg.rs) and a Merkle tree backend (merkle.rs)
//! generic over the
//! hashes in `crate::hashes`, which span Fr (SHA-256, BLAKE3, Poseidon) and
//! Winterfell's f128 (Rescue, STARK-provable).
//!
//! Two further backends are off by default, each behind a feature, because
//! each drags in a dependency or a machine requirement the core crate should
//! not force on every build:
//!   - `greyhound` — the Greyhound lattice PCS via C FFI (greyhound.rs). The
//!     C is AVX512-only, so it builds and runs only on AVX512 hardware or
//!     under Intel SDE; see build.rs.
//!   - `mnt-kzg` — KZG10 over MNT4-298 on the ark 0.3 stack (mnt_kzg.rs), so
//!     its openings can be verified inside a Groth16 circuit over MNT6-298.

pub mod flat_hash;
pub mod kzg;
pub mod merkle;

#[cfg(feature = "greyhound")]
pub mod greyhound;
#[cfg(feature = "mnt-kzg")]
pub mod mnt_kzg;

pub use flat_hash::{Blake3FlatHashVc, FlatHashVc, PoseidonFlatHashVc, RescueFlatHashVc, Sha2FlatHashVc};
pub use kzg::KzgVc;
pub use merkle::{Blake3MerkleVc, PoseidonMerkleVc, RescueMerkleVc, Sha2MerkleVc};

#[cfg(feature = "greyhound")]
pub use greyhound::GreyhoundVc;
#[cfg(feature = "mnt-kzg")]
pub use mnt_kzg::MntKzgVc;

use crate::field::NodeDigest;
use std::fmt::Debug;

pub trait VectorCommitment: Sized {
    /// The type of one slot of a committed vector: an embedded key at IBSL
    /// leaves, or a child commitment mapped down via `to_field` at upper
    /// nodes. Not necessarily a mathematical field — see `NodeDigest`.
    type DigestType: NodeDigest;
    type Commitment: Clone + Debug;
    type Witness: Clone + Debug;
    /// Prover-side state produced by `commit` and kept alongside the
    /// commitment, so `open` is a lookup rather than a recomputation (the
    /// prover holds the whole structure): Merkle keeps the tree layers, KZG
    /// the interpolated polynomial.
    type Opener;

    /// Public parameters for committing to vectors of length <= `width`.
    fn setup(width: usize) -> Self;

    /// Placeholder for nodes whose commitment has not been computed yet.
    fn empty_commitment() -> Self::Commitment;

    /// C = Com(m_0, ..., m_{d-1}), plus the prover state for opening it.
    fn commit(&self, values: &[Self::DigestType]) -> (Self::Commitment, Self::Opener);

    /// Opening proof that slot `i` of the committed vector holds its value,
    /// derived from the stored prover state — no hashes or commitments are
    /// recomputed here.
    fn open(&self, opener: &Self::Opener, i: usize) -> Self::Witness;

    /// Verifies an opening of slot `i` to `value` against commitment `c`.
    fn check(&self, c: &Self::Commitment, i: usize, value: Self::DigestType, w: &Self::Witness) -> bool;

    /// Canonical byte encoding of a commitment (display, equality).
    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8>;

    /// Size in bytes of a commitment. Backends whose commitment is a
    /// fixed-size digest override this with the static answer (e.g. the
    /// hash's paper-specified digest size); the default measures the
    /// canonical encoding.
    fn commitment_size(c: &Self::Commitment) -> usize {
        Self::commitment_bytes(c).len()
    }

    /// Size in bytes of one opening witness as it would go on the wire.
    /// Hash-path backends count sibling digests at the hash's static digest
    /// size; the rest measure their canonical serialization.
    fn witness_size(w: &Self::Witness) -> usize;

    /// Maps a child commitment into `DigestType` so it can be a slot of the
    /// parent's vector. Collision resistance of this map is what keeps the
    /// parent-child chain binding.
    fn to_field(c: &Self::Commitment) -> Self::DigestType;
}

/// Backends whose node commitment is a plain hash of its slots, so a
/// membership proof can be a Merkle-tree-style *sibling-hash chain*: the
/// verifier recomputes each node's commitment bottom-up from the opened
/// value plus the sibling data in the witness, never carrying the
/// intermediate commitments in the proof. This is what powers the IBSL's
/// Merkle mode (`Ibsl::prove_hash` / `Ibsl::verify_hash`); the Merkle-tree
/// backends (merkle.rs) implement it, KZG does not.
pub trait HashVc: VectorCommitment {
    /// The commitment a committed vector would have, reconstructed from the
    /// value at slot `position` and the sibling data in `w` — i.e. `check`'s
    /// recomputation, but returning the digest instead of comparing it.
    /// `None` if the witness is malformed for that position. `check` is then
    /// exactly `recompute(..).map_or(false, |c| c == commitment)`.
    fn recompute(
        &self,
        position: usize,
        value: Self::DigestType,
        w: &Self::Witness,
    ) -> Option<Self::Commitment>;
}

/// Backends whose per-slot opening proofs can be collapsed into ONE
/// constant-size witness covering a whole batch of `(commitment, slot,
/// value)` claims — e.g. KZG via a SHPLONK/BDFG20 batch opening (kzg.rs).
/// An IBSL membership proof over such a backend shrinks from L per-level
/// witnesses to the L commitments plus a single aggregate
/// (`Ibsl::prove_agg` / `Ibsl::verify_agg`).
pub trait AggregatableVc: VectorCommitment {
    /// The single witness standing in for all per-step opening proofs.
    type AggWitness: Clone + Debug;

    /// Size in bytes of the ONE aggregated witness — this replaces all the
    /// per-level `witness_size` contributions of a non-aggregated proof
    /// (for KZG: two compressed G1 points, however long the chain).
    fn agg_witness_size(w: &Self::AggWitness) -> usize;

    /// Aggregates the openings `claims[i] = (opener_i, commitment_i,
    /// slot_i, value_i)` into one witness. Challenges are derived by
    /// Fiat-Shamir from the `(commitment, slot, value)` triples, which is
    /// exactly the data `aggregate_check` re-derives them from.
    fn aggregate_open(
        &self,
        claims: &[(&Self::Opener, &Self::Commitment, usize, Self::DigestType)],
    ) -> Self::AggWitness;

    /// Verifies every `(commitment, slot, value)` claim against the single
    /// aggregated witness.
    fn aggregate_check(
        &self,
        claims: &[(&Self::Commitment, usize, Self::DigestType)],
        witness: &Self::AggWitness,
    ) -> bool;
}

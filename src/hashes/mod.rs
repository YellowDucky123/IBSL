//! Hash functions for the Merkle-tree vector commitment, one per file.
//!
//! `Hash` is what the tree needs from a hash: a digest type and two
//! domain-separated compressions (leaf and inner node), plus an embedding of
//! digests into the scalar field so the IBSL can commit to a child's root.
//!
//!   - `Sha256Hash` (sha2.rs): byte-oriented, fast natively, expensive
//!     inside an arithmetic circuit;
//!   - `Blake3Hash` (blake3.rs): byte-oriented like SHA-256 but faster in
//!     software; same circuit-unfriendliness;
//!   - `PoseidonHash` (poseidon.rs): algebraic hash over Fr, digests stay
//!     field elements, which is what a zk circuit wants.

pub mod blake3;
pub mod poseidon;
pub mod sha2;

pub use blake3::Blake3Hash;
pub use poseidon::PoseidonHash;
pub use sha2::Sha256Hash;

use ark_bls12_381::Fr;
use std::fmt::Debug;

/// A digest type plus domain-separated leaf and node compressions.
pub trait Hash {
    type Digest: Clone + PartialEq + Debug;

    /// Digest of an all-zero placeholder (for not-yet-committed nodes).
    fn empty() -> Self::Digest;
    fn leaf(value: &Fr) -> Self::Digest;
    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest;
    fn digest_bytes(d: &Self::Digest) -> Vec<u8>;
    /// Embeds a digest into the scalar field (used by the IBSL to commit to
    /// a child's root).
    fn digest_to_field(d: &Self::Digest) -> Fr;
}

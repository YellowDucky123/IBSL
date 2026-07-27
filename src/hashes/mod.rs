//! Hash functions for the Merkle-tree vector commitment, one per file.
//!
//! `Hash` is what the tree needs from a hash: a field it works over, a digest
//! type, two compressions (leaf and inner node), plus an embedding of digests
//! back into the field so the IBSL can commit to a child's root. The field is
//! pluggable per backend (see `crate::field`):
//!
//!   - `Sha256Hash` (sha2.rs): over Fr; byte-oriented, fast natively,
//!     expensive inside an arithmetic circuit;
//!   - `Blake3Hash` (blake3.rs): over Fr; byte-oriented like SHA-256 but
//!     faster in software; same circuit-unfriendliness;
//!   - `PoseidonHash` (poseidon.rs): algebraic hash over Fr, digests stay
//!     field elements, which is what a zk circuit wants;
//!   - `RescueHash` (rescue.rs): algebraic hash over Winterfell's f128,
//!     bit-for-bit the hash the STARK AIR (crate::stark) arithmetises, so
//!     proofs from an `Ibsl<RescueMerkleVc>` can be verified in a STARK.

pub mod blake3;
pub mod poseidon;
pub mod rescue;
pub mod sha2;

pub use blake3::Blake3Hash;
pub use poseidon::PoseidonHash;
pub use rescue::{RescueFlatHash, RescueHash};
pub use sha2::Sha256Hash;

use crate::field::NodeDigest;
use std::fmt::Debug;

/// A field, a digest type, and leaf/node compressions over them.
pub trait Hash {
    type Field: NodeDigest;
    type Digest: Clone + PartialEq + Debug;

    /// Digest of an all-zero placeholder (for not-yet-committed nodes).
    fn empty() -> Self::Digest;
    fn leaf(value: &Self::Field) -> Self::Digest;
    fn node(values: &[Self::Digest]) -> Self::Digest;
    fn digest_bytes(d: &Self::Digest) -> Vec<u8>;
    /// Digest size in bytes, as specified by the hash's defining
    /// paper/RFC (e.g. SHA-256 and BLAKE3 both output 256 bits = 32).
    fn digest_size() -> usize;
    /// Embeds a digest into the field (used by the IBSL to commit to a
    /// child's root).
    fn digest_to_field(d: &Self::Digest) -> Self::Field;
}

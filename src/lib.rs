//! IBSL as a library: exposes the data structure (`ibsl`), the pluggable
//! field and vector-commitment abstractions (`field`, `vc`, `hashes`), the
//! plain Merkle baseline (`merkle_list`), the STARK compiler (`stark`) and
//! the benchmark driver (`bench`), so external harnesses (e.g. the
//! zkcreds-rs Groth16 comparison) can build IBSL instances with their own
//! `VectorCommitment` backends.
//!
//! Every backend the project has — including the experimental lattice one
//! and the MNT4-298 KZG the Groth16 harness verifies in-circuit — lives in
//! `vc`, so a harness never has to define its own. The two that carry a
//! dependency or hardware cost are feature-gated (`greyhound`, `mnt-kzg`);
//! see `vc`'s module docs.

pub mod bench;
pub mod field;
pub mod hashes;
pub mod ibsl;
pub mod merkle_list;
pub mod stark;
pub mod vc;

#[cfg(test)]
mod tests;

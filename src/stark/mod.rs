//! A Winterfell STARK that re-verifies real IBSL membership proofs.
//!
//! The pipeline: build an `Ibsl<RescueMerkleVc>` (the Rescue backend over
//! Winterfell's f128 — the field is pluggable, see `crate::field`), take the
//! real proof `pi = Ibsl::prove(k)`, and hand it to `membership::prove`,
//! which arithmetises the whole containment chain — every per-level opening
//! AND the seam between levels (child digest -> `to_field` -> leaf hash in
//! the parent's tree) — into one execution trace. `membership::verify`
//! checks the resulting STARK against sigma without seeing k or pi.
//!
//! The AIR (air.rs) is adapted from Winterfell's `examples/src/merkle`
//! single-authentication-path example, extended with a *seam register* so
//! one trace can chain multiple per-level openings; rescue.rs is the
//! vendored Rescue hash it arithmetises (also used natively by
//! `crate::hashes::rescue`); prover.rs builds the trace.
//!
//! What stays dynamic here is the STARK's own commitment hash H (BLAKE3 /
//! SHA3, the FRI Merkle hasher) — the *in-circuit* hash is Rescue, fixed by
//! the AIR. A polynomial VC (KZG) can't reuse THIS AIR — its openings are
//! pairing checks, not hash paths — but could in principle get its own: a
//! STARK can arithmetise the pairing verification itself (non-native
//! 381-bit F_q limb arithmetic, Miller loop, final exponentiation, with the
//! accept bit pinned by a boundary assertion — the constraints, not FRI,
//! are what make that bit sound). That is a far larger circuit than this
//! whole module and is not implemented here; the cheaper practical route is
//! a proof-of-equivalence to a hash commitment plus one native KZG check.
//!
//! rescue.rs and parts of air.rs/prover.rs are vendored from Facebook's
//! Winterfell (MIT), adapted for this crate.

use winterfell::math::FieldElement;

pub mod air;
pub mod membership;
pub mod prover;
pub mod rescue;

/// Trace width: 6 Rescue state registers (0-1 accumulator, 2-3 incoming
/// sibling, 4-5 capacity), register 6 = the position/index bit, register 7 =
/// the seam flag (1 on the transition that starts a new IBSL level by
/// truncating the accumulated digest to its first element).
pub const TRACE_WIDTH: usize = 8;

// CONSTRAINT EVALUATION HELPERS
// (vendored from examples/src/utils/mod.rs)
// ================================================================================================

/// Returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

/// Returns zero only when a == zero.
pub fn is_zero<E: FieldElement>(a: E) -> E {
    a
}

/// Returns zero only when a == zero || a == one.
pub fn is_binary<E: FieldElement>(a: E) -> E {
    a * a - a
}

/// Returns zero when a == one, and one when a == zero; assumes a is binary.
pub fn not<E: FieldElement>(a: E) -> E {
    E::ONE - a
}

/// Trait to simplify aggregating a flagged constraint into the result slot.
pub trait EvaluationResult<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

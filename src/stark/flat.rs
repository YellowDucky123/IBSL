//! Bridge: a real IBSL *flat-hash* proof -> a STARK, on the SAME `MerkleAir`
//! as the Merkle chain — but seam-free.
//!
//! The flat-hash backend (`RescueFlatHashVc`) commits a node as the
//! left-fold of 2-to-1 Rescue merges over its slots, and its `to_field` is
//! the identity: a child's FULL 2-element digest is the parent's slot value.
//! So the entire membership chain — leaf-hash k, fold through every level up
//! to sigma — is one uninterrupted run of merge cycles, i.e. exactly the
//! shape of a plain single-segment Merkle path (`stark::path`), with no
//! seam truncation anywhere (and hence no 64-bit collision pinch at level
//! boundaries).
//!
//! Per level with opened slot i and width w, the fold is arithmetised as:
//!   - i = 0: the child digest is the fold seed; merge each later sibling
//!     slot in order (position bit 0 — accumulator stays left);
//!   - i > 0: the prover folds the sibling slots BEFORE i into one prefix
//!     digest natively and feeds it as the first merge with position bit 1
//!     (accumulator on the right), then merges the later siblings as above.
//!     Compressing the prefix is sound for membership: any prefix preimage
//!     reaching sigma with a different chain is a Rescue collision — the
//!     same argument that lets a Merkle witness be trusted sibling data.
//!   - w = 1 (a single-child node): one merge with the ZERO digest,
//!     matching `RescueFlatHash::node([s]) = merge(s, ZERO)`; the leaf
//!     node's own 1-slot commit IS the trace's leaf-hash cycle
//!     P([k,0,0,0|0,0]), so it costs no extra merge.
//!
//! `verify` is `membership::verify` verbatim: same AIR, same public inputs
//! (sigma + cycle count), verifier learns neither k nor the proof.

use winterfell::{
    crypto::{ElementHasher, Hasher as _},
    math::fields::f128::BaseElement,
    Prover as _, VerifierError,
};

use crate::ibsl::{Key, Step};
use crate::vc::RescueFlatHashVc;

use super::membership;
use super::prover::{MerkleProver, Segment};
use super::rescue::{self, Rescue128};

/// Compiles a real `Ibsl<RescueFlatHashVc>` proof into a STARK. Returns the
/// proof and the number of path cycles for the verifier.
pub fn prove<H>(k: u64, pi: &[Step<RescueFlatHashVc>]) -> (winterfell::Proof, usize)
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    assert!(!pi.is_empty(), "empty IBSL proof");

    // pi is top-down (sigma first, leaf last); the trace folds bottom-up.
    // The leaf step is covered by the trace's leaf-hash cycle (its vector is
    // [key], so its witness must be empty).
    let leaf = pi.last().unwrap();
    assert!(
        leaf.witness.siblings().is_empty() && leaf.position == 0,
        "leaf step must open slot 0 of a 1-slot vector"
    );

    let mut siblings: Vec<rescue::Hash> = Vec::new();
    let mut position = 0usize;
    for step in pi.iter().rev().skip(1) {
        let slots = step.witness.siblings();
        let i = step.position;
        assert!(i <= slots.len(), "opened slot outside the committed vector");
        if slots.is_empty() {
            // w = 1: com = merge(child, ZERO).
            siblings.push(rescue::Hash::default());
        } else if i == 0 {
            // Child digest seeds the fold; absorb every later slot.
            siblings.extend_from_slice(slots);
        } else {
            // Fold the slots before i into one prefix digest; the child
            // enters that merge on the RIGHT (bit 1), then the later slots
            // absorb as usual.
            let prefix = slots[1..i]
                .iter()
                .fold(slots[0], |acc, s| Rescue128::merge(&[acc, *s]));
            // Only merges with a set bit (accumulator on the right) need a
            // representable position bit; unset bits past 64 are harmless.
            assert!(
                siblings.len() < usize::BITS as usize,
                "prefix merge index exceeds position bits"
            );
            position |= 1 << siblings.len();
            siblings.push(prefix);
            siblings.extend_from_slice(&slots[i..]);
        }
    }

    let segment = Segment { position, siblings };
    let path_cycles = segment.num_cycles();

    let prover = MerkleProver::<H>::new(membership::default_options(), path_cycles);
    let trace = prover.build_trace(Key::Val(k).field(), &[segment]);
    let proof = prover.prove(trace).expect("proof generation");
    (proof, path_cycles)
}

/// Verifies the STARK against the trusted sigma. Identical to the Merkle
/// chain's verifier: the AIR and public inputs are shared.
pub fn verify<H>(
    sigma: &rescue::Hash,
    path_cycles: usize,
    proof: winterfell::Proof,
) -> Result<(), VerifierError>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    membership::verify::<H>(sigma, path_cycles, proof)
}

/// Convenience instantiations over BLAKE3 as the STARK's own (FRI/Merkle)
/// commitment hash, so drivers outside this crate need no winterfell import.
pub fn prove_blake3(k: u64, pi: &[Step<RescueFlatHashVc>]) -> (winterfell::Proof, usize) {
    prove::<winterfell::crypto::hashers::Blake3_256<BaseElement>>(k, pi)
}

pub fn verify_blake3(
    sigma: &rescue::Hash,
    path_cycles: usize,
    proof: winterfell::Proof,
) -> Result<(), VerifierError> {
    verify::<winterfell::crypto::hashers::Blake3_256<BaseElement>>(sigma, path_cycles, proof)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibsl::Ibsl;

    /// End to end: a real Ibsl<RescueFlatHashVc> proof verifies natively AND
    /// as a STARK against the same sigma.
    #[test]
    fn real_flat_hash_proof_verifies_as_stark() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = Ibsl::<RescueFlatHashVc>::new(&keys, 7);
        let sigma = s.root_commitment();

        for k in [3, 45, 90] {
            let pi = s.prove(k).expect("member proof");
            assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "native proof for {k} rejected");

            let (proof, cycles) = prove_blake3(k, &pi);
            assert!(
                verify_blake3(&sigma, cycles, proof).is_ok(),
                "STARK proof for {k} rejected"
            );
        }
    }

    /// A wrong sigma must be rejected.
    #[test]
    fn wrong_sigma_rejected() {
        let s = Ibsl::<RescueFlatHashVc>::new(&[10, 20, 30, 40], 3);
        let pi = s.prove(30).unwrap();
        let (proof, cycles) = prove_blake3(30, &pi);

        let s2 = Ibsl::<RescueFlatHashVc>::new(&[10, 20, 30, 40, 50], 3);
        let wrong = s2.root_commitment();
        assert!(verify_blake3(&wrong, cycles, proof).is_err());
    }
}

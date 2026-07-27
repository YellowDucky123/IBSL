//! Bridge: a real IBSL proof -> a STARK.
//!
//! `prove` takes the actual `pi = Ibsl::prove(k)` — the top-down chain of
//! `(com_i, pi_com_i)` pairs — reverses it into bottom-up segments, and
//! arithmetises the whole chain in one trace: leaf-hash k, climb the leaf
//! node's tree, cross a seam (digest -> to_field -> leaf hash) into the next
//! level, climb again, ... until the last segment resolves to sigma, which
//! the AIR asserts against the public input. `verify` checks the STARK
//! knowing only sigma and the path length — not k, not pi.
//!
//! Generic over two things, mirroring the crate's pluggable design:
//!   - V: any `VectorCommitment` whose openings are Rescue Merkle paths
//!     (`StarkVc`). A polynomial VC (KZG) can't implement this trait — it
//!     has no sibling path to hand the Rescue AIR — though a STARK for KZG
//!     openings is possible in principle with its own AIR arithmetising the
//!     pairing check (see the module doc in stark/mod.rs).
//!   - H: the STARK's own commitment hash (FRI/Merkle hasher), e.g. BLAKE3.

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::fields::f128::BaseElement,
    AcceptableOptions, BatchingMethod, FieldExtension, ProofOptions, Prover as _, VerifierError,
};

use crate::ibsl::{Key, Step};
use crate::vc::{RescueMerkleVc, VectorCommitment};

use super::air::{MerkleAir, PublicInputs};
use super::prover::{MerkleProver, Segment};
use super::rescue;

/// A vector commitment the Rescue AIR can re-verify: commitments are Rescue
/// digests over f128 and openings are Rescue Merkle sibling paths.
pub trait StarkVc:
    VectorCommitment<DigestType = BaseElement, Commitment = rescue::Hash>
{
    /// The opening's sibling digests, pair level first (climb order).
    fn siblings(w: &Self::Witness) -> Vec<rescue::Hash>;
}

impl StarkVc for RescueMerkleVc {
    fn siblings(w: &Self::Witness) -> Vec<rescue::Hash> {
        w.siblings.clone()
    }
}

/// Compiles a real IBSL proof into a STARK. Returns the proof and the number
/// of path cycles, which the verifier needs alongside sigma.
pub fn prove<V, H>(k: u64, pi: &[Step<V>]) -> (winterfell::Proof, usize)
where
    V: StarkVc,
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    assert!(!pi.is_empty(), "empty IBSL proof");

    // pi is top-down (sigma first, leaf last); the trace climbs bottom-up.
    let segments: Vec<Segment> = pi
        .iter()
        .rev()
        .map(|s| Segment {
            position: s.position,
            siblings: V::siblings(&s.witness),
        })
        .collect();
    let path_cycles: usize = segments.iter().map(Segment::num_cycles).sum();

    let prover = MerkleProver::<H>::new(default_options(), path_cycles);
    let trace = prover.build_trace(Key::Val(k).field(), &segments);
    let proof = prover.prove(trace).expect("proof generation");
    (proof, path_cycles)
}

/// Verifies the STARK against the trusted sigma.
pub fn verify<H>(
    sigma: &rescue::Hash,
    path_cycles: usize,
    proof: winterfell::Proof,
) -> Result<(), VerifierError>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    let pub_inputs = PublicInputs {
        tree_root: sigma.to_elements(),
        num_path_cycles: path_cycles,
    };
    let acceptable = AcceptableOptions::OptionSet(vec![proof.options().clone()]);
    winterfell::verify::<MerkleAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
        proof, pub_inputs, &acceptable,
    )
}

/// Reasonable STARK parameters: 28 queries, blowup 8, ~96-bit conjectured.
/// Shared with the plain-path circuit (stark::path) so the two benchmarks
/// compare like with like.
pub(super) fn default_options() -> ProofOptions {
    ProofOptions::new(
        28,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibsl::Ibsl;
    use winterfell::crypto::hashers::Blake3_256;

    type Blake3 = Blake3_256<BaseElement>;

    /// End to end: a real Ibsl<RescueMerkleVc> proof verifies natively AND as
    /// a STARK against the same sigma.
    #[test]
    fn real_ibsl_proof_verifies_as_stark() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = Ibsl::<RescueMerkleVc>::new(&keys, 7);
        let sigma = s.root_commitment();

        for k in [3, 45, 90] {
            let pi = s.prove(k).expect("member proof");
            assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "native proof for {k} rejected");

            let (proof, cycles) = prove::<_, Blake3>(k, &pi);
            assert!(
                verify::<Blake3>(&sigma, cycles, proof).is_ok(),
                "STARK proof for {k} rejected"
            );
        }
    }

    /// A wrong sigma must be rejected.
    #[test]
    fn wrong_sigma_rejected() {
        let s = Ibsl::<RescueMerkleVc>::new(&[10, 20, 30, 40], 3);
        let pi = s.prove(30).unwrap();
        let (proof, cycles) = prove::<_, Blake3>(30, &pi);

        let s2 = Ibsl::<RescueMerkleVc>::new(&[10, 20, 30, 40, 50], 3);
        let wrong = s2.root_commitment();
        assert!(verify::<Blake3>(&wrong, cycles, proof).is_err());
    }

    /// A proof for one key must not verify a different tree state: after an
    /// insert, the old STARK no longer matches the new sigma.
    #[test]
    fn stale_proof_rejected() {
        let mut s = Ibsl::<RescueMerkleVc>::new(&[10, 20, 30, 40], 3);
        let pi = s.prove(30).unwrap();
        let (proof, cycles) = prove::<_, Blake3>(30, &pi);

        s.insert(35);
        let new_sigma = s.root_commitment();
        assert!(verify::<Blake3>(&new_sigma, cycles, proof).is_err());
    }
}

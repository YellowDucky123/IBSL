//! The plain Merkle membership circuit: Winterfell's original merkle-example
//! shape — ONE authentication path, no seams — run on the same `MerkleAir`
//! as a one-segment trace. This is what re-verifies a
//! `crate::merkle_list::MerkleList<RescueHash>` proof; the verifier sees
//! only the root and the path length, not k or the proof.

use winterfell::{
    crypto::ElementHasher, math::fields::f128::BaseElement, Prover as _, VerifierError,
};

use crate::hashes::RescueHash;
use crate::ibsl::Key;
use crate::merkle_list::PathProof;

use super::membership;
use super::prover::{MerkleProver, Segment};
use super::rescue;

/// Compiles a plain Merkle membership proof into a STARK. Returns the proof
/// and the number of path cycles (1 leaf hash + one merge per sibling).
pub fn prove<H>(k: u64, p: &PathProof<RescueHash>) -> (winterfell::Proof, usize)
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    let segment = Segment {
        position: p.position,
        siblings: p.siblings.clone(),
    };
    let path_cycles = segment.num_cycles();

    let prover = MerkleProver::<H>::new(membership::default_options(), path_cycles);
    let trace = prover.build_trace(Key::Val(k).field(), &[segment]);
    let proof = prover.prove(trace).expect("proof generation");
    (proof, path_cycles)
}

/// Verifies the STARK against the trusted root. Identical to the IBSL
/// verifier: the AIR and public inputs are shared, a plain path is just the
/// seam-free case.
pub fn verify<H>(
    root: &rescue::Hash,
    path_cycles: usize,
    proof: winterfell::Proof,
) -> Result<(), VerifierError>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    membership::verify::<H>(root, path_cycles, proof)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_list::MerkleList;
    use winterfell::crypto::hashers::Blake3_256;

    type Blake3 = Blake3_256<BaseElement>;

    /// End to end: a real MerkleList proof verifies natively AND as a STARK
    /// against the same root.
    #[test]
    fn real_merkle_list_proof_verifies_as_stark() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = MerkleList::<RescueHash>::new(&keys);
        let root = s.root();

        for k in [3, 45, 90] {
            let p = s.prove(k).expect("member proof");
            assert!(MerkleList::verify(&root, k, &p), "native proof for {k} rejected");

            let (proof, cycles) = prove::<Blake3>(k, &p);
            assert!(
                verify::<Blake3>(&root, cycles, proof).is_ok(),
                "STARK proof for {k} rejected"
            );
        }
    }

    /// A wrong root must be rejected.
    #[test]
    fn wrong_root_rejected() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = MerkleList::<RescueHash>::new(&keys);
        let p = s.prove(30).unwrap();
        let (proof, cycles) = prove::<Blake3>(30, &p);

        let s2 = MerkleList::<RescueHash>::new(&[10, 20, 30, 40]);
        assert!(verify::<Blake3>(&s2.root(), cycles, proof).is_err());
    }
}

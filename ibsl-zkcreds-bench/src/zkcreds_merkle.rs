//! Benchmarks zkcreds-rs's own Groth16 Merkle-membership circuit
//! (`TreeMembershipProver`, Poseidon two-to-one hash over BLS12-381 Fr),
//! driven directly through linkg16 — the exact Groth16 zkcreds-rs uses —
//! so nothing in that repo needs modification.
//!
//! For each tree height h (capacity 2^(h-1) leaves): constraint count,
//! CRS generation time, proving time, verification time, proof size.

use std::marker::PhantomData;
use std::time::{Duration, Instant};

use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::ToConstraintField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_serialize::CanonicalSerialize;
use linkg16::groth16;
use rand::{rngs::StdRng, SeedableRng};
use zkcreds::{
    attrs::Attrs,
    com_tree::{ComTree, TreeMembershipProver},
    poseidon_utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh},
    test_util::NameAndBirthYear,
};

type AC = Bls12PoseidonCommitter;
type H = Bls12PoseidonCrh;
type Prover = TreeMembershipProver<Fr, AC, AC, H, H>;

const DEFAULT_HEIGHTS: &[usize] = &[11, 15, 18, 32];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

pub fn run(heights: &[usize]) {
    let heights = if heights.is_empty() { DEFAULT_HEIGHTS } else { heights };
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    println!("== zkcreds-rs Groth16 Merkle membership (Poseidon, BLS12-381) ==");
    println!("| height | capacity | constraints | CRS gen | prove | verify | proof size |");
    println!("|---|---|---|---|---|---|---|");

    for &h in heights {
        let tree_height = h as u32;

        // One credential in the tree, exactly like zkcreds' com_tree tests.
        let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
        let person_com = Attrs::<_, AC>::commit(&person);
        let mut tree = ComTree::<Fr, H, AC>::empty((), tree_height);
        let auth_path = tree.insert(17, &person_com);
        let root = auth_path.root();

        // Constraint count of the membership circuit at this height.
        let num_constraints = {
            let cs = ConstraintSystem::<Fr>::new_ref();
            cs.set_optimization_goal(OptimizationGoal::Constraints);
            let circuit: Prover = TreeMembershipProver {
                height: tree_height,
                crh_param: (),
                attrs_com: person_com,
                root: root.clone(),
                auth_path: Some(auth_path.path.clone()),
                _marker: PhantomData,
            };
            circuit.generate_constraints(cs.clone()).expect("synthesis");
            cs.num_constraints()
        };

        // CRS generation (same circuit shape zkcreds' gen_tree_memb_crs builds).
        let (pk, crs_gen) = timed(|| {
            let blank: Prover = TreeMembershipProver {
                height: tree_height,
                crh_param: (),
                attrs_com: Default::default(),
                root: Default::default(),
                auth_path: None,
                _marker: PhantomData,
            };
            groth16::generate_random_parameters::<E, _, _>(blank, &mut rng).expect("CRS gen")
        });
        let vk = pk.verifying_key();

        // Prove (average over a few runs).
        const PROVE_ITERS: u32 = 5;
        let mut proof = None;
        let (_, prove_total) = timed(|| {
            for _ in 0..PROVE_ITERS {
                let circuit: Prover = TreeMembershipProver {
                    height: tree_height,
                    crh_param: (),
                    attrs_com: person_com,
                    root: root.clone(),
                    auth_path: Some(auth_path.path.clone()),
                    _marker: PhantomData,
                };
                proof = Some(groth16::create_random_proof(circuit, &pk, &mut rng).expect("prove"));
            }
        });
        let prove = prove_total / PROVE_ITERS;
        let proof = proof.unwrap();

        let mut proof_bytes = Vec::new();
        proof.serialize(&mut proof_bytes).expect("serialize proof");

        // Verify (public inputs = attrs commitment fields ++ root fields,
        // exactly as zkcreds' verify_tree_memb does).
        let inputs: Vec<Fr> = [
            person_com.to_field_elements().unwrap(),
            root.to_field_elements().unwrap(),
        ]
        .concat();
        const VERIFY_ITERS: u32 = 50;
        let (ok, verify_total) = timed(|| {
            (0..VERIFY_ITERS).all(|_| groth16::verify_proof(&vk, &proof, &inputs).unwrap())
        });
        assert!(ok, "Groth16 verification failed at height {h}");
        let verify = verify_total / VERIFY_ITERS;

        println!(
            "| {h} | 2^{} | {num_constraints} | {crs_gen:.2?} | {prove:.2?} | {verify:.2?} | {} B |",
            h - 1,
            proof_bytes.len()
        );
    }
}

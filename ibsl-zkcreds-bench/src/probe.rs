//! One-off cost probe for the MNT4-298-inside-MNT6-298 circuit primitives:
//! constraint counts for pairings, preparations, and scalar muls, to size
//! the IBSL-KZG Groth16 circuit before building it.

use ark_ec::ProjectiveCurve;
use ark_mnt4_298::constraints::{G1Var, G2Var, PairingVar};
use ark_mnt4_298::{Fq, G1Projective, G2Projective};
use ark_r1cs_std::pairing::PairingVar as PairingVarTrait;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::ConstraintSystem;

pub fn run() {
    let cs = ConstraintSystem::<Fq>::new_ref();

    let g1 = G1Projective::prime_subgroup_generator();
    let g2 = G2Projective::prime_subgroup_generator();

    let p = G1Var::new_witness(cs.clone(), || Ok(g1)).unwrap();
    let q = G2Var::new_witness(cs.clone(), || Ok(g2)).unwrap();
    println!("alloc p,q: {}", cs.num_constraints());

    let mut last = cs.num_constraints();
    let pp = PairingVar::prepare_g1(&p).unwrap();
    println!("prepare_g1: {}", cs.num_constraints() - last);

    last = cs.num_constraints();
    let qp = PairingVar::prepare_g2(&q).unwrap();
    println!("prepare_g2: {}", cs.num_constraints() - last);

    last = cs.num_constraints();
    let _gt = PairingVar::pairing(pp.clone(), qp.clone()).unwrap();
    println!("pairing (miller+final exp): {}", cs.num_constraints() - last);

    last = cs.num_constraints();
    let _gt2 = PairingVar::product_of_pairings(&[pp.clone(), pp.clone()], &[qp.clone(), qp.clone()])
        .unwrap();
    println!("product_of_pairings (2 pairs): {}", cs.num_constraints() - last);

    // Variable-base scalar mul by a ~298-bit scalar (bits witnessed).
    last = cs.num_constraints();
    let bits: Vec<Boolean<Fq>> = (0..298)
        .map(|i| Boolean::new_witness(cs.clone(), || Ok(i % 2 == 0)).unwrap())
        .collect();
    let _r = p.scalar_mul_le(bits.iter()).unwrap();
    println!("g1 scalar_mul_le 298 bits (var base): {}", cs.num_constraints() - last);

    // G1 witness alloc alone (MNT4-298 G1 has cofactor 1).
    last = cs.num_constraints();
    let _p2 = G1Var::new_witness(cs.clone(), || Ok(g1)).unwrap();
    println!("g1 alloc alone: {}", cs.num_constraints() - last);

    // Nonnative MNT4-Fr arithmetic inside the MNT6-Fr(=MNT4-Fq) circuit:
    // witness z, enforce z^512 = 1 (9 squarings), decompose to bits.
    use ark_ff::UniformRand;
    use ark_mnt4_298::Fr as Fr4;
    use ark_nonnative_field::NonNativeFieldVar;
    let mut rng = ark_std::test_rng();
    let z_val = Fr4::rand(&mut rng);
    last = cs.num_constraints();
    let z = NonNativeFieldVar::<Fr4, Fq>::new_witness(cs.clone(), || Ok(z_val)).unwrap();
    println!("nonnative alloc: {}", cs.num_constraints() - last);
    last = cs.num_constraints();
    let mut acc = z.clone();
    for _ in 0..9 {
        acc = &acc * &acc;
    }
    println!("9 nonnative squarings: {}", cs.num_constraints() - last);
    last = cs.num_constraints();
    let _zbits = z.to_bits_le().unwrap();
    println!("nonnative to_bits_le: {}", cs.num_constraints() - last);

    println!("total: {}, satisfied: {:?}", cs.num_constraints(), cs.is_satisfied());
}

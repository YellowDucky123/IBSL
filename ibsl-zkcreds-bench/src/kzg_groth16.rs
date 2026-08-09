//! IBSL-KZG membership re-verified inside Groth16 — "the groth16 in
//! zkcreds-rs" (linkg16), instantiated over the MNT4-298 / MNT6-298
//! pairing-friendly cycle.
//!
//! Statement (public input: sigma, the IBSL root commitment, as affine
//! coordinates): "I know a chain (com_0 = sigma, pi_0), ..., (com_{L-1},
//! pi_{L-1}) of KZG10 openings over MNT4-298 and a key k such that every
//! opening verifies, each non-leaf opening reveals the seam value of the
//! next commitment, and the leaf opening reveals k." This is exactly
//! `Ibsl::verify` arithmetised; the verifier learns neither k, nor the
//! path positions, nor any intermediate commitment.
//!
//! Because MNT4-298's base field IS MNT6-298's scalar field, every KZG
//! pairing check is native field arithmetic inside the MNT6-298 circuit:
//!
//!   e(com - v*G + z*W, H) = e(W, beta*H)      with z = omega^position
//!
//! per level, where v's scalar bits are *derived in-circuit* from the next
//! commitment's coordinates (the seam map of `mnt_kzg`) — so the chain
//! linkage costs nothing beyond the bit decomposition. Position privacy is
//! kept by witnessing z and enforcing z^{domain_size} = 1 (nonnative).

use std::time::{Duration, Instant};

use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_mnt4_298::constraints::{G1Var, PairingVar};
use ark_mnt4_298::{Fq, Fr as Fr4, G1Projective, MNT4_298};
use ark_mnt6_298::MNT6_298;
use ark_nonnative_field::NonNativeFieldVar;
use ark_poly::EvaluationDomain;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::pairing::PairingVar as PairingVarTrait;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
    SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use linkg16::groth16;
use rand::{rngs::StdRng, SeedableRng};

use ibsl::vc::mnt_kzg::{MntKzgVc, SEAM_X_BITS};
use ibsl::ibsl::{Ibsl, Proof as IbslProof};
use ibsl::vc::VectorCommitment;

type G2Prepared = <MNT4_298 as PairingEngine>::G2Prepared;
type GTVar = <PairingVar as PairingVarTrait<MNT4_298, Fq>>::GTVar;

/// Bits witnessed for the leaf's opened value (the key embedding k+1,
/// which is at most 2^64 + 1).
const LEAF_VALUE_BITS: usize = 65;

/// One level's witness data, extracted from an IBSL `Step`.
#[derive(Clone)]
struct LevelAssignment {
    com: G1Projective,
    w: G1Projective,
    z: Fr4,
}

/// The full circuit. All fields are cloned into both the CRS generation and
/// the proving run (benchmark setting: generating the CRS from an honest
/// instance of the right shape is harmless).
#[derive(Clone)]
pub struct IbslKzgCircuit {
    // Circuit constants (KZG verifier key material).
    g: G1Projective,
    h_prep: G2Prepared,
    beta_h_prep: G2Prepared,
    /// log2 of the KZG evaluation domain size (z^{2^log_domain} = 1).
    log_domain: u32,

    // Public input.
    sigma: ark_mnt4_298::G1Affine,

    // Private witnesses.
    levels: Vec<LevelAssignment>,
    leaf_value: Fr4,
}

impl IbslKzgCircuit {
    /// Builds the circuit from a real IBSL-KZG membership proof.
    pub fn new(vc: &MntKzgVc, sigma: &<MntKzgVc as VectorCommitment>::Commitment, k: u64, pi: &IbslProof<MntKzgVc>) -> Self {
        let levels = pi
            .iter()
            .map(|s| LevelAssignment {
                com: s.commitment.0.into_projective(),
                w: s.witness.w.into_projective(),
                z: vc.domain.element(s.position),
            })
            .collect();
        IbslKzgCircuit {
            g: vc.vk.g.into_projective(),
            h_prep: vc.vk.prepared_h.clone(),
            beta_h_prep: vc.vk.prepared_beta_h.clone(),
            log_domain: vc.domain.size().trailing_zeros(),
            sigma: sigma.0,
            levels,
            leaf_value: Fr4::from(k as u128 + 1),
        }
    }
}

impl ConstraintSynthesizer<Fq> for IbslKzgCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        let l = self.levels.len();
        assert!(l >= 1, "empty chain");

        // Public input: sigma's affine coordinates.
        let sigma_x = FpVar::new_input(cs.clone(), || Ok(self.sigma.x))?;
        let sigma_y = FpVar::new_input(cs.clone(), || Ok(self.sigma.y))?;

        // Constants: G, and the prepared G2 elements H, beta*H.
        let g_const = G1Var::new_constant(cs.clone(), self.g)?;
        let h_prep = <PairingVar as PairingVarTrait<MNT4_298, Fq>>::G2PreparedVar::new_constant(
            cs.clone(),
            self.h_prep.clone(),
        )?;
        let beta_h_prep =
            <PairingVar as PairingVarTrait<MNT4_298, Fq>>::G2PreparedVar::new_constant(
                cs.clone(),
                self.beta_h_prep.clone(),
            )?;
        let gt_one = GTVar::one();

        // com_0, bound to the public sigma.
        let mut com = G1Var::new_witness(cs.clone(), || Ok(self.levels[0].com))?;
        let com0_aff = com.to_affine()?;
        com0_aff.infinity.enforce_equal(&Boolean::FALSE)?;
        com0_aff.x.enforce_equal(&sigma_x)?;
        com0_aff.y.enforce_equal(&sigma_y)?;

        for i in 0..l {
            let lvl = &self.levels[i];

            // The opening proof W_i and evaluation point z_i = omega^pos_i.
            let w = G1Var::new_witness(cs.clone(), || Ok(lvl.w))?;
            let z = NonNativeFieldVar::<Fr4, Fq>::new_witness(cs.clone(), || Ok(lvl.z))?;

            // Domain membership: z^{2^log_domain} = 1 (so z = omega^pos for
            // some pos, keeping the position private but sound).
            let mut zpow = z.clone();
            for _ in 0..self.log_domain {
                zpow = &zpow * &zpow;
            }
            zpow.enforce_equal(&NonNativeFieldVar::one())?;

            // The opened value v_i as scalar bits: the seam map of the next
            // commitment down, or the key embedding at the leaf.
            let (v_bits, next_com): (Vec<Boolean<Fq>>, Option<G1Var>) = if i + 1 < l {
                let child = G1Var::new_witness(cs.clone(), || Ok(self.levels[i + 1].com))?;
                let child_aff = child.to_affine()?;
                child_aff.infinity.enforce_equal(&Boolean::FALSE)?;
                let xbits = child_aff.x.to_bits_le()?;
                let ybits = child_aff.y.to_bits_le()?;
                let mut v = xbits[..SEAM_X_BITS].to_vec();
                v.push(ybits[0].clone());
                (v, Some(child))
            } else {
                let leaf_bits = self.leaf_value.into_repr().to_bits_le();
                let v = (0..LEAF_VALUE_BITS)
                    .map(|j| Boolean::new_witness(cs.clone(), || Ok(leaf_bits[j])))
                    .collect::<Result<Vec<_>, _>>()?;
                (v, None)
            };

            // acc = com - v*G + z*W;  check e(acc, H) * e(-W, beta*H) = 1.
            let vg = g_const.scalar_mul_le(v_bits.iter())?;
            let z_bits = z.to_bits_le()?;
            let zw = w.scalar_mul_le(z_bits.iter())?;
            let acc = com.clone() - vg + zw;
            let neg_w = w.negate()?;

            let acc_prep = PairingVar::prepare_g1(&acc)?;
            let neg_w_prep = PairingVar::prepare_g1(&neg_w)?;
            let gt = PairingVar::product_of_pairings(
                &[acc_prep, neg_w_prep],
                &[h_prep.clone(), beta_h_prep.clone()],
            )?;
            gt.enforce_equal(&gt_one)?;

            if let Some(c) = next_com {
                com = c;
            }
        }
        Ok(())
    }
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

const DEFAULT_SIZES: &[usize] = &[1_000];

pub fn run(sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    println!("== IBSL-KZG membership inside Groth16 (linkg16, MNT4-298 KZG / MNT6-298 Groth16) ==");
    println!("| n | levels | constraints | CRS gen | prove | verify | proof size | native build | native prove | native verify |");
    println!("|---|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let (s, build) = timed(|| Ibsl::<MntKzgVc>::new(&keys, 0xC0FFEE));
        let sigma = s.root_commitment();
        let k = keys[keys.len() / 2];

        let (pi, native_prove) = timed(|| s.prove(k).expect("member proof"));
        let (ok, native_verify) = timed(|| Ibsl::verify(s.vc(), &sigma, k, &pi));
        assert!(ok, "native MNT-KZG verification failed");
        let levels = pi.len();

        let circuit = IbslKzgCircuit::new(s.vc(), &sigma, k, &pi);

        // Constraint count + satisfiability sanity check.
        let cs = ConstraintSystem::<Fq>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        circuit
            .clone()
            .generate_constraints(cs.clone())
            .expect("synthesis");
        assert_eq!(
            cs.is_satisfied(),
            Ok(true),
            "IBSL-KZG circuit unsatisfied on honest witness"
        );
        let num_constraints = cs.num_constraints();
        drop(cs);

        // Groth16 over MNT6-298 via linkg16.
        let (pk, crs_gen) =
            timed(|| groth16::generate_random_parameters::<MNT6_298, _, _>(circuit.clone(), &mut rng).expect("CRS gen"));
        let vk = pk.verifying_key();

        let (proof, prove) =
            timed(|| groth16::create_random_proof(circuit.clone(), &pk, &mut rng).expect("prove"));

        let mut proof_bytes = Vec::new();
        proof.serialize(&mut proof_bytes).expect("serialize proof");

        let inputs = [circuit.sigma.x, circuit.sigma.y];
        const VERIFY_ITERS: u32 = 20;
        let (ok, verify_total) = timed(|| {
            (0..VERIFY_ITERS).all(|_| groth16::verify_proof(&vk, &proof, &inputs).unwrap())
        });
        assert!(ok, "Groth16 verification of IBSL-KZG chain failed");
        let verify = verify_total / VERIFY_ITERS;

        // Sanity: wrong sigma must not verify.
        let bad = [inputs[1], inputs[0]];
        assert!(
            !groth16::verify_proof(&vk, &proof, &bad).unwrap_or(false),
            "proof verified against a wrong sigma"
        );

        println!(
            "| {n} | {levels} | {num_constraints} | {crs_gen:.2?} | {prove:.2?} | {verify:.2?} | {} B | {build:.2?} | {native_prove:.2?} | {native_verify:.2?} |",
            proof_bytes.len()
        );
    }
}

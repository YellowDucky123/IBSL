//! IBSL vector-commitment backend: KZG10 over MNT4-298 (ark 0.3 stack).
//!
//! A port of IBSL's `vc::kzg` (BLS12-381, ark 0.6) onto the MNT4-298 curve,
//! whose base field equals MNT6-298's scalar field — so KZG opening checks
//! (pairing equations on MNT4-298) can be verified *inside* a Groth16
//! circuit over MNT6-298 with native field arithmetic (see `kzg_groth16`).
//!
//! Differences from the BLS backend, both forced by the in-circuit use:
//!   - `open` is hand-rolled (synthetic division by X - z, then a plain
//!     commit of the quotient) because ark-poly-commit 0.3 keeps
//!     `KZG10::open` crate-private. The produced proof is identical.
//!   - `to_field` (the seam map child-commitment -> parent-vector slot) is
//!     not a byte hash: it packs the low 249 bits of the affine
//!     x-coordinate plus the y-parity bit into an MNT4-298 Fr element. The
//!     circuit recomputes exactly this from the child point's coordinate
//!     bits. (A production system would use an algebraic hash here, e.g.
//!     Poseidon over MNT6 Fr — a few hundred extra constraints per level.)

use std::borrow::Cow;

// This backend lives on the ark 0.3 stack (the rest of the crate is ark 0.6),
// because the MNT4-298/MNT6-298 cycle and the r1cs gadgets the Groth16 harness
// verifies it with are only available there. The 0.3 crates are pulled in under
// `-v03` aliases so both major versions can coexist in one dependency graph.
use ark_ff_v03::{BigInteger, PrimeField, Zero};
use ark_mnt4_298::{Fr, G1Affine, MNT4_298};
use ark_poly_commit_v03::kzg10::{Commitment, Powers, Proof, VerifierKey, KZG10};
use ark_poly_commit_v03::PCCommitment;
use ark_poly_v03::{
    univariate::DensePolynomial, EvaluationDomain, Radix2EvaluationDomain, UVPolynomial,
};
use ark_serialize_v03::CanonicalSerialize;
use ark_std_v03::rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest as _, Sha256};

use crate::field::NodeDigest;
use crate::vc::VectorCommitment;

/// Newtype over MNT4-298 Fr so IBSL's foreign `NodeDigest` trait can be
/// implemented here (orphan rule).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct F4(pub Fr);

impl NodeDigest for F4 {
    fn from_u128(v: u128) -> Self {
        F4(Fr::from(v))
    }
    fn zero() -> Self {
        F4(Fr::zero())
    }
}

/// Number of x-coordinate bits packed into the seam value; +1 y-parity bit
/// gives 250 bits, comfortably below both r (298 bits) and q.
pub const SEAM_X_BITS: usize = 249;

pub type UniPoly = DensePolynomial<Fr>;
type Scheme = KZG10<MNT4_298, UniPoly>;

pub struct MntKzgVc {
    pub domain: Radix2EvaluationDomain<Fr>,
    pub powers: Powers<'static, MNT4_298>,
    pub vk: VerifierKey<MNT4_298>,
}

/// The seam map on a native G1 point: low `SEAM_X_BITS` bits of x, then the
/// y-parity bit. The identity (empty commitment placeholder) maps to 0.
pub fn seam_to_field(p: &G1Affine) -> Fr {
    if p.infinity {
        return Fr::zero();
    }
    let xbits = p.x.into_repr().to_bits_le();
    let ybit = p.y.into_repr().to_bits_le()[0];
    let mut bits: Vec<bool> = xbits[..SEAM_X_BITS].to_vec();
    bits.push(ybit);
    Fr::from_repr(<Fr as PrimeField>::BigInt::from_bits_le(&bits)).expect("250 bits < r")
}

impl MntKzgVc {
    fn interpolate(&self, values: &[F4]) -> UniPoly {
        assert!(values.len() <= self.domain.size());
        let mut evals: Vec<Fr> = values.iter().map(|v| v.0).collect();
        evals.resize(self.domain.size(), Fr::zero());
        UniPoly::from_coefficients_vec(self.domain.ifft(&evals))
    }
}

impl VectorCommitment for MntKzgVc {
    type DigestType = F4;
    type Commitment = Commitment<MNT4_298>;
    type Witness = Proof<MNT4_298>;
    type Opener = UniPoly;

    /// Demo only: tau is derived from a public seed, so the setup is
    /// INSECURE — same stance as IBSL's BLS12-381 KZG backend.
    fn setup(width: usize) -> Self {
        let size = width.next_power_of_two();
        let seed32: [u8; 32] = Sha256::digest(b"IBSL demo trusted setup (MNT4-298)").into();
        let mut rng = StdRng::from_seed(seed32);
        let pp = Scheme::setup(size, false, &mut rng).expect("KZG10 setup");

        let powers_of_g = pp.powers_of_g[..size].to_vec();
        let powers_of_gamma_g = (0..size).map(|i| pp.powers_of_gamma_g[&i]).collect();
        let powers = Powers {
            powers_of_g: Cow::Owned(powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };

        MntKzgVc {
            domain: Radix2EvaluationDomain::new(size).expect("radix-2 domain"),
            powers,
            vk,
        }
    }

    fn empty_commitment() -> Self::Commitment {
        Self::Commitment::empty()
    }

    fn commit(&self, values: &[F4]) -> (Self::Commitment, Self::Opener) {
        let p = self.interpolate(values);
        let c = Scheme::commit(&self.powers, &p, None, None).expect("commit").0;
        (c, p)
    }

    /// Standard KZG opening at z = w^i: commit to the quotient
    /// q(X) = (p(X) - p(z)) / (X - z), computed by synthetic division.
    fn open(&self, p: &Self::Opener, i: usize) -> Self::Witness {
        let z = self.domain.element(i);
        let coeffs = p.coeffs();
        // Synthetic division of p by (X - z): q_{j-1} = p_j + z * q_j,
        // scanning from the top coefficient down. The remainder p(z) is
        // discarded (the opened value is supplied at check time).
        let mut q = vec![Fr::zero(); coeffs.len().saturating_sub(1)];
        let mut carry = Fr::zero();
        for j in (1..coeffs.len()).rev() {
            carry = coeffs[j] + z * carry;
            q[j - 1] = carry;
        }
        let quotient = UniPoly::from_coefficients_vec(q);
        let w = Scheme::commit(&self.powers, &quotient, None, None)
            .expect("commit quotient")
            .0;
        Proof {
            w: w.0,
            random_v: None,
        }
    }

    fn check(&self, c: &Self::Commitment, i: usize, value: F4, w: &Self::Witness) -> bool {
        if i >= self.domain.size() {
            return false;
        }
        Scheme::check(&self.vk, c, self.domain.element(i), value.0, w).unwrap_or(false)
    }

    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8> {
        let mut bytes = Vec::new();
        c.serialize(&mut bytes).expect("serialization");
        bytes
    }

    /// Canonical (ark 0.3) serialized size of the KZG proof.
    fn witness_size(w: &Self::Witness) -> usize {
        w.serialized_size()
    }

    fn to_field(c: &Self::Commitment) -> F4 {
        F4(seam_to_field(&c.0))
    }
}

/// Sanity check used by the harness: pairing check the seam and openings on
/// a tiny instance before the Groth16 side runs.
#[allow(dead_code)]
pub fn self_test() {
    use crate::ibsl::Ibsl;
    let keys: Vec<u64> = (1..=20).map(|i| i * 10).collect();
    let s = Ibsl::<MntKzgVc>::new(&keys, 0xC0FFEE);
    let sigma = s.root_commitment();
    let pi = s.prove(70).expect("70 is a member");
    assert!(Ibsl::verify(s.vc(), &sigma, 70, &pi), "native MNT-KZG verify failed");
    assert!(s.prove(75).is_none());
}

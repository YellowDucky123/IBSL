//! Vector commitment on the univariate Ligero PCS from `ark-poly-commit`
//! (`linear_codes::LinearCodePCS` + `UnivariateLigero`) — like kzg.rs, this
//! module contributes no polynomial-commitment cryptography of its own, only
//! the glue to use that crate as a vector commitment.
//!
//! Same vector encoding as KZG: (m_0, ..., m_{d-1}) is interpolated into the
//! polynomial p with p(w^i) = m_i over the radix-2 domain of size
//! `width.next_power_of_two()`, and "opening slot i" is a Ligero evaluation
//! proof at w^i. Unlike KZG, Ligero is hash-based and TRANSPARENT: the
//! coefficient matrix is Reed-Solomon-encoded row-wise and committed by a
//! SHA-256 Merkle tree over its columns, and an opening spot-checks columns
//! against a Fiat-Shamir challenge (a Poseidon sponge here, fresh and
//! deterministic on both sides). No trusted setup, no pairings; proofs are
//! bigger than KZG's single group element.

use crate::vc::VectorCommitment;
use ark_bls12_381::Fr;
use ark_crypto_primitives::crh::sha256::Sha256 as ArkSha256;
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree::{ByteDigestConverter, Config};
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain,
};
use ark_poly_commit::linear_codes::{LigeroPCParams, LinearCodePCS, UnivariateLigero};
use ark_poly_commit::{LabeledCommitment, LabeledPolynomial, PolynomialCommitment};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest as _, Sha256};
use std::borrow::Borrow;

const LABEL: &str = "ibsl";

// --------------------------------------------------------------- column tree
// In-crate equivalents of ark-pcs-bench-templates' helper hashers: a column
// of the encoded matrix is hashed to bytes (SHA-256 of its canonical
// serialization), those hashes are the Merkle leaves as-is, and inner nodes
// compress with SHA-256.

/// SHA-256 of a column's serialized field elements.
pub struct FieldColHasher;

impl CRHScheme for FieldColHasher {
    type Input = Vec<Fr>;
    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: ark_std::rand::Rng>(_: &mut R) -> Result<(), ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Vec<Fr>>>(
        _: &(),
        input: T,
    ) -> Result<Vec<u8>, ark_crypto_primitives::Error> {
        let mut bytes = Vec::new();
        input.borrow().serialize_compressed(&mut bytes)?;
        Ok(Sha256::digest(&bytes).to_vec())
    }
}

/// Column hashes go into the tree unchanged.
pub struct IdentityLeafHash;

impl CRHScheme for IdentityLeafHash {
    type Input = Vec<u8>;
    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: ark_std::rand::Rng>(_: &mut R) -> Result<(), ark_crypto_primitives::Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Vec<u8>>>(
        _: &(),
        input: T,
    ) -> Result<Vec<u8>, ark_crypto_primitives::Error> {
        Ok(input.borrow().clone())
    }
}

pub struct ColumnTree;

impl Config for ColumnTree {
    type Leaf = Vec<u8>;
    type LeafDigest = Vec<u8>;
    type LeafInnerDigestConverter = ByteDigestConverter<Vec<u8>>;
    type InnerDigest = Vec<u8>;
    type LeafHash = IdentityLeafHash;
    type TwoToOneHash = ArkSha256;
}

// ------------------------------------------------------------------- the VC

type UniPoly = DensePolynomial<Fr>;
type Scheme = LinearCodePCS<
    UnivariateLigero<Fr, ColumnTree, UniPoly, FieldColHasher>,
    Fr,
    UniPoly,
    ColumnTree,
    FieldColHasher,
>;
type CommitterKey = <Scheme as PolynomialCommitment<Fr, UniPoly>>::CommitterKey;
type VerifierKey = <Scheme as PolynomialCommitment<Fr, UniPoly>>::VerifierKey;

pub struct LigeroVc {
    domain: Radix2EvaluationDomain<Fr>,
    ck: CommitterKey,
    vk: VerifierKey,
}

/// Prover-side state from the one `Scheme::commit`: the labeled polynomial
/// and the column-tree commitment/state, so `open` never re-commits.
pub struct LigeroOpener {
    poly: LabeledPolynomial<Fr, UniPoly>,
    comms: Vec<LabeledCommitment<<Scheme as PolynomialCommitment<Fr, UniPoly>>::Commitment>>,
    states: Vec<<Scheme as PolynomialCommitment<Fr, UniPoly>>::CommitmentState>,
}

impl LigeroVc {
    fn interpolate(&self, values: &[Fr]) -> UniPoly {
        assert!(values.len() <= self.domain.size());
        let mut evals = values.to_vec();
        // Pad with ONE, not zero: an all-zero vector (the -inf sentinel leaf
        // commits to [0]) would interpolate to the zero polynomial, whose
        // empty coefficient list panics Ligero's matrix layout. Padding
        // slots are never opened, so the opening relation for real slots is
        // unchanged. (A full-width all-zero vector would still be the zero
        // polynomial, but upper vectors hold digests-as-field-elements and
        // leaf vectors have length 1 — never full-width zeros.)
        evals.resize(self.domain.size(), Fr::from(1u64));
        UniPoly::from_coefficients_vec(self.domain.ifft(&evals))
    }

    fn labeled(&self, values: &[Fr]) -> LabeledPolynomial<Fr, UniPoly> {
        LabeledPolynomial::new(LABEL.to_string(), self.interpolate(values), None, None)
    }

    /// Fresh deterministic Fiat-Shamir sponge; prover and verifier must
    /// derive challenges from identical transcripts, so both sides start
    /// from the same state.
    fn sponge() -> PoseidonSponge<Fr> {
        PoseidonSponge::new(crate::hashes::poseidon::poseidon_config())
    }
}

impl VectorCommitment for LigeroVc {
    type Field = Fr;
    type Commitment =
        <Scheme as PolynomialCommitment<Fr, UniPoly>>::Commitment;
    type Witness = <Scheme as PolynomialCommitment<Fr, UniPoly>>::Proof;
    type Opener = LigeroOpener;

    /// Transparent: the "setup" is just parameter selection (128-bit
    /// security target, rate 1/4, well-formedness check on), no secrets.
    fn setup(width: usize) -> Self {
        let size = width.next_power_of_two();
        let mut rng = StdRng::from_seed(Sha256::digest(b"IBSL ligero params").into());
        let leaf = <IdentityLeafHash as CRHScheme>::setup(&mut rng).expect("leaf params");
        let two_to_one =
            <ArkSha256 as TwoToOneCRHScheme>::setup(&mut rng).expect("node params");
        let col = <FieldColHasher as CRHScheme>::setup(&mut rng).expect("col params");
        let pp: LigeroPCParams<Fr, ColumnTree, FieldColHasher> =
            LigeroPCParams::new(128, 4, true, leaf, two_to_one, col);
        let (ck, vk) = Scheme::trim(&pp, 0, 0, None).expect("trim");

        LigeroVc {
            domain: Radix2EvaluationDomain::new(size).expect("radix-2 domain"),
            ck,
            vk,
        }
    }

    fn empty_commitment() -> Self::Commitment {
        Default::default()
    }

    fn commit(&self, values: &[Fr]) -> (Self::Commitment, Self::Opener) {
        let poly = self.labeled(values);
        let (comms, states) =
            Scheme::commit(&self.ck, &[poly.clone()], None).expect("commit");
        let c = comms[0].commitment().clone();
        (c, LigeroOpener { poly, comms, states })
    }

    fn open(&self, o: &Self::Opener, i: usize) -> Self::Witness {
        Scheme::open(
            &self.ck,
            [&o.poly],
            &o.comms,
            &self.domain.element(i),
            &mut Self::sponge(),
            &o.states,
            None,
        )
        .expect("open")
    }

    fn check(&self, c: &Self::Commitment, i: usize, value: Fr, w: &Self::Witness) -> bool {
        if i >= self.domain.size() {
            return false;
        }
        let labeled = LabeledCommitment::new(LABEL.to_string(), c.clone(), None);
        Scheme::check(
            &self.vk,
            &[labeled],
            &self.domain.element(i),
            [value],
            w,
            &mut Self::sponge(),
            None,
        )
        .unwrap_or(false)
    }

    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8> {
        let mut bytes = Vec::new();
        c.serialize_compressed(&mut bytes).expect("serialization");
        bytes
    }

    /// Merkle root + metadata -> Fr via SHA-256 of the canonical bytes.
    fn to_field(c: &Self::Commitment) -> Fr {
        Fr::from_le_bytes_mod_order(&Sha256::digest(Self::commitment_bytes(c)))
    }
}

//! Poseidon tree hash over Fr: leaf = P(0, value), node = P(1, l, r).
//!
//! Digests are field elements, so `digest_to_field` is the identity and the
//! parent-child chain never leaves the field — what a zk circuit wants.

use crate::hashes::Hash;
use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use std::sync::OnceLock;

pub struct PoseidonHash;

/// Standard constraints-optimized parameters for BLS12-381 Fr at rate 3
/// (the `PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0)` entry), derived
/// once with the crate's Grain LFSR. Rate 3 fits a whole node compression
/// (tag, left, right) in a single permutation.
fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (full_rounds, partial_rounds, alpha, rate) = (8, 56, 5, 3);
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );
        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            alpha,
            mds,
            ark,
            rate,
            1,
        )
    })
}

fn poseidon(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

impl Hash for PoseidonHash {
    type Digest = Fr;

    fn empty() -> Self::Digest {
        Fr::zero()
    }

    fn leaf(value: &Fr) -> Self::Digest {
        poseidon(&[Fr::from(0u64), *value])
    }

    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        poseidon(&[Fr::from(1u64), *left, *right])
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        let mut bytes = Vec::new();
        d.serialize_compressed(&mut bytes).expect("serialization");
        bytes
    }

    /// A Poseidon digest already is a field element.
    fn digest_to_field(d: &Self::Digest) -> Fr {
        *d
    }
}

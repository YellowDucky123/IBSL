//! SHA-256 tree hash: leaf = H(0x00 || value), node = H(0x01 || l || r).

use crate::hashes::Hash;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest as _, Sha256};

pub struct Sha256Hash;

impl Hash for Sha256Hash {
    type Field = Fr;
    type Digest = [u8; 32];

    fn empty() -> Self::Digest {
        [0u8; 32]
    }

    fn leaf(value: &Fr) -> Self::Digest {
        let mut bytes = Vec::new();
        value.serialize_compressed(&mut bytes).expect("serialization");
        Sha256::new().chain_update([0x00]).chain_update(&bytes).finalize().into()
    }

    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        Sha256::new()
            .chain_update([0x01])
            .chain_update(left)
            .chain_update(right)
            .finalize()
            .into()
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_vec()
    }

    fn digest_to_field(d: &Self::Digest) -> Fr {
        Fr::from_le_bytes_mod_order(d)
    }
}

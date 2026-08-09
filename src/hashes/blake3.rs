//! BLAKE3 tree hash: leaf = H(0x00 || value), node = H(0x01 || l || r).

use crate::hashes::Hash;
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

pub struct Blake3Hash;

impl Hash for Blake3Hash {
    type Field = Fr;
    type Digest = [u8; 32];

    fn empty() -> Self::Digest {
        [0u8; 32]
    }

    fn leaf(value: &Fr) -> Self::Digest {
        let mut bytes = Vec::new();
        value.serialize_compressed(&mut bytes).expect("serialization");
        ::blake3::Hasher::new().update(&[0x00]).update(&bytes).finalize().into()
    }

    fn node(values: &[Self::Digest]) -> Self::Digest {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(&[0x01]);
        for v in values {
            hasher.update(v);
        }
        hasher.finalize().into()
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_vec()
    }

    /// BLAKE3 paper: default output length is 256 bits.
    fn digest_size() -> usize {
        32
    }

    fn digest_to_field(d: &Self::Digest) -> Fr {
        Fr::from_le_bytes_mod_order(d)
    }
}

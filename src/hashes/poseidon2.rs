//! Poseidon2 over the Mersenne-31 field (width 16), and the flat hash it
//! feeds — the M31 counterpart of `RescueFlatHash`.
//!
//! This exists because the Winterfell STARK (`crate::stark`) and the Stwo
//! STARK (`crate::stark::stwo`) live over different fields: Winterfell's
//! circuit is Rescue over f128, Stwo is a Circle STARK and works over M31
//! (p = 2^31 - 1). To bench the same IBSL construction on Stwo we need an
//! M31-native hash, arithmetised bit-for-bit by the Stwo AIR, exactly as
//! Rescue is by `MerkleAir`.
//!
//! Parameters: width 16, S-box x^5, 8 full rounds (4 + 4) and 14 partial
//! rounds — the shape Stwo's own Poseidon2 example AIR uses, and the usual
//! M31 width-16 instance. The linear layers are the Poseidon2 paper's
//! (<https://eprint.iacr.org/2023/323.pdf> §5.1-5.2): external =
//! circ(2·M4, M4, M4, M4), internal = J + diag(2^{i+1}). `apply_m4`,
//! `apply_external_round_matrix` and `apply_internal_round_matrix` are
//! adapted from Stwo's `examples/src/poseidon` (Apache-2.0) and are generic
//! over the arithmetic type so the native permutation below and the AIR in
//! `crate::stark::stwo` share one definition — the AIR cannot drift from
//! the hash.
//!
//! Round constants are derived from BLAKE3 over a fixed domain string
//! (nothing-up-my-sleeve) rather than taken from a reference implementation;
//! Stwo's own example uses the literal 1234 everywhere with a TODO. Round
//! constants have no effect on proof size or proving cost.
//!
//! Compression is truncation, `merge(l, r) = P(l || r)[0..8]` (Plonky3's
//! `TruncatedPermutation`), and a digest is 8 M31 elements — 32 bytes
//! encoded, matching Rescue-128's 2 f128 elements, so the two STARKs'
//! commitment sizes compare directly.
//!
//! Same domain-separation caveat as `RescueFlatHash`: there are no leaf/node
//! tags, and `node([s]) == node([s, ZERO])`. Demo-grade, don't ship.

use std::ops::{Add, AddAssign, Mul, Sub};
use std::sync::LazyLock;

use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::{BaseField, M31, P};

use crate::field::NodeDigest;
use crate::hashes::Hash;

/// Permutation state width.
pub const WIDTH: usize = 16;
/// Digest width: the permutation output is truncated to this many elements.
pub const DIGEST_WIDTH: usize = 8;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const N_FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
pub const N_PARTIAL_ROUNDS: usize = 14;

/// Width of the Stwo AIR's per-permutation column block. Stated here because
/// the trace layout is defined by the permutation, not by the AIR.
///
/// The x^5 S-box cannot be constrained in one shot: Stwo's lifted protocol
/// caps constraint degree at 3 (its own Poseidon2 example is `#[ignore]`d
/// for exactly this — "AIRs with constraint degree >= 2 are not supported
/// yet in the lifted protocol"). So each S-box commits an auxiliary x^2
/// alongside its output, and x^5 is written as `aux * aux * x` — degree 3.
/// That costs one extra column per S-box: 16 per full round, 1 per partial
/// round.
pub const N_COLUMNS_PER_PERM: usize =
    WIDTH + N_FULL_ROUNDS * 2 * WIDTH + N_PARTIAL_ROUNDS * 2;

// ROUND CONSTANTS
// ================================================================================================

pub struct RoundConstants {
    pub external: [[BaseField; WIDTH]; N_FULL_ROUNDS],
    pub internal: [BaseField; N_PARTIAL_ROUNDS],
}

/// BLAKE3-XOF-derived constants over a fixed domain string. Rejection-samples
/// the single invalid 31-bit word (p itself) so every constant is a canonical
/// M31 element.
static ROUND_CONSTANTS: LazyLock<RoundConstants> = LazyLock::new(|| {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"IBSL/Poseidon2-M31/w16/d5/rf8/rp14/v1");
    let mut xof = hasher.finalize_xof();

    let mut next = || loop {
        let mut word = [0u8; 4];
        xof.fill(&mut word);
        let v = u32::from_le_bytes(word) & 0x7fff_ffff;
        if v != P {
            return BaseField::from_u32_unchecked(v);
        }
    };

    RoundConstants {
        external: std::array::from_fn(|_| std::array::from_fn(|_| next())),
        internal: std::array::from_fn(|_| next()),
    }
});

pub fn round_constants() -> &'static RoundConstants {
    &ROUND_CONSTANTS
}

// LINEAR LAYERS AND S-BOX (shared with the AIR)
// ================================================================================================

/// The M4 MDS matrix of <https://eprint.iacr.org/2023/323.pdf> §5.1.
#[inline(always)]
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

/// The external round matrix circ(2·M4, M4, M4, M4) (§5.1, Appendix B).
pub fn apply_external_round_matrix<F>(state: &mut [F; WIDTH])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F>,
{
    for i in 0..4 {
        [state[4 * i], state[4 * i + 1], state[4 * i + 2], state[4 * i + 3]] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s = state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

/// The internal round matrix J + diag(mu_i), mu_i = 2^{i+1} (§5.2).
pub fn apply_internal_round_matrix<F>(state: &mut [F; WIDTH])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let sum = state[1..].iter().cloned().fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * BaseField::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

pub fn pow5<F: FieldExpOps>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}

// NATIVE PERMUTATION
// ================================================================================================

/// The Poseidon2 permutation, in the exact order the Stwo AIR constrains it:
/// initial external matrix, 4 full rounds, 14 partial rounds, 4 full rounds;
/// a full round is `M_E(pow5(state + RC))`, a partial round is
/// `M_I(state with lane 0 replaced by pow5(state[0] + rc))`.
pub fn permute(state: &mut [BaseField; WIDTH]) {
    let rc = round_constants();

    apply_external_round_matrix(state);

    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(state, &rc.external[round]);
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] = pow5(state[0] + rc.internal[round]);
        apply_internal_round_matrix(state);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(state, &rc.external[round + N_HALF_FULL_ROUNDS]);
    }
}

fn full_round(state: &mut [BaseField; WIDTH], rc: &[BaseField; WIDTH]) {
    for i in 0..WIDTH {
        state[i] = pow5(state[i] + rc[i]);
    }
    apply_external_round_matrix(state);
}

// DIGEST
// ================================================================================================

/// An 8-element M31 digest (~248 bits, 32 bytes encoded).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Digest(pub [BaseField; DIGEST_WIDTH]);

impl Digest {
    pub const ZERO: Digest = Digest([M31::from_u32_unchecked(0); DIGEST_WIDTH]);

    pub fn to_bytes(self) -> [u8; 4 * DIGEST_WIDTH] {
        let mut out = [0u8; 4 * DIGEST_WIDTH];
        for (chunk, e) in out.chunks_exact_mut(4).zip(self.0) {
            chunk.copy_from_slice(&e.0.to_le_bytes());
        }
        out
    }
}

/// 2-to-1 compression: permute the concatenation and truncate to the first
/// `DIGEST_WIDTH` lanes (Plonky3's `TruncatedPermutation`).
pub fn merge(left: Digest, right: Digest) -> Digest {
    let mut state = [BaseField::from_u32_unchecked(0); WIDTH];
    state[..DIGEST_WIDTH].copy_from_slice(&left.0);
    state[DIGEST_WIDTH..].copy_from_slice(&right.0);
    permute(&mut state);
    Digest(state[..DIGEST_WIDTH].try_into().unwrap())
}

/// Keys embed as 30-bit little-endian limbs, three of them — injective for
/// anything up to 2^90, well past `Key::field`'s 2^64 + 1, and every limb is
/// below p so no two keys share a digest.
impl NodeDigest for Digest {
    fn from_u128(v: u128) -> Self {
        let mut d = [BaseField::from_u32_unchecked(0); DIGEST_WIDTH];
        for (i, lane) in d.iter_mut().enumerate().take(3) {
            *lane = BaseField::from_u32_unchecked(((v >> (30 * i)) & 0x3fff_ffff) as u32);
        }
        assert_eq!(v >> 90, 0, "key too large for a 3-limb M31 embedding");
        Digest(d)
    }

    fn zero() -> Self {
        Digest::ZERO
    }
}

// FLAT HASH
// ================================================================================================

/// Chain ("caterpillar") Poseidon2 hash for the flat-hash VC — the same fold
/// as `RescueFlatHash`, over M31: a node's commitment is the LEFT-FOLD of
/// 2-to-1 merges over its slots, with the 1-slot case `com([s]) =
/// merge(s, ZERO)`. Slots hold full digests (`FlatHashVc::to_field` is the
/// identity), so an IBSL chain over this hash is one seamless run of merges —
/// exactly what `crate::stark::stwo` re-verifies.
pub struct Poseidon2FlatHash;

impl Hash for Poseidon2FlatHash {
    type Field = Digest;
    type Digest = Digest;

    fn empty() -> Self::Digest {
        Digest::ZERO
    }

    /// Unused by `FlatHashVc` (keys embed via `NodeDigest::from_u128` on the
    /// digest type); present to satisfy the trait.
    fn leaf(value: &Digest) -> Self::Digest {
        merge(*value, Digest::ZERO)
    }

    fn node(values: &[Self::Digest]) -> Self::Digest {
        match values {
            [] => Self::empty(),
            [s] => merge(*s, Digest::ZERO),
            [first, rest @ ..] => rest.iter().fold(*first, |acc, s| merge(acc, *s)),
        }
    }

    fn digest_bytes(d: &Self::Digest) -> Vec<u8> {
        d.to_bytes().to_vec()
    }

    /// 8 M31 elements, encoded as 8 words = 32 bytes.
    fn digest_size() -> usize {
        4 * DIGEST_WIDTH
    }

    /// Unused by `FlatHashVc` (`to_field` is the identity on digests);
    /// present to satisfy the trait.
    fn digest_to_field(d: &Self::Digest) -> Digest {
        *d
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The permutation must actually mix: no lane survives unchanged, and
    /// flipping one input lane changes every output lane.
    #[test]
    fn permutation_diffuses() {
        let mut a = std::array::from_fn(|i| BaseField::from_u32_unchecked(i as u32));
        let mut b = a;
        b[3] = b[3] + BaseField::from_u32_unchecked(1);
        permute(&mut a);
        permute(&mut b);
        assert!(a.iter().zip(b).all(|(x, y)| *x != y), "avalanche failed");
    }

    #[test]
    fn merge_is_order_sensitive() {
        let l = Digest::from_u128(7);
        let r = Digest::from_u128(9);
        assert_ne!(merge(l, r), merge(r, l));
    }

    #[test]
    fn key_embedding_is_injective() {
        let a = Digest::from_u128(u64::MAX as u128);
        let b = Digest::from_u128(u64::MAX as u128 - 1);
        assert_ne!(a, b);
        assert_ne!(Digest::from_u128(0), Digest::from_u128(1));
    }

    /// The fold is what `Hash::node` promises, and the 1-slot case is the
    /// zero-padded merge the STARK's first row reproduces.
    #[test]
    fn fold_matches_manual_chain() {
        let s: Vec<Digest> = (1..=4).map(|i| Digest::from_u128(i)).collect();
        let expect = merge(merge(merge(s[0], s[1]), s[2]), s[3]);
        assert_eq!(Poseidon2FlatHash::node(&s), expect);
        assert_eq!(Poseidon2FlatHash::node(&s[..1]), merge(s[0], Digest::ZERO));
    }
}

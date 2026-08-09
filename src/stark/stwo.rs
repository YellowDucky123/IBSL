//! Bridge: a real IBSL *flat-hash* proof -> a Stwo Circle STARK.
//!
//! The M31 counterpart of `stark::flat`. Same construction, same chain, a
//! different prover: where `flat` folds Rescue merges over Winterfell's f128
//! into `MerkleAir`, this folds Poseidon2 merges over Mersenne-31
//! (`crate::hashes::poseidon2`) into a Stwo `FrameworkEval` component, so the
//! two STARK backends can be compared on the same statement.
//!
//! # Trace
//!
//! One row per 2-to-1 merge, `N_COLUMNS_PER_PERM = 300` columns holding the
//! Poseidon2 witness (input state, then per round an x^2 S-box auxiliary and
//! the round output) plus one column for the position bit — 301 in all. The output digest of a row is the first 8 lanes
//! of its final state, columns `OUT_COL .. OUT_COL + 8`.
//!
//! Row 0 is the leaf node's own 1-slot commitment, `merge(key, ZERO)`; its
//! input is deliberately unconstrained (that is where the secret key enters,
//! exactly as the leaf-hash cycle does in the Winterfell circuit). Every
//! later row is chained to its predecessor by
//!
//! ```text
//! (1 - is_first) * (1 - bit) * (in[i]     - prev_out[i]) = 0
//! (1 - is_first) *      bit  * (in[8 + i] - prev_out[i]) = 0
//! ```
//!
//! i.e. bit 0 puts the accumulator on the left of the merge, bit 1 on the
//! right — the flat-hash fold of `stark::flat`, including its prefix
//! compression for an opened slot i > 0. `prev_out` is a mask at row offset
//! -1; the wrap-around at row 0 is killed by `is_first`, so no cyclic
//! constraint is imposed.
//!
//! Rows past the end of the chain are padding: they keep folding with a ZERO
//! sibling, which satisfies every constraint, and the real end of the chain
//! is pinned by a second selector: `is_last * (out[i] - sigma[i]) = 0`.
//!
//! # What the verifier learns
//!
//! sigma, the number of merges, and nothing else — not the key, not the
//! commitments along the chain. Same public statement as `stark::flat`
//! (which publishes sigma and the cycle count).
//!
//! # Hashes
//!
//! Two hashes are in play and they are not the same thing. The *in-circuit*
//! hash — the one the IBSL chain is built from and the AIR arithmetises — is
//! Poseidon2 over M31. The STARK's *own* commitment hash, for the FRI/Merkle
//! trees and the Fiat-Shamir channel, is Poseidon252 (Stwo's algebraic
//! option, over the Starknet field) rather than Blake2s: an algebraic
//! commitment hash is what makes the proof cheap to verify inside another
//! proof. It costs proving time — Poseidon252 is far slower in software than
//! Blake2s — and nothing in proof size, since both digests are 32 bytes.
//!
//! The Winterfell side of the comparison stays on BLAKE3: winterfell 0.13
//! ships only Blake3/SHA3 and Rescue-Prime, and its Rescue-Prime hashers
//! (`Rp64_256`, `RpJive64_256`) are Goldilocks-only, so there is no algebraic
//! hasher for the f128 field that circuit runs over.
//!
//! # Preprocessed columns
//!
//! `is_first` and `is_last` are preprocessed (verifier-known) columns, fully
//! determined by the pair (log_n_rows, n_merges). Stwo's own examples commit
//! the preprocessed tree and never check its contents, which would let a
//! prover move `is_last`; `verify` below closes that by regenerating both
//! columns from the public parameters and checking the recomputed root
//! against `proof.commitments[0]`.

use std::ops::AddAssign;

use itertools::Itertools;
use num_traits::{One, Zero};
use stwo::core::ColumnVec;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::poseidon252_merkle::{Poseidon252MerkleChannel, Poseidon252MerkleHasher};
use stwo::core::verifier::VerificationError;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentSchemeProver, prove as stwo_prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
};
use stwo::core::air::Component;

use crate::hashes::poseidon2::{
    DIGEST_WIDTH, Digest, N_COLUMNS_PER_PERM, N_FULL_ROUNDS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS,
    WIDTH,
    apply_external_round_matrix, apply_internal_round_matrix, merge, round_constants,
};
use crate::ibsl::{Key, Step};
use crate::vc::Poseidon2FlatHashVc;

/// Column holding the position bit, right after the Poseidon2 block.
pub const BIT_COL: usize = N_COLUMNS_PER_PERM;
pub const N_TRACE_COLUMNS: usize = N_COLUMNS_PER_PERM + 1;
/// First column of the permutation's final state; the output digest is
/// `OUT_COL .. OUT_COL + DIGEST_WIDTH`.
pub const OUT_COL: usize = N_COLUMNS_PER_PERM - WIDTH;
/// Stwo's lifted protocol only accepts `log_size + 1` here; every constraint
/// below is degree 3 or less to fit (see `poseidon2::N_COLUMNS_PER_PERM`).
const LOG_EXPAND: u32 = 1;

/// Blowup 8 and a FRI remainder capped at degree 31, matching
/// `stark::membership::default_options`; queries and grinding are the dials.
///
/// Conjectured security is `n_queries * 3 + pow_bits` bits. Grinding buys
/// security for prover time rather than proof bytes — the nonce is 8 bytes —
/// so it is the cheap way to trade a few queries away, and each query
/// dropped saves `n_columns * 4` bytes of queried trace values.
pub fn config(n_queries: usize, pow_bits: u32) -> PcsConfig {
    PcsConfig {
        pow_bits,
        fri_config: FriConfig::new(5, 3, n_queries, 1),
        lifting_log_size: None,
    }
}

/// 28 queries, no grinding — parity with `stark::membership::default_options`
/// (~84-bit conjectured), so the two STARKs' sizes are quoted alike.
pub fn default_config() -> PcsConfig {
    config(28, 0)
}

/// FRI's first circle-to-line fold halves the domain, so a last layer wider
/// than that cannot be reached. These traces are short, so the cap usually
/// bites; where it does not, the configured bound stands.
fn clamped(config: PcsConfig, log_n_rows: u32) -> PcsConfig {
    let fri = config.fri_config;
    PcsConfig {
        fri_config: FriConfig::new(
            fri.log_last_layer_degree_bound.min(log_n_rows.saturating_sub(1)),
            fri.log_blowup_factor,
            fri.n_queries,
            fri.fold_step,
        ),
        ..config
    }
}

// CHAIN
// ================================================================================================

/// One merge of the chain: fold `sibling` into the accumulator, on the right
/// when `bit` is false and on the left when it is true.
#[derive(Clone, Copy, Debug)]
pub struct Merge {
    pub sibling: Digest,
    pub bit: bool,
}

/// The whole membership chain, flattened: a secret seed (the embedded key)
/// and the merges that carry it to sigma.
#[derive(Clone, Debug)]
pub struct Chain {
    pub seed: Digest,
    pub merges: Vec<Merge>,
}

impl Chain {
    /// The digest each merge produces, `acc[j]` being the output of row `j`.
    fn accumulators(&self) -> Vec<Digest> {
        let mut acc = self.seed;
        self.merges
            .iter()
            .map(|m| {
                acc = if m.bit { merge(m.sibling, acc) } else { merge(acc, m.sibling) };
                acc
            })
            .collect()
    }

    pub fn root(&self) -> Digest {
        *self.accumulators().last().unwrap()
    }
}

/// Flattens a real IBSL proof into the merge chain, exactly as
/// `stark::flat::prove` does for the Rescue circuit: the leaf node's own
/// 1-slot commitment `merge(key, ZERO)` is row 0, then each level contributes
/// its sibling slots, with the slots before an opened slot i > 0 folded
/// natively into one prefix digest that enters on the left (bit 1).
///
/// Compressing that prefix is sound for membership: a prefix preimage that
/// reaches sigma along a different chain is a Poseidon2 collision — the same
/// argument that lets Merkle sibling data be trusted.
pub fn compile(k: u64, pi: &[Step<Poseidon2FlatHashVc>]) -> Chain {
    assert!(!pi.is_empty(), "empty IBSL proof");

    // pi is top-down (sigma first, leaf last); the chain folds bottom-up.
    let leaf = pi.last().unwrap();
    assert!(
        leaf.witness.siblings().is_empty() && leaf.position == 0,
        "leaf step must open slot 0 of a 1-slot vector"
    );

    // Row 0 IS the leaf node's commitment: merge(key, ZERO).
    let mut merges = vec![Merge { sibling: Digest::ZERO, bit: false }];

    for step in pi.iter().rev().skip(1) {
        let slots = step.witness.siblings();
        let i = step.position;
        assert!(i <= slots.len(), "opened slot outside the committed vector");
        if slots.is_empty() {
            // w = 1: com = merge(child, ZERO).
            merges.push(Merge { sibling: Digest::ZERO, bit: false });
        } else if i == 0 {
            // Child digest seeds the fold; absorb every later slot.
            merges.extend(slots.iter().map(|s| Merge { sibling: *s, bit: false }));
        } else {
            let prefix = slots[1..i].iter().fold(slots[0], |acc, s| merge(acc, *s));
            merges.push(Merge { sibling: prefix, bit: true });
            merges.extend(slots[i..].iter().map(|s| Merge { sibling: *s, bit: false }));
        }
    }

    Chain { seed: Key::Val(k).field(), merges }
}

// PREPROCESSED COLUMNS
// ================================================================================================

fn selector_id(name: &str, log_size: u32, row: usize) -> PreProcessedColumnId {
    PreProcessedColumnId { id: format!("ibsl_stwo_{name}_{log_size}_{row}") }
}

fn is_first_id(log_size: u32) -> PreProcessedColumnId {
    selector_id("is_first", log_size, 0)
}

fn is_last_id(log_size: u32, last_row: usize) -> PreProcessedColumnId {
    selector_id("is_last", log_size, last_row)
}

/// A column that is 1 at one logical row and 0 everywhere else.
fn indicator_column(
    log_size: u32,
    row: usize,
) -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
    let mut col = Col::<SimdBackend, BaseField>::zeros(1 << log_size);
    col.set(storage_index(row, log_size), BaseField::one());
    CircleEvaluation::new(CanonicCoset::new(log_size).circle_domain(), col)
}

/// Where logical row `row` is stored: trace columns live in bit-reversed
/// circle-domain order.
fn storage_index(row: usize, log_size: u32) -> usize {
    bit_reverse_index(coset_index_to_circle_domain_index(row, log_size), log_size)
}

fn preprocessed_trace(
    log_size: u32,
    last_row: usize,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    vec![indicator_column(log_size, 0), indicator_column(log_size, last_row)]
}

// AIR
// ================================================================================================

pub type ChainComponent = FrameworkComponent<ChainEval>;

/// `x + c`. `EvalAtRow::F` offers `AddAssign<BaseField>` but no `Add`.
fn add_const<F: AddAssign<BaseField>>(mut x: F, c: BaseField) -> F {
    x += c;
    x
}

/// The x^5 S-box, split to stay within Stwo's degree-3 ceiling: commit
/// `aux = x^2`, then x^5 is `aux * aux * x`, degree 3 in committed values.
fn sbox<E: EvalAtRow>(eval: &mut E, x: E::F) -> E::F {
    let aux = eval.next_trace_mask();
    eval.add_constraint(aux.clone() - x.clone() * x.clone());
    aux.clone() * aux * x
}

/// Pins a computed value to a fresh trace column, so the next round starts
/// from degree 1 again. When `prev` is given the column is also read at row
/// offset -1, and that neighbour is written there.
fn commit<E: EvalAtRow>(eval: &mut E, value: E::F, prev: Option<&mut E::F>) -> E::F {
    let m = match prev {
        Some(slot) => {
            let [here, before] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1]);
            *slot = before;
            here
        }
        None => eval.next_trace_mask(),
    };
    eval.add_constraint(value - m.clone());
    m
}

/// One full round: `M_E(pow5(state + RC))`, with all 16 aux columns emitted
/// before the 16 output columns. `digest_prev`, when present, marks this as
/// the final round, whose first `DIGEST_WIDTH` outputs are the row's digest.
fn full_round<E: EvalAtRow>(
    eval: &mut E,
    state: &mut [E::F; WIDTH],
    rc: &[BaseField; WIDTH],
    mut digest_prev: Option<&mut [E::F; DIGEST_WIDTH]>,
) {
    let x: [E::F; WIDTH] = std::array::from_fn(|i| add_const(state[i].clone(), rc[i]));
    let aux: [E::F; WIDTH] = std::array::from_fn(|_| eval.next_trace_mask());
    for i in 0..WIDTH {
        eval.add_constraint(aux[i].clone() - x[i].clone() * x[i].clone());
    }

    let mut y: [E::F; WIDTH] =
        std::array::from_fn(|i| aux[i].clone() * aux[i].clone() * x[i].clone());
    apply_external_round_matrix(&mut y);

    for (i, value) in y.into_iter().enumerate() {
        let prev = digest_prev
            .as_deref_mut()
            .and_then(|d| (i < DIGEST_WIDTH).then(|| &mut d[i]));
        state[i] = commit(eval, value, prev);
    }
}

#[derive(Clone)]
pub struct ChainEval {
    pub log_n_rows: u32,
    /// Logical row of the last real merge, where the chain must equal sigma.
    pub last_row: usize,
    pub sigma: Digest,
}

impl FrameworkEval for ChainEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + LOG_EXPAND
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let is_first = eval.get_preprocessed_column(is_first_id(self.log_n_rows));
        let is_last = eval.get_preprocessed_column(is_last_id(self.log_n_rows, self.last_row));
        let rc = round_constants();

        // Column block 1: the permutation's input state.
        let input: [E::F; WIDTH] = std::array::from_fn(|_| eval.next_trace_mask());

        let mut state = input.clone();
        apply_external_round_matrix(&mut state);

        // Column blocks 2 and 4: the 8 full rounds, each an x^2 aux block
        // followed by the post-round state. Block 3, between them, is the
        // partial rounds: only lane 0 is non-linear there, so each costs one
        // aux and one output column while the rest of the state stays linear
        // in already-committed values.
        //
        // The first 8 output lanes of the FINAL round are this row's digest,
        // and are the one place a mask is also read at row offset -1, to
        // chain to the previous merge.
        let mut prev_out: [E::F; DIGEST_WIDTH] = std::array::from_fn(|_| E::F::zero());

        for round in 0..N_HALF_FULL_ROUNDS {
            full_round(&mut eval, &mut state, &rc.external[round], None);
        }
        for round in 0..N_PARTIAL_ROUNDS {
            let x = add_const(state[0].clone(), rc.internal[round]);
            let y = sbox(&mut eval, x);
            state[0] = commit(&mut eval, y, None);
            apply_internal_round_matrix(&mut state);
        }
        for round in 0..N_HALF_FULL_ROUNDS {
            let last = round == N_HALF_FULL_ROUNDS - 1;
            full_round(
                &mut eval,
                &mut state,
                &rc.external[round + N_HALF_FULL_ROUNDS],
                last.then_some(&mut prev_out),
            );
        }
        let out: [E::F; DIGEST_WIDTH] = std::array::from_fn(|i| state[i].clone());

        // Column block 5: the position bit.
        let bit = eval.next_trace_mask();
        eval.add_constraint(bit.clone() * bit.clone() - bit.clone());

        // Chain: the previous row's digest enters this merge on the left when
        // the bit is 0 and on the right when it is 1. Disabled at row 0,
        // whose input is the secret leaf state.
        let live = E::F::one() - is_first;
        for i in 0..DIGEST_WIDTH {
            eval.add_constraint(
                live.clone()
                    * (E::F::one() - bit.clone())
                    * (input[i].clone() - prev_out[i].clone()),
            );
            eval.add_constraint(
                live.clone() * bit.clone() * (input[DIGEST_WIDTH + i].clone() - prev_out[i].clone()),
            );
        }

        // The last real merge must produce sigma.
        for i in 0..DIGEST_WIDTH {
            eval.add_constraint(is_last.clone() * (out[i].clone() - E::F::from(self.sigma.0[i])));
        }

        eval
    }
}

// TRACE
// ================================================================================================

/// The Poseidon2 witness for one permutation, in the column order the AIR
/// consumes: input state, then per full round an x^2 aux block and the
/// post-round state, then per partial round the same pair for lane 0 only.
fn permutation_witness(input: [BaseField; WIDTH]) -> [BaseField; N_COLUMNS_PER_PERM] {
    let rc = round_constants();
    let mut w = [BaseField::zero(); N_COLUMNS_PER_PERM];
    let mut col = 0;

    w[col..col + WIDTH].copy_from_slice(&input);
    col += WIDTH;

    let mut state = input;
    apply_external_round_matrix(&mut state);

    for round in 0..N_FULL_ROUNDS {
        // The partial rounds sit between the two halves of the full rounds.
        if round == N_HALF_FULL_ROUNDS {
            for r in 0..N_PARTIAL_ROUNDS {
                let x = state[0] + rc.internal[r];
                let aux = x * x;
                state[0] = aux * aux * x;
                w[col] = aux;
                w[col + 1] = state[0];
                col += 2;
                apply_internal_round_matrix(&mut state);
            }
        }

        let x: [BaseField; WIDTH] = std::array::from_fn(|i| state[i] + rc.external[round][i]);
        let aux: [BaseField; WIDTH] = std::array::from_fn(|i| x[i] * x[i]);
        w[col..col + WIDTH].copy_from_slice(&aux);
        col += WIDTH;

        state = std::array::from_fn(|i| aux[i] * aux[i] * x[i]);
        apply_external_round_matrix(&mut state);
        w[col..col + WIDTH].copy_from_slice(&state);
        col += WIDTH;
    }

    debug_assert_eq!(col, N_COLUMNS_PER_PERM);
    w
}

/// Smallest log-height that holds the chain (the SIMD backend needs at least
/// one full lane vector).
pub fn log_n_rows(n_merges: usize) -> u32 {
    n_merges.next_power_of_two().trailing_zeros().max(LOG_N_LANES)
}

fn gen_trace(
    chain: &Chain,
    log_size: u32,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let n_rows = 1usize << log_size;
    assert!(chain.merges.len() <= n_rows, "chain does not fit the trace");

    let mut cols = (0..N_TRACE_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(n_rows))
        .collect_vec();

    let mut acc = chain.seed;
    for row in 0..n_rows {
        // Padding rows keep folding with a ZERO sibling, which satisfies the
        // chain constraint without any extra selector.
        let m = chain.merges.get(row).copied().unwrap_or(Merge {
            sibling: Digest::ZERO,
            bit: false,
        });

        let (left, right) = if m.bit { (m.sibling, acc) } else { (acc, m.sibling) };
        let mut input = [BaseField::zero(); WIDTH];
        input[..DIGEST_WIDTH].copy_from_slice(&left.0);
        input[DIGEST_WIDTH..].copy_from_slice(&right.0);

        let w = permutation_witness(input);
        let idx = storage_index(row, log_size);
        for (col, v) in cols.iter_mut().zip(w) {
            col.set(idx, v);
        }
        cols[BIT_COL].set(idx, BaseField::from_u32_unchecked(m.bit as u32));

        acc = Digest(w[OUT_COL..OUT_COL + DIGEST_WIDTH].try_into().unwrap());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.into_iter().map(|c| CircleEvaluation::new(domain, c)).collect()
}

// PROVE / VERIFY
// ================================================================================================

#[derive(Debug)]
pub enum StwoError {
    Verification(VerificationError),
    /// The preprocessed (selector) tree the proof commits to is not the one
    /// the public parameters determine.
    PreprocessedRootMismatch,
}

impl From<VerificationError> for StwoError {
    fn from(e: VerificationError) -> Self {
        StwoError::Verification(e)
    }
}

/// Everything the verifier needs alongside sigma: the trace height and the
/// row the chain ends on. Both are public in `stark::flat` too (as the
/// cycle count).
#[derive(Clone, Copy, Debug)]
pub struct ChainShape {
    pub log_n_rows: u32,
    pub last_row: usize,
}

/// Binds the public statement into the transcript before anything is
/// committed. Prover and verifier must agree here or Fiat-Shamir diverges.
fn mix_public_inputs(channel: &mut Poseidon252Channel, sigma: &Digest, shape: ChainShape) {
    channel.mix_u64(shape.log_n_rows as u64);
    channel.mix_u64(shape.last_row as u64);
    channel.mix_u32s(&sigma.0.map(|e| e.0));
}

/// Proves the chain. Returns the proof and the shape the verifier needs.
pub fn prove(chain: &Chain, config: PcsConfig) -> (StarkProof<Poseidon252MerkleHasher>, ChainShape) {
    let log_size = log_n_rows(chain.merges.len());
    let shape = ChainShape { log_n_rows: log_size, last_row: chain.merges.len() - 1 };
    let sigma = chain.root();
    let config = clamped(config, log_size);

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + LOG_EXPAND + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut Poseidon252Channel::default();
    mix_public_inputs(channel, &sigma, shape);
    let mut commitment_scheme =
        CommitmentSchemeProver::<_, Poseidon252MerkleChannel>::new(config, &twiddles);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed_trace(log_size, shape.last_row));
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(gen_trace(chain, log_size));
    tree_builder.commit(channel);

    let component = ChainComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_first_id(log_size),
            is_last_id(log_size, shape.last_row),
        ]),
        ChainEval { log_n_rows: log_size, last_row: shape.last_row, sigma },
        SecureField::zero(),
    );

    let proof = stwo_prove::<SimdBackend, Poseidon252MerkleChannel>(&[&component], channel, commitment_scheme).expect("proof generation");
    (proof, shape)
}

/// Verifies the chain proof against a trusted sigma. Knows only sigma and
/// the shape — not the key, not the chain.
pub fn verify(
    sigma: &Digest,
    shape: ChainShape,
    proof: StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
) -> Result<(), StwoError> {
    // The selector columns are public data, so pin them: regenerate and
    // commit them here and require the proof's preprocessed root to match.
    let config = clamped(config, shape.log_n_rows);
    let expected_root = {
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(shape.log_n_rows + LOG_EXPAND + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let throwaway = &mut Poseidon252Channel::default();
        let mut cs = CommitmentSchemeProver::<_, Poseidon252MerkleChannel>::new(config, &twiddles);
        let mut tree_builder = cs.tree_builder();
        tree_builder.extend_evals(preprocessed_trace(shape.log_n_rows, shape.last_row));
        tree_builder.commit(throwaway);
        cs.roots()[0]
    };
    if proof.commitments[0] != expected_root {
        return Err(StwoError::PreprocessedRootMismatch);
    }

    let component = ChainComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&[
            is_first_id(shape.log_n_rows),
            is_last_id(shape.log_n_rows, shape.last_row),
        ]),
        ChainEval { log_n_rows: shape.log_n_rows, last_row: shape.last_row, sigma: *sigma },
        SecureField::zero(),
    );

    let channel = &mut Poseidon252Channel::default();
    mix_public_inputs(channel, sigma, shape);
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    let sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);

    stwo::core::verifier::verify(&[&component], channel, commitment_scheme, proof)
        .map_err(StwoError::from)
}

/// Convenience: compile a real IBSL proof and prove it in one step.
pub fn prove_ibsl(
    k: u64,
    pi: &[Step<Poseidon2FlatHashVc>],
) -> (StarkProof<Poseidon252MerkleHasher>, ChainShape) {
    prove(&compile(k, pi), default_config())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::NodeDigest;
    use crate::hashes::Hash;
    use crate::hashes::poseidon2::Poseidon2FlatHash;
    use crate::ibsl::Ibsl;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    /// Every constraint must vanish on the trace domain — the direct check,
    /// independent of FRI, that the AIR and the witness generator agree.
    #[test]
    fn constraints_hold_on_trace() {
        let chain = Chain {
            seed: Digest::from_u128(42),
            merges: (0..5)
                .map(|i| Merge { sibling: Digest::from_u128(100 + i), bit: i % 2 == 1 })
                .collect(),
        };
        let log_size = log_n_rows(chain.merges.len());
        let last_row = chain.merges.len() - 1;
        let sigma = chain.root();

        let pre: Vec<Vec<BaseField>> = preprocessed_trace(log_size, last_row)
            .iter()
            .map(|c| c.values.to_cpu())
            .collect();
        let main: Vec<Vec<BaseField>> =
            gen_trace(&chain, log_size).iter().map(|c| c.values.to_cpu()).collect();

        let trees = TreeVec::new(vec![
            pre.iter().collect::<Vec<_>>(),
            main.iter().collect::<Vec<_>>(),
        ]);
        let eval = ChainEval { log_n_rows: log_size, last_row, sigma };
        assert_constraints_on_trace(
            &trees,
            log_size,
            |e| {
                eval.evaluate(e);
            },
            SecureField::zero(),
        );
    }

    /// The trace's fold must reproduce what the native flat hash computes:
    /// the chain's root is the IBSL root commitment.
    #[test]
    fn compiled_chain_reaches_sigma() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = Ibsl::<Poseidon2FlatHashVc>::new(&keys, 7);
        let sigma = s.root_commitment();

        for k in [3, 45, 90] {
            let pi = s.prove(k).expect("member proof");
            assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "native proof for {k} rejected");
            assert_eq!(compile(k, &pi).root(), sigma, "chain for {k} misses sigma");
        }
    }

    /// The witness generator and the AIR must agree on the permutation: the
    /// output columns of a row equal the native merge.
    #[test]
    fn witness_matches_native_merge() {
        let l = Digest::from_u128(11);
        let r = Digest::from_u128(22);
        let mut input = [BaseField::zero(); WIDTH];
        input[..DIGEST_WIDTH].copy_from_slice(&l.0);
        input[DIGEST_WIDTH..].copy_from_slice(&r.0);
        let w = permutation_witness(input);
        assert_eq!(
            Digest(w[OUT_COL..OUT_COL + DIGEST_WIDTH].try_into().unwrap()),
            merge(l, r)
        );
        assert_eq!(Poseidon2FlatHash::node(&[l, r]), merge(l, r));
    }

    /// End to end: a real IBSL proof verifies natively AND as a Stwo STARK
    /// against the same sigma.
    #[test]
    fn real_proof_verifies_as_stwo_stark() {
        let keys: Vec<u64> = (1..=30).map(|i| i * 3).collect();
        let s = Ibsl::<Poseidon2FlatHashVc>::new(&keys, 7);
        let sigma = s.root_commitment();

        for k in [3, 45, 90] {
            let pi = s.prove(k).expect("member proof");
            let (proof, shape) = prove_ibsl(k, &pi);
            assert!(
                verify(&sigma, shape, proof, default_config()).is_ok(),
                "Stwo proof for {k} rejected"
            );
        }
    }

    /// A wrong sigma must be rejected.
    #[test]
    fn wrong_sigma_rejected() {
        let s = Ibsl::<Poseidon2FlatHashVc>::new(&[10, 20, 30, 40], 3);
        let pi = s.prove(30).unwrap();
        let (proof, shape) = prove_ibsl(30, &pi);

        let s2 = Ibsl::<Poseidon2FlatHashVc>::new(&[10, 20, 30, 40, 50], 3);
        let wrong = s2.root_commitment();
        assert!(verify(&wrong, shape, proof, default_config()).is_err());
    }

    /// Moving the end-of-chain selector must be caught by the preprocessed
    /// root check rather than silently accepted.
    #[test]
    fn moved_last_row_rejected() {
        let s = Ibsl::<Poseidon2FlatHashVc>::new(&[10, 20, 30, 40], 3);
        let pi = s.prove(30).unwrap();
        let sigma = s.root_commitment();
        let (proof, shape) = prove_ibsl(30, &pi);

        let tampered = ChainShape { last_row: shape.last_row + 1, ..shape };
        assert!(matches!(
            verify(&sigma, tampered, proof, default_config()),
            Err(StwoError::PreprocessedRootMismatch)
        ));
    }

    /// Sanity: the component really is 301 trace columns wide.
    #[test]
    fn trace_width_is_as_documented() {
        let component = ChainComponent::new(
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&[
                is_first_id(4),
                is_last_id(4, 3),
            ]),
            ChainEval { log_n_rows: 4, last_row: 3, sigma: Digest::ZERO },
            SecureField::zero(),
        );
        let sizes = component.trace_log_degree_bounds();
        assert_eq!(sizes[ORIGINAL_TRACE_IDX].len(), N_TRACE_COLUMNS);
        assert_eq!(N_TRACE_COLUMNS, 301);
        assert_eq!(N_COLUMNS_PER_PERM, 300);
    }
}

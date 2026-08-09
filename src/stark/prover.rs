// Adapted from Facebook's Winterfell examples/src/merkle/prover.rs (MIT).
// Generalised for IBSL: the trace is built from a chain of per-level opening
// segments (with seam transitions between them) instead of a single
// authentication path, and is padded to a power-of-two cycle count.

use core::marker::PhantomData;

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use super::air::{MerkleAir, PublicInputs};
use super::rescue::{
    self, CYCLE_LENGTH as HASH_CYCLE_LEN, NUM_ROUNDS as NUM_HASH_ROUNDS,
    STATE_WIDTH as HASH_STATE_WIDTH,
};
use super::TRACE_WIDTH;

// SEGMENTS
// ================================================================================================

/// One IBSL level's opening, bottom-up: climb `siblings` (pair level first)
/// steered by the bits of `position` — exactly the content of one
/// `Step::witness` + `Step::position` of a real proof.
#[derive(Clone, Debug)]
pub struct Segment {
    pub position: usize,
    pub siblings: Vec<rescue::Hash>,
}

impl Segment {
    /// Cycles this segment occupies: one leaf-hash cycle plus one merge per
    /// sibling.
    pub fn num_cycles(&self) -> usize {
        1 + self.siblings.len()
    }
}

/// What the transition at the end of a cycle sets up for the next cycle.
enum CycleIn {
    /// Merge with a sibling: bit 0 -> accumulator stays left, sibling right;
    /// bit 1 -> accumulator moves right, sibling left. Padding cycles are
    /// merges with a zero sibling.
    Merge { sibling: [BaseElement; 2], bit: BaseElement },
    /// New IBSL level: truncate the accumulated digest to its first element
    /// and leaf-hash it into the parent's tree.
    Seam,
}

// IBSL MEMBERSHIP PROVER
// ================================================================================================

pub struct MerkleProver<H: ElementHasher> {
    options: ProofOptions,
    /// Real (unpadded) path cycles; needed to locate sigma in the trace for
    /// the public inputs.
    path_cycles: usize,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> MerkleProver<H> {
    pub fn new(options: ProofOptions, path_cycles: usize) -> Self {
        Self { options, path_cycles, _hasher: PhantomData }
    }

    /// Builds the execution trace for the whole IBSL chain: `leaf_value` (the
    /// key embedded in the field) is leaf-hashed, climbs the first segment's
    /// siblings, crosses a seam into the next level, and so on until the last
    /// segment resolves to sigma; remaining cycles up to the next power of
    /// two are padding merges.
    pub fn build_trace(
        &self,
        leaf_value: BaseElement,
        segments: &[Segment],
    ) -> TraceTable<BaseElement> {
        let path_cycles: usize = segments.iter().map(Segment::num_cycles).sum();
        assert_eq!(path_cycles, self.path_cycles, "prover/segment cycle mismatch");
        let total_cycles = path_cycles.next_power_of_two();

        // plan[c] = what the transition INTO cycle c does (c >= 1; cycle 0 is
        // the first leaf hash, set up by the init closure).
        let mut plan: Vec<CycleIn> = Vec::with_capacity(total_cycles);
        plan.push(CycleIn::Seam); // placeholder for cycle 0, never read
        for (i, seg) in segments.iter().enumerate() {
            if i > 0 {
                plan.push(CycleIn::Seam);
            }
            for (j, sib) in seg.siblings.iter().enumerate() {
                plan.push(CycleIn::Merge {
                    sibling: sib.to_elements(),
                    bit: BaseElement::new(((seg.position >> j) & 1) as u128),
                });
            }
        }
        while plan.len() < total_cycles {
            plan.push(CycleIn::Merge {
                sibling: [BaseElement::ZERO; 2],
                bit: BaseElement::ZERO,
            });
        }

        let trace_length = total_cycles * HASH_CYCLE_LEN;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        trace.fill(
            |state| {
                // cycle 0 leaf-hashes the key: state = [k, 0, 0, 0 | 0, 0]
                state[0] = leaf_value;
                state[1..].fill(BaseElement::ZERO);
            },
            |step, state| {
                // For the first NUM_HASH_ROUNDS steps of each cycle, apply one
                // Rescue round to registers [0..HASH_STATE_WIDTH]. On the last
                // step, set up the next cycle according to the plan.
                let cycle_num = step / HASH_CYCLE_LEN;
                let cycle_pos = step % HASH_CYCLE_LEN;

                if cycle_pos < NUM_HASH_ROUNDS {
                    rescue::apply_round(&mut state[..HASH_STATE_WIDTH], step);
                } else {
                    match plan[cycle_num + 1] {
                        CycleIn::Merge { sibling, bit } => {
                            if bit == BaseElement::ZERO {
                                state[2] = sibling[0];
                                state[3] = sibling[1];
                            } else {
                                state[2] = state[0];
                                state[3] = state[1];
                                state[0] = sibling[0];
                                state[1] = sibling[1];
                            }
                            state[6] = bit;
                            state[7] = BaseElement::ZERO;
                        }
                        CycleIn::Seam => {
                            // to_field(digest) = first element; leaf-hash it
                            state[1] = BaseElement::ZERO;
                            state[2] = BaseElement::ZERO;
                            state[3] = BaseElement::ZERO;
                            state[6] = BaseElement::ZERO;
                            state[7] = BaseElement::ONE;
                        }
                    }
                    // reset the capacity registers of the state to ZERO
                    state[4] = BaseElement::ZERO;
                    state[5] = BaseElement::ZERO;
                }
            },
        );

        // set the bit and seam registers at the second step to one; still a
        // valid trace (both are only read at cycle boundaries) but it keeps
        // their binary-constraint degrees stable by avoiding all-zero /
        // short-period columns.
        trace.set(6, 1, FieldElement::ONE);
        trace.set(7, 1, FieldElement::ONE);

        trace
    }
}

impl<H: ElementHasher> Prover for MerkleProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let end = self.path_cycles * HASH_CYCLE_LEN - 1;
        PublicInputs {
            tree_root: [trace.get(0, end), trace.get(1, end)],
            num_path_cycles: self.path_cycles,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// Adapted from Facebook's Winterfell examples/src/merkle/air.rs (MIT).
// Extended for IBSL: a seam register (column 7) lets one trace chain the
// per-level openings of an IBSL proof, and the sigma assertion lands at a
// public-input-determined step so the path can be padded to a power of two.

use winterfell::{
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::rescue::{self, CYCLE_LENGTH as HASH_CYCLE_LEN, STATE_WIDTH as HASH_STATE_WIDTH};
use super::{are_equal, is_binary, is_zero, not, EvaluationResult, TRACE_WIDTH};

// IBSL MEMBERSHIP CHAIN AIR
// ================================================================================================

pub struct PublicInputs {
    /// sigma, the IBSL root commitment the chain must resolve to.
    pub tree_root: [BaseElement; 2],
    /// Number of 8-step hash cycles the real path occupies; everything after
    /// is padding. Determines the step at which sigma is asserted.
    pub num_path_cycles: usize,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.tree_root[0],
            self.tree_root[1],
            BaseElement::new(self.num_path_cycles as u128),
        ]
    }
}

pub struct MerkleAir {
    context: AirContext<BaseElement>,
    tree_root: [BaseElement; 2],
    /// Last step of the real (unpadded) path: the accumulated digest here
    /// must equal sigma.
    path_end_step: usize,
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // one degree-5 cyclic constraint per Rescue state register, plus the
        // binary constraints on the index-bit and seam registers.
        let mut degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN]);
            HASH_STATE_WIDTH
        ];
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));
        assert_eq!(TRACE_WIDTH, trace_info.width());

        assert!(pub_inputs.num_path_cycles > 0, "path must have at least one cycle");
        let path_end_step = pub_inputs.num_path_cycles * HASH_CYCLE_LEN - 1;
        assert!(
            path_end_step < trace_info.length(),
            "path ({} cycles) does not fit the trace ({} steps)",
            pub_inputs.num_path_cycles,
            trace_info.length()
        );

        MerkleAir {
            context: AirContext::new(trace_info, degrees, 4, options),
            tree_root: pub_inputs.tree_root,
            path_end_step,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into the hash-cycle mask and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..];

        // when hash_flag = 1, constraints for a Rescue round are enforced
        rescue::enforce_round(
            result,
            &current[..HASH_STATE_WIDTH],
            &next[..HASH_STATE_WIDTH],
            ark,
            hash_flag,
        );

        // when hash_flag = 0 the next cycle is being set up. Two shapes:
        //
        // seam = 0 (a sibling merge within one level's tree, as in the
        // original example): the accumulated digest goes into registers
        // [0, 1] when the position bit is 0, or [2, 3] when it is 1; the
        // sibling occupies the other pair (unconstrained — it is witness).
        //
        // seam = 1 (a new IBSL level starts): the accumulated digest — the
        // commitment of the level below — is truncated to its first element
        // (this IS `to_field` for the Rescue backend) and becomes the sole
        // input of a leaf hash: next state must be [d0, 0, 0, 0].
        let hash_init_flag = not(hash_flag);
        let bit = next[6];
        let not_bit = not(bit);
        let seam = next[7];
        let not_seam = not(seam);

        // merge placement (seam = 0)
        result.agg_constraint(0, hash_init_flag, not_seam * not_bit * are_equal(current[0], next[0]));
        result.agg_constraint(1, hash_init_flag, not_seam * not_bit * are_equal(current[1], next[1]));
        result.agg_constraint(2, hash_init_flag, not_seam * bit * are_equal(current[0], next[2]));
        result.agg_constraint(3, hash_init_flag, not_seam * bit * are_equal(current[1], next[3]));

        // seam placement (seam = 1): next = [to_field(digest), 0, 0, 0]
        result.agg_constraint(0, hash_init_flag, seam * are_equal(current[0], next[0]));
        result.agg_constraint(1, hash_init_flag, seam * is_zero(next[1]));
        result.agg_constraint(2, hash_init_flag, seam * is_zero(next[2]));
        result.agg_constraint(3, hash_init_flag, seam * is_zero(next[3]));

        // make sure the capacity registers of the hash state are reset to zeros
        result.agg_constraint(4, hash_init_flag, is_zero(next[4]));
        result.agg_constraint(5, hash_init_flag, is_zero(next[5]));

        // the bit and seam registers always hold binary values
        result[6] = is_binary(current[6]);
        result[7] = is_binary(current[7]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // assert that the chain resolves to sigma at the end of the real path
        // (padding cycles may follow), and that the hash capacity registers
        // (4 and 5) are reset to ZERO every cycle.
        vec![
            Assertion::single(0, self.path_end_step, self.tree_root[0]),
            Assertion::single(1, self.path_end_step, self.tree_root[1]),
            Assertion::periodic(4, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(5, 0, HASH_CYCLE_LEN, BaseElement::ZERO),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![HASH_CYCLE_MASK.to_vec()];
        result.append(&mut rescue::get_round_constants());
        result
    }
}

// MASKS
// ================================================================================================
const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];

//! IBSL vector-commitment backend over the Greyhound lattice polynomial
//! commitment (lattice-dogs/labrador), via C FFI. AVX512-only C — runs only on
//! AVX512 hardware or under Intel SDE.
//!
//! # An evaluation-PCS used as a positional VC, properly
//!
//! Greyhound commits to a polynomial and proves `p(x) = y` at a public point
//! x. That IS a positional vector commitment once the vector is encoded in the
//! evaluation basis: commit to the **interpolant** of the slot values, so that
//! `p(z_i) = m[i]` at fixed public points `z_i = i+1`. Opening slot `i` is then
//! an evaluation proof at `x = z_i`, and it reveals nothing but that slot's
//! value — the committed vector never goes on the wire. (Same idea as the
//! Lagrange-basis trick that makes KZG a vector commitment; see `vc::kzg`.)
//!
//! A commitment is the 16-byte hash `h = H(u1)` of Greyhound's outer
//! commitment. The opening carries `u1` itself, and `check` recomputes `H(u1)`
//! and compares — that comparison is what binds an opening to a commitment.
//!
//! # Two proving modes
//!
//! `polcom_reduce` turns an evaluation proof into a Labrador *principal
//! statement*; a Labrador composite proof then discharges it. What an L-level
//! IBSL proof pays for depends on where the sharing happens:
//!
//!   - **per node** (`VectorCommitment::check`): one composite per opened
//!     node, so an L-level proof carries L of them, plus L `(u1, u2)` pairs.
//!   - **batched** (`AggregatableVc`): Greyhound's own batching, from §3.2 and
//!     §4.4 of the paper. Every level's `w-hat` goes under ONE shared
//!     commitment `v = Σ_j D_j ŵ_j`, so the wire carries `L+1` commitments
//!     rather than `2L`, and a single composite covers the whole path.
//!
//! The `D_j` must be disjoint column blocks of the commitment key or `v` binds
//! nothing about the individual `ŵ_j`; `greyhound_batch.c` lays them out past
//! everything else the protocol reads.
//!
//! Batching is not free at commit time. The batched principal statement
//! carries ONE norm bound for all L blocks and it must be their SUM — nothing
//! stops a cheating prover concentrating the budget in one block — so every
//! commitment's parameters have to be chosen for the largest batch it might
//! later join (`GH_BATCH_MAX` in the shim). That buys a slightly larger
//! `kappa`/`kappa1` on every commitment, which partly offsets the commitments
//! the batch saves.
//!
//! Slot values are `Z_q` elements with `q = 2^32 - 99` (`LOGQ = 32`), so one
//! slot carries 32 bits. `to_field` truncates a 128-bit commitment hash into
//! that, which caps the parent-child chain's collision resistance at ~2^16
//! work — inherent to one slot per child at this modulus, not to the encoding.

use std::ffi::c_void;
use std::fmt;
use std::sync::Arc;

use crate::field::NodeDigest;
use crate::vc::{AggregatableVc, VectorCommitment};

extern "C" {
    fn gh_commit(vals: *const i64, d: usize, out_h: *mut u8) -> *mut c_void;
    fn gh_open(ctx: *mut c_void, i: usize) -> *mut c_void;
    fn gh_open_pos(o: *const c_void) -> usize;
    fn gh_open_x(o: *const c_void) -> i64;
    fn gh_open_y(o: *const c_void) -> i64;
    fn gh_open_h(o: *const c_void, out: *mut u8);
    fn gh_open_proof_bytes(o: *const c_void) -> usize;
    fn gh_prove_node(o: *mut c_void) -> i32;
    fn gh_node_proof_bytes(o: *const c_void) -> usize;
    fn gh_verify(o: *mut c_void) -> i32;
    fn gh_batch_prove(ctxs: *const *mut c_void, slots: *const usize, nb: usize) -> *mut c_void;
    fn gh_batch_eval_bytes(b: *const c_void) -> usize;
    fn gh_batch_proof_bytes(b: *const c_void) -> usize;
    fn gh_batch_len(b: *const c_void) -> usize;
    fn gh_batch_pos(b: *const c_void, j: usize) -> usize;
    fn gh_batch_x(b: *const c_void, j: usize) -> i64;
    fn gh_batch_y(b: *const c_void, j: usize) -> i64;
    fn gh_batch_h(b: *const c_void, j: usize, out: *mut u8);
    fn gh_batch_verify(b: *const c_void) -> i32;
    fn gh_batch_free(b: *mut c_void);
    fn gh_ctx_free(ctx: *mut c_void);
    fn gh_open_free(o: *mut c_void);
    fn gh_quiet(on: i32);
}

/// The Greyhound modulus, `LOGQ = 32`, `QOFF = 99` (prime, so the shim's
/// interpolation can invert every difference of evaluation points).
const Q: i64 = (1i64 << 32) - 99;

/// The public evaluation point standing for slot `i` — must match the shim's
/// `slot_point`.
fn slot_point(i: usize) -> i64 {
    ((i as i64) + 1) % Q
}

/// Silences the upstream prove/verify progress tables, which would otherwise
/// interleave with benchmark output. Idempotent.
pub fn set_quiet(on: bool) {
    unsafe { gh_quiet(on as i32) };
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct GreyhoundField(pub i64);

impl NodeDigest for GreyhoundField {
    fn from_u128(v: u128) -> Self {
        GreyhoundField((v % (Q as u128)) as i64)
    }
    fn zero() -> Self {
        GreyhoundField(0)
    }
}

/// A node commitment: `H(u1)`, plus the slot count it was built for.
#[derive(Clone, Debug, PartialEq)]
pub struct GhCommitment {
    pub h: [u8; 16],
    pub d: usize,
}

// --- owned C handles, freed on drop ---

struct GhCtxHandle(*mut c_void);
impl Drop for GhCtxHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { gh_ctx_free(self.0) };
        }
    }
}

struct GhOpenHandle(*mut c_void);
impl Drop for GhOpenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { gh_open_free(self.0) };
        }
    }
}

struct GhBatchHandle(*mut c_void);
impl Drop for GhBatchHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { gh_batch_free(self.0) };
        }
    }
}

/// Prover state kept beside a commitment: the C context handle and the slot
/// count, so `open(i)` is a bounds check plus one C call.
pub struct GhOpener {
    ctx: GhCtxHandle,
    d: usize,
}

/// A single-node opening: the Greyhound evaluation proof plus this node's own
/// Labrador composite. `Arc` so `Clone` shares the C handle rather than
/// double-freeing it.
#[derive(Clone)]
pub struct GhWitness {
    open: Arc<GhOpenHandle>,
    /// Greyhound's outer commitments (u1, u2) for this node.
    pub proof_bytes: usize,
    /// This node's own Labrador composite — the part aggregation removes.
    pub node_proof_bytes: usize,
}

impl fmt::Debug for GhWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GhWitness")
            .field("proof_bytes", &self.proof_bytes)
            .field("node_proof_bytes", &self.node_proof_bytes)
            .finish()
    }
}

/// ONE batched opening covering a whole proof path: the per-level outer
/// commitments `u1`, the single shared `v` that commits to every level's
/// `w-hat`, and one Labrador composite over the lot.
#[derive(Clone)]
pub struct GhAggWitness {
    batch: Arc<GhBatchHandle>,
    levels: usize,
    /// The L outer commitments plus the ONE shared v — `(L+1)` commitments,
    /// where L unbatched openings would carry `2L`.
    pub eval_bytes: usize,
    /// The single composite covering every level.
    pub composite_bytes: usize,
}

impl fmt::Debug for GhAggWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GhAggWitness")
            .field("levels", &self.levels)
            .field("eval_bytes", &self.eval_bytes)
            .field("composite_bytes", &self.composite_bytes)
            .finish()
    }
}

pub struct GreyhoundVc;

/// Opens slot `i` of `opener`'s committed vector, returning the raw C handle.
fn raw_open(opener: &GhOpener, i: usize) -> *mut c_void {
    assert!(i < opener.d, "slot {i} out of range for width {}", opener.d);
    let o = unsafe { gh_open(opener.ctx.0, i) };
    assert!(!o.is_null(), "gh_open failed at slot {i}");
    o
}

/// The checks every opening must pass regardless of proving mode: it speaks
/// about THIS commitment, at THIS slot, and yields THIS value. The Labrador
/// proof (per node or aggregated) is what certifies the evaluation itself.
fn public_checks(o: *mut c_void, c: &GhCommitment, i: usize, value: GreyhoundField) -> bool {
    let mut h = [0u8; 16];
    unsafe {
        gh_open_h(o, h.as_mut_ptr());
        h == c.h && gh_open_pos(o) == i && gh_open_x(o) == slot_point(i) && gh_open_y(o) == value.0
    }
}

impl VectorCommitment for GreyhoundVc {
    type DigestType = GreyhoundField;
    type Commitment = GhCommitment;
    type Witness = GhWitness;
    type Opener = GhOpener;

    fn setup(_width: usize) -> Self {
        GreyhoundVc
    }

    fn empty_commitment() -> Self::Commitment {
        GhCommitment { h: [0u8; 16], d: 0 }
    }

    fn commit(&self, values: &[Self::DigestType]) -> (Self::Commitment, Self::Opener) {
        // The shim needs at least one slot to interpolate through.
        let vals: Vec<i64> = if values.is_empty() {
            vec![0]
        } else {
            values.iter().map(|v| v.0).collect()
        };
        let mut h = [0u8; 16];
        let ctx = unsafe { gh_commit(vals.as_ptr(), vals.len(), h.as_mut_ptr()) };
        assert!(!ctx.is_null(), "gh_commit failed (d={})", vals.len());
        (
            GhCommitment { h, d: vals.len() },
            GhOpener { ctx: GhCtxHandle(ctx), d: vals.len() },
        )
    }

    fn open(&self, opener: &Self::Opener, i: usize) -> Self::Witness {
        let o = raw_open(opener, i);
        let proof_bytes = unsafe { gh_open_proof_bytes(o) };
        let rc = unsafe { gh_prove_node(o) };
        assert_eq!(rc, 0, "gh_prove_node failed ({rc})");
        let node_proof_bytes = unsafe { gh_node_proof_bytes(o) };
        GhWitness {
            open: Arc::new(GhOpenHandle(o)),
            proof_bytes,
            node_proof_bytes,
        }
    }

    fn check(&self, c: &Self::Commitment, i: usize, value: Self::DigestType, w: &Self::Witness) -> bool {
        public_checks(w.open.0, c, i, value) && unsafe { gh_verify(w.open.0) == 0 }
    }

    fn commitment_bytes(c: &Self::Commitment) -> Vec<u8> {
        c.h.to_vec()
    }

    /// Greyhound's own evaluation proof (u1, u2) plus this node's Labrador
    /// composite. The slot value is no longer revealed, and the committed
    /// vector never appears — both are what the interpolant encoding buys.
    fn witness_size(w: &Self::Witness) -> usize {
        w.proof_bytes + w.node_proof_bytes
    }

    fn to_field(c: &Self::Commitment) -> Self::DigestType {
        let mut b = [0u8; 8];
        b.copy_from_slice(&c.h[..8]);
        GreyhoundField((u64::from_le_bytes(b) % (Q as u64)) as i64)
    }
}

/// Batched openings: Greyhound's own batching (paper §3.2/§4.4), then ONE
/// Labrador composite. See the module docs.
impl AggregatableVc for GreyhoundVc {
    type AggWitness = GhAggWitness;

    /// The L+1 commitments, plus the one composite.
    fn agg_witness_size(w: &Self::AggWitness) -> usize {
        w.eval_bytes + w.composite_bytes
    }

    fn aggregate_open(
        &self,
        claims: &[(&Self::Opener, &Self::Commitment, usize, Self::DigestType)],
    ) -> Self::AggWitness {
        // The batch is driven straight off the committing contexts: unlike the
        // per-node path there is no separate `open` step, because a level's
        // w-hat is only ever committed as part of the shared v.
        let ctxs: Vec<*mut c_void> = claims.iter().map(|&(op, _, _, _)| op.ctx.0).collect();
        let slots: Vec<usize> = claims
            .iter()
            .map(|&(op, _, i, _)| {
                assert!(i < op.d, "slot {i} out of range for width {}", op.d);
                i
            })
            .collect();

        let b = unsafe { gh_batch_prove(ctxs.as_ptr(), slots.as_ptr(), ctxs.len()) };
        assert!(!b.is_null(), "gh_batch_prove failed over {} openings", ctxs.len());

        GhAggWitness {
            levels: ctxs.len(),
            eval_bytes: unsafe { gh_batch_eval_bytes(b) },
            composite_bytes: unsafe { gh_batch_proof_bytes(b) },
            batch: Arc::new(GhBatchHandle(b)),
        }
    }

    fn aggregate_check(
        &self,
        claims: &[(&Self::Commitment, usize, Self::DigestType)],
        witness: &Self::AggWitness,
    ) -> bool {
        let b = witness.batch.0;
        if claims.len() != unsafe { gh_batch_len(b) } {
            return false;
        }
        // Each instance must speak about its claimed (commitment, slot, value)
        // — the same public checks the per-node path makes, read off the batch
        // instead of off a standalone opening.
        for (j, &(c, i, v)) in claims.iter().enumerate() {
            let mut h = [0u8; 16];
            unsafe { gh_batch_h(b, j, h.as_mut_ptr()) };
            let ok = unsafe {
                h == c.h
                    && gh_batch_pos(b, j) == i
                    && gh_batch_x(b, j) == slot_point(i)
                    && gh_batch_y(b, j) == v.0
            };
            if !ok {
                return false;
            }
        }
        // ... and the one composite certifies all L evaluations together.
        unsafe { gh_batch_verify(b) == 0 }
    }
}

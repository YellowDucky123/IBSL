//! Native benchmark of IBSL over the Greyhound lattice-PCS backend
//! (`ibsl::vc::greyhound::GreyhoundVc`, C FFI), at a configurable promotion
//! probability.
//!
//! Measures the two proving modes against each other:
//!   - **per node**  — `Ibsl::prove`     — one Labrador composite per level,
//!     and Greyhound's own `(u1, u2)` per level, so `2L` commitments.
//!   - **aggregated** — `Ibsl::prove_agg` — Greyhound's batching (paper
//!     §3.2/§4.4): every level's `w-hat` under ONE shared commitment `v`, so
//!     `L+1` commitments, then ONE Labrador composite over the whole path.
//!
//! So the modes differ in two places, not one: where the Labrador proof sits,
//! AND how many commitments the wire carries. The batched mode does not win
//! for free — its commitments must be parameterised for the batch's summed
//! norm bound, which costs a larger `kappa1` (5 rather than 4 here, so 1.25 KB
//! per commitment rather than 1.0 KB). It comes out ahead from L = 2 on, and
//! the margin widens with L.
//!
//! Runs only under AVX512 (real hardware or Intel SDE). Under SDE, proof SIZES
//! and verification correctness are real; ALL TIMINGS ARE VOID (emulation is
//! 50-100x slow and non-uniform). Keep n tiny.

use std::time::{Duration, Instant};

use ibsl::ibsl::{AggProof, Ibsl, Proof};
use ibsl::vc::greyhound::set_quiet;
use ibsl::vc::{AggregatableVc, GreyhoundVc, VectorCommitment};

const DEFAULT_SIZES: &[usize] = &[30];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

/// Per-node mode: every level carries a Greyhound eval proof AND its own
/// Labrador composite.
fn per_node_bytes(pi: &Proof<GreyhoundVc>) -> (usize, usize) {
    let eval = pi.iter().map(|s| s.witness.proof_bytes).sum();
    let composite = pi.iter().map(|s| s.witness.node_proof_bytes).sum();
    (eval, composite)
}

/// Aggregated mode: the same per-level eval proofs, but ONE composite for the
/// entire path.
fn agg_bytes(pi: &AggProof<GreyhoundVc>) -> (usize, usize) {
    (pi.witness.eval_bytes, pi.witness.composite_bytes)
}

fn kb(b: usize) -> String {
    format!("{:.1} KB", b as f64 / 1024.0)
}

pub fn run(p: f64, sizes: &[usize]) {
    // Upstream prints a prove/verify table per composite; keep it out of ours.
    set_quiet(true);
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL over Greyhound lattice-PCS (labrador, C FFI), native — p = {p} ==");
    println!("(under SDE: sizes/verify real, timings VOID)");
    println!();
    println!("| n | p | height | levels | mode | eval proofs | Labrador | total | prove | verify |");
    println!("|---|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let s = Ibsl::<GreyhoundVc>::new_with_promotion(&keys, 0xC0FFEE, p);
        let sigma = s.root_commitment();

        // One sample: each is several full Labrador proofs under emulation.
        let k = keys[keys.len() / 2];

        let (pi, prove) = timed(|| s.prove(k).expect("member proof"));
        let (ok, verify) = timed(|| Ibsl::verify(s.vc(), &sigma, k, &pi));
        assert!(ok, "IBSL-Greyhound per-node verification failed");
        let (n_eval, n_comp) = per_node_bytes(&pi);
        let levels = pi.len();

        let (api, agg_prove) = timed(|| s.prove_agg(k).expect("aggregated member proof"));
        let (ok, agg_verify) = timed(|| Ibsl::verify_agg(s.vc(), &sigma, k, &api));
        assert!(ok, "IBSL-Greyhound aggregated verification failed");
        let (a_eval, a_comp) = agg_bytes(&api);

        let h = s.height();
        println!(
            "| {n} | {p} | {h} | {levels} | per node | {} | {} ({levels}x) | {} | {prove:.2?} | {verify:.2?} |",
            kb(n_eval),
            kb(n_comp),
            kb(n_eval + n_comp),
        );
        println!(
            "| {n} | {p} | {h} | {levels} | aggregated | {} | {} (1x) | {} | {agg_prove:.2?} | {agg_verify:.2?} |",
            kb(a_eval),
            kb(a_comp),
            kb(a_eval + a_comp),
        );

        let before = (n_eval + n_comp) as f64;
        let after = (a_eval + a_comp) as f64;
        println!();
        println!(
            "  n={n}: {levels} levels — aggregation {:.2}x smaller ({} -> {}); \
             one commitment is {} B, one eval proof {} B.",
            before / after,
            kb(n_eval + n_comp),
            kb(a_eval + a_comp),
            GreyhoundVc::commitment_size(&sigma),
            a_eval / levels,
        );
        println!(
            "  aggregated proof also carries {levels} commitments ({} B) in AggProof::steps.",
            GreyhoundVc::commitment_size(&sigma) * levels,
        );
        println!();
        let _ = GreyhoundVc::agg_witness_size(&api.witness);
    }
}

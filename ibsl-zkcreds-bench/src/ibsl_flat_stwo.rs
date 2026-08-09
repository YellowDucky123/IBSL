//! ZK benchmark: the IBSL flat-hash membership chain proven twice — once in
//! the Winterfell STARK (`ibsl::stark::flat`, Rescue over f128) and once in
//! StarkWare's Stwo Circle STARK (`ibsl::stark::stwo`, Poseidon2 over M31) —
//! so the two provers can be compared on the same statement at the same
//! security (28 queries, blowup 8, no grinding, ~84-bit conjectured).
//!
//! Stwo commits with Poseidon252, its algebraic Merkle/FRI hash, not Blake2s;
//! Winterfell has no algebraic hasher for f128 and stays on BLAKE3. Digests
//! are 32 bytes either way, so this costs proving time, not proof size.
//!
//! The IBSL structure is built with the same keys, promotion probability and
//! RNG seed on both sides, so the two chains have identical shape: the same
//! number of 2-to-1 merges, level for level. Only the hash and the prover
//! differ. Digests are 32 bytes either way (2 f128 elements vs 8 M31), so
//! the native proof sizes line up too.
//!
//! Also reprinted: the recorded Greyhound/LaBRADOR *total* proof sizes at
//! p = 0.15 (GREYHOUND_BATCHING.md / GREYHOUND_AGGREGATION.md), which are not
//! re-run here — their timings are void on this machine (no AVX512,
//! SDE-emulated) but the sizes are exact.

use std::time::{Duration, Instant};

use ibsl::ibsl::Ibsl;
use ibsl::stark::{flat, stwo};
use ibsl::vc::{Poseidon2FlatHashVc, RescueFlatHashVc, VectorCommitment};

const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];
const SEED: u64 = 0xC0FFEE;

/// Stwo (n_queries, pow_bits) settings to report. The first is parity with
/// the Winterfell circuit; the second trades two extra queries and 26 bits of
/// grinding for ~116-bit conjectured security.
const STWO_CONFIGS: &[(usize, u32)] = &[(28, 0), (30, 26)];

/// Grinding dominates wall time — 2^26 Poseidon252 hashes, ~2 minutes per
/// proof even with rayon across 12 cores. Every config is still measured over
/// the SAME keys, or the rows would not be comparable: chain length varies
/// per key, and a longer chain can push the trace to the next power of two.

/// (n, recorded Greyhound/LaBRADOR proof bytes at p = 0.15) — the *total*
/// self-contained proof: Greyhound eval proofs PLUS the LaBRADOR composite.
///
/// n = 1000 (5 levels) is the batched-mode row of GREYHOUND_BATCHING.md;
/// n = 10000 (6 levels) is the merged-mode row of GREYHOUND_AGGREGATION.md
/// (batching was never re-run at that size; its 6-level datapoint is 43.7 KB,
/// so this is a slight over-estimate).
///
/// NOT the "10,430 / 12,566 B" of BENCHMARKS_2026-07-17.md §9-10 — those
/// counted the eval proofs alone and omitted the LaBRADOR proof, i.e. the
/// bulk of it. See GREYHOUND_AGGREGATION.md:58.
const GREYHOUND_REFERENCE: &[(usize, usize)] = &[(1_000, 42_200), (10_000, 46_900)];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

/// Per-sample averages for one prover.
#[derive(Default)]
struct Row {
    proof_bytes: usize,
    prove: Duration,
    verify: Duration,
}

impl Row {
    fn mean(self, n: u32) -> Self {
        Row {
            proof_bytes: self.proof_bytes / n as usize,
            prove: self.prove / n,
            verify: self.verify / n,
        }
    }
}

pub fn run(p: f64, sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL flat-hash chain: Winterfell STARK vs Stwo Circle STARK — p = {p} ==");
    println!(
        "Both at 28 queries, blowup 8, no grinding (~84-bit conjectured).\n\
         Commitment (FRI/Merkle) hash: Winterfell BLAKE3, Stwo Poseidon252 —\n\
         winterfell 0.13 has no algebraic hasher for f128 (its Rescue-Prime\n\
         hashers are Goldilocks-only), so that side cannot match."
    );
    println!(
        "Winterfell: Rescue/f128 on MerkleAir, 8-step hash cycles, trace width 8.\n\
         Stwo:       Poseidon2/M31, one merge per row, trace width {} \
         (the x^5 S-box needs an x^2 helper column each — Stwo's lifted\n\
         \x20           protocol caps constraint degree at 3).",
        stwo::N_TRACE_COLUMNS
    );
    println!(
        "Greyhound row: recorded TOTAL sizes — eval proofs + the LaBRADOR composite\n\
         (SDE-emulated, sizes exact, timings void) — not re-run.\n"
    );
    println!(
        "| n | height | mean merges | wf proof | wf prove | wf verify | stwo config | stwo bits | stwo rows x cols | stwo proof | stwo prove | stwo verify | greyhound (ref) |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();

        let wf = Ibsl::<RescueFlatHashVc>::new_with_promotion(&keys, SEED, p);
        let sw = Ibsl::<Poseidon2FlatHashVc>::new_with_promotion(&keys, SEED, p);
        assert_eq!(wf.height(), sw.height(), "the two structures must have the same shape");
        let wf_sigma = wf.root_commitment();
        let sw_sigma = sw.root_commitment();

        // Evenly spread member keys — same sampling as the other drivers.
        let sample: Vec<u64> = (0..10).map(|i| keys[i * keys.len() / 10]).collect();

        let mut winterfell = Row::default();
        // Winterfell cycle count per sampled key, so the Stwo pass can assert
        // it is proving the same-shaped chain key for key.
        let mut wf_cycles: Vec<usize> = Vec::with_capacity(sample.len());

        for &k in &sample {
            let pi = wf.prove(k).expect("member proof");
            assert!(Ibsl::verify(wf.vc(), &wf_sigma, k, &pi), "native proof for {k} rejected");
            let ((proof, cycles), t) = timed(|| flat::prove_blake3(k, &pi));
            winterfell.prove += t;
            winterfell.proof_bytes += proof.to_bytes().len();
            let (ok, t) = timed(|| flat::verify_blake3(&wf_sigma, cycles, proof).is_ok());
            assert!(ok, "Winterfell proof for {k} rejected");
            winterfell.verify += t;
            wf_cycles.push(cycles);
        }
        let winterfell = winterfell.mean(sample.len() as u32);

        for &(n_queries, pow_bits) in STWO_CONFIGS {
            let config = stwo::config(n_queries, pow_bits);
            let mut circle = Row::default();
            let mut breakdown = None;
            let mut total_merges = 0usize;
            let mut max_log_rows = 0u32;
            for (idx, &k) in sample.iter().enumerate() {
                let pi = sw.prove(k).expect("member proof");
                assert!(Ibsl::verify(sw.vc(), &sw_sigma, k, &pi), "native proof for {k} rejected");
                let chain = stwo::compile(k, &pi);
                // Both circuits must be proving the same-shaped chain: one
                // Winterfell hash cycle per Stwo row.
                assert_eq!(chain.merges.len(), wf_cycles[idx], "chain shapes diverged");
                total_merges += chain.merges.len();
                max_log_rows = max_log_rows.max(stwo::log_n_rows(chain.merges.len()));

                let ((proof, shape), t) = timed(|| stwo::prove(&chain, config));
                circle.prove += t;
                circle.proof_bytes += proof.size_estimate();
                breakdown = Some(proof.size_breakdown_estimate());
                let (ok, t) = timed(|| stwo::verify(&sw_sigma, shape, proof, config).is_ok());
                assert!(ok, "Stwo proof for {k} rejected");
                circle.verify += t;
            }
            let circle = circle.mean(sample.len() as u32);
            let mean_merges = total_merges as f64 / sample.len() as f64;

            let greyhound = GREYHOUND_REFERENCE
                .iter()
                .find(|&&(gn, _)| gn == n)
                .map(|&(_, b)| format!("{b} B"))
                .unwrap_or_else(|| "—".into());
            let security = n_queries * 3 + pow_bits as usize;

            println!(
                "| {n} | {} | {mean_merges:.1} | {} B | {:.2?} | {:.2?} | {n_queries}q + {pow_bits}b grind | {security} | <={} x {} | {} B | {:.2?} | {:.2?} | {greyhound} |",
                wf.height(),
                winterfell.proof_bytes,
                winterfell.prove,
                winterfell.verify,
                1usize << max_log_rows,
                stwo::N_TRACE_COLUMNS,
                circle.proof_bytes,
                circle.prove,
                circle.verify,
            );

            if let Some(b) = breakdown {
                println!(
                    "|  ^ stwo bytes: queried trace values {} | OODS samples {} | trace decommitments {} | FRI {} |",
                    b.queries_values,
                    b.oods_samples,
                    b.trace_decommitments,
                    b.fri_samples + b.fri_decommitments,
                );
            }
        }
    }

    println!(
        "\nStwo sizes are `StarkProof::size_estimate()` (Stwo has no canonical\n\
         serialisation); Winterfell sizes are `Proof::to_bytes().len()`.\n\
         The Stwo proof is dominated by queried trace values — n_queries x\n\
         n_columns x 4 B — and so barely grows with chain length: the trace is\n\
         wide (one whole permutation per row) and only tens of rows tall.\n\
         Grinding costs 8 bytes (the nonce) and a lot of prover time: each\n\
         query it lets you drop is worth n_columns x 4 B.");
}

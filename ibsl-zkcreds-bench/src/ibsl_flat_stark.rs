//! ZK benchmark: IBSL over the Rescue flat-hash VC (`RescueFlatHashVc`),
//! with the whole membership chain re-verified inside a Winterfell STARK
//! (`ibsl::stark::flat` — the seam-free chain-fold circuit on `MerkleAir`;
//! 28 queries, blowup 8, ~96-bit conjectured, BLAKE3 FRI hasher).
//!
//! Compared against IBSL over the Greyhound/LaBRADOR lattice PCS at the same
//! promotion probability p = 0.15. Greyhound is NOT re-run: its timings are
//! void on this machine (no AVX512 — SDE-emulated), but its proof SIZES are
//! exact and recorded in GREYHOUND_BATCHING.md / GREYHOUND_AGGREGATION.md;
//! they are reprinted here as the reference row. Note the trust models differ: the STARK is
//! transparent AND zero-knowledge-shaped (verifier sees only sigma and the
//! cycle count, not k or the chain), while the recorded Greyhound numbers
//! are native openings (revealed node vectors + eval proofs), not ZK.

use std::time::{Duration, Instant};

use ibsl::ibsl::Ibsl;
use ibsl::stark::flat;
use ibsl::vc::{RescueFlatHashVc, VectorCommitment};

const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];

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

pub fn run(p: f64, sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL flat-hash (Rescue/f128) chain in a ZK-STARK vs Greyhound/LaBRADOR — p = {p} ==");
    println!("STARK: seam-free chain-fold on MerkleAir, 28 queries, blowup 8, BLAKE3 FRI.");
    println!(
        "Greyhound row: recorded TOTAL sizes — eval proofs + the LaBRADOR composite\n\
         (SDE-emulated, sizes exact, timings void) — not re-run.\n"
    );
    println!("| n | p | height | build | native proof | stark prove | stark verify | stark proof | greyhound total (ref, p=0.15) |");
    println!("|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let (s, build) = timed(|| Ibsl::<RescueFlatHashVc>::new_with_promotion(&keys, 0xC0FFEE, p));
        let sigma = s.root_commitment();

        // Evenly spread member keys — same sampling as the other drivers.
        let sample: Vec<u64> = (0..10).map(|i| keys[i * keys.len() / 10]).collect();

        let mut native_bytes = 0usize;
        let mut stark_bytes = 0usize;
        let mut prove_total = Duration::ZERO;
        let mut verify_total = Duration::ZERO;
        for &k in &sample {
            let pi = s.prove(k).expect("member proof");
            assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "native proof for {k} rejected");
            native_bytes += pi
                .iter()
                .map(|st| {
                    RescueFlatHashVc::commitment_size(&st.commitment)
                        + 8
                        + RescueFlatHashVc::witness_size(&st.witness)
                })
                .sum::<usize>();

            let ((proof, cycles), t_prove) = timed(|| flat::prove_blake3(k, &pi));
            prove_total += t_prove;
            stark_bytes += proof.to_bytes().len();

            let (ok, t_verify) = timed(|| flat::verify_blake3(&sigma, cycles, proof).is_ok());
            assert!(ok, "STARK proof for {k} rejected");
            verify_total += t_verify;
        }
        let native_bytes = native_bytes / sample.len();
        let stark_bytes = stark_bytes / sample.len();
        let prove = prove_total / sample.len() as u32;
        let verify = verify_total / sample.len() as u32;

        let greyhound = GREYHOUND_REFERENCE
            .iter()
            .find(|&&(gn, _)| gn == n)
            .map(|&(_, b)| format!("{b} B"))
            .unwrap_or_else(|| "—".into());

        println!(
            "| {n} | {p} | {} | {build:.2?} | {native_bytes} B | {prove:.2?} | {verify:.2?} | {stark_bytes} B | {greyhound} |",
            s.height()
        );
    }
}

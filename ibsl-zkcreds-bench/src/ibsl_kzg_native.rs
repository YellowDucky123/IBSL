//! Native benchmark of IBSL with the KZG10 backend (BLS12-381, ark 0.6):
//! build, prove (chain of KZG openings), verify (pairing checks per level),
//! proof size. These are the numbers the Groth16/STARK compilations are
//! compared against.

use std::time::{Duration, Instant};

use ark_serialize_v06::CanonicalSerialize;
use ibsl::ibsl::Ibsl;
use ibsl::vc::KzgVc;

/// Structural byte size of an aggregated IBSL-KZG proof: per step the
/// compressed commitment and the position (8 bytes), plus the single
/// two-point SHPLONK witness.
fn agg_proof_bytes(pi: &ibsl::ibsl::AggProof<KzgVc>) -> usize {
    let steps: usize = pi
        .steps
        .iter()
        .map(|s| {
            let mut c = Vec::new();
            s.commitment.serialize_compressed(&mut c).unwrap();
            c.len() + 8
        })
        .sum();
    let mut w = Vec::new();
    pi.witness.w.serialize_compressed(&mut w).unwrap();
    pi.witness.w_prime.serialize_compressed(&mut w).unwrap();
    steps + w.len()
}

const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

/// Structural byte size of a native IBSL-KZG proof: per step, the compressed
/// commitment, the position (8 bytes), and the compressed opening proof.
fn proof_bytes(pi: &ibsl::ibsl::Proof<KzgVc>) -> usize {
    pi.iter()
        .map(|s| {
            let mut c = Vec::new();
            s.commitment.serialize_compressed(&mut c).unwrap();
            let mut w = Vec::new();
            s.witness.serialize_compressed(&mut w).unwrap();
            c.len() + 8 + w.len()
        })
        .sum()
}

pub fn run(sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL over KZG10 (BLS12-381, ark-poly-commit), native ==");
    println!("| n | height | build | prove | verify | proof size | agg prove | agg verify | agg proof size | proof shape |");
    println!("|---|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let (s, build) = timed(|| Ibsl::<KzgVc>::new(&keys, 0xC0FFEE));
        let sigma = s.root_commitment();

        // Evenly spread member keys, same sampling as IBSL's own bench.rs.
        let sample: Vec<u64> = (0..10).map(|i| keys[i * keys.len() / 10]).collect();

        let (proofs, prove_total) = timed(|| {
            sample
                .iter()
                .map(|&k| s.prove(k).expect("member proof"))
                .collect::<Vec<_>>()
        });
        let prove = prove_total / sample.len() as u32;

        let (ok, verify_total) = timed(|| {
            sample
                .iter()
                .zip(&proofs)
                .all(|(&k, pi)| Ibsl::verify(s.vc(), &sigma, k, pi))
        });
        assert!(ok, "IBSL-KZG native verification failed");
        let verify = verify_total / sample.len() as u32;

        let bytes = proofs.iter().map(proof_bytes).sum::<usize>() / proofs.len();
        let steps = proofs.iter().map(Vec::len).sum::<usize>() / proofs.len();

        // Aggregated (SHPLONK) versions of the same membership proofs.
        let (agg_proofs, agg_prove_total) = timed(|| {
            sample
                .iter()
                .map(|&k| s.prove_agg(k).expect("member proof"))
                .collect::<Vec<_>>()
        });
        let agg_prove = agg_prove_total / sample.len() as u32;

        let (ok, agg_verify_total) = timed(|| {
            sample
                .iter()
                .zip(&agg_proofs)
                .all(|(&k, pi)| Ibsl::verify_agg(s.vc(), &sigma, k, pi))
        });
        assert!(ok, "IBSL-KZG aggregated verification failed");
        let agg_verify = agg_verify_total / sample.len() as u32;

        let agg_bytes = agg_proofs.iter().map(agg_proof_bytes).sum::<usize>() / agg_proofs.len();

        println!(
            "| {n} | {} | {build:.2?} | {prove:.2?} | {verify:.2?} | {bytes} B | {agg_prove:.2?} | {agg_verify:.2?} | {agg_bytes} B | {steps} (com, pi) pairs |",
            s.height()
        );
    }
}

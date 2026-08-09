//! Native benchmark of IBSL over the flat-hash vector commitment
//! (`FlatHashVc`): a node's commitment is ONE hash over its child slots,
//! and an opening witness is every sibling slot in order — no inner tree.
//! Run for all three hash instantiations (Poseidon, SHA-256, BLAKE3) at a
//! configurable promotion probability `p` (default 0.5).
//!
//! Versus `ibsl-merkle` the structure above the hash is identical (same
//! interval skip list, same chain of per-level openings); what changes is
//! the per-node commitment: one flat hash instead of a Merkle tree, so a
//! witness is O(fan-out) digests instead of O(log fan-out) — cheaper to
//! commit, bigger to open. Only commitment mode (`prove` / `verify`) exists
//! here: `FlatHashVc` does not implement `HashVc`, so there is no
//! sibling-hash-chain mode to report.
//!
//! Reports build, prove, verify, and native proof size. Membership only.

use std::time::{Duration, Instant};

use ibsl::ibsl::{Ibsl, Proof};
use ibsl::vc::{Blake3FlatHashVc, PoseidonFlatHashVc, Sha2FlatHashVc, VectorCommitment};

const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

/// Proof size: per level, the node commitment (one digest), an 8-byte
/// position, and the witness (every sibling slot) — sized through the
/// backend's own `commitment_size` / `witness_size`.
fn proof_bytes<V: VectorCommitment>(pi: &Proof<V>) -> usize {
    pi.iter()
        .map(|s| V::commitment_size(&s.commitment) + 8 + V::witness_size(&s.witness))
        .sum()
}

fn bench<V: VectorCommitment>(label: &str, p: f64, sizes: &[usize]) {
    println!("-- {label} flat hash --");
    println!("| n | p | height | build | prove | verify | proof |");
    println!("|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let (s, build) = timed(|| Ibsl::<V>::new_with_promotion(&keys, 0xC0FFEE, p));
        let sigma = s.root_commitment();

        // Evenly spread member keys — same sampling as the other drivers.
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
        assert!(ok, "IBSL flat-hash verification failed");
        let verify = verify_total / sample.len() as u32;

        let bytes = proofs.iter().map(proof_bytes::<V>).sum::<usize>() / proofs.len();

        println!(
            "| {n} | {p} | {} | {build:.2?} | {prove:.2?} | {verify:.2?} | {bytes} B |",
            s.height()
        );
    }
    println!();
}

pub fn run(p: f64, sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL over flat-hash VC (one hash per node, witness = all siblings) — p = {p} ==\n");
    bench::<PoseidonFlatHashVc>("Poseidon (BLS12-381 Fr)", p, sizes);
    bench::<Sha2FlatHashVc>("SHA-256", p, sizes);
    bench::<Blake3FlatHashVc>("BLAKE3", p, sizes);
}

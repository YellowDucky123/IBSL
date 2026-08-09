//! Native benchmark of IBSL over a Poseidon Merkle-tree vector commitment
//! (`PoseidonMerkleVc`: Poseidon two-to-one over BLS12-381 Fr, ark 0.6) at a
//! configurable promotion probability `p` (default 0.5 — one sibling per
//! level, the regime that lands on par with a binary Merkle tree).
//!
//! Poseidon over BLS12-381 Fr is exactly the hash zkcreds-rs's `ComTree`
//! uses, so this is an apples-to-apples native comparison against
//! `zkcreds-merkle-raw`: same hash family, same field, same 32-byte digests.
//! What differs is the STRUCTURE — IBSL's per-level chain of node openings
//! (an interval skip list, membership over arbitrary u64 keys) vs a single
//! fixed-height authentication path.
//!
//! Two IBSL proof modes are reported side by side:
//!   - **Merkle mode** (`prove_hash` / `verify_hash`): a plain sibling-hash
//!     chain — the node hashes are recomputed bottom-up, nothing but siblings
//!     and positions travels in the proof. THIS is the mode to set against
//!     the zkcreds Merkle path; at p = 0.5 it is on par with it.
//!   - **commitment mode** (`prove` / `verify`): the original proof that also
//!     carries each level's node commitment, shown for contrast.
//!
//! Reports build, prove, verify, and native proof size. Membership only.

use std::time::{Duration, Instant};

use ibsl::hashes::{Hash, PoseidonHash};
use ibsl::ibsl::{HashProof, Ibsl, Proof};
use ibsl::vc::{PoseidonMerkleVc, VectorCommitment};

const DEFAULT_SIZES: &[usize] = &[1_000, 10_000];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

/// Size of a 32-byte Poseidon digest as this backend serialises it.
fn digest_len() -> usize {
    PoseidonHash::digest_bytes(&PoseidonHash::empty()).len()
}

/// Merkle-mode proof size: per level, the authentication path's sibling
/// digests plus one byte of opened position (fan-out is small, so a position
/// never needs more). No node commitments are carried — this is the number
/// that is directly comparable to a plain Merkle path.
fn hash_proof_bytes(pi: &HashProof<PoseidonMerkleVc>) -> usize {
    pi.iter()
        .map(|s| {
            1 + s
                .witness
                .siblings
                .iter()
                .map(|d| PoseidonHash::digest_bytes(d).len())
                .sum::<usize>()
        })
        .sum()
}

/// Commitment-mode proof size: additionally carries each level's Poseidon
/// node commitment (32 B) and an 8-byte position, for contrast.
fn commit_proof_bytes(pi: &Proof<PoseidonMerkleVc>) -> usize {
    pi.iter()
        .map(|s| {
            PoseidonMerkleVc::commitment_size(&s.commitment)
                + 8
                + s.witness
                    .siblings
                    .iter()
                    .map(|d| PoseidonHash::digest_bytes(d).len())
                    .sum::<usize>()
        })
        .sum()
}

pub fn run(p: f64, sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    println!("== IBSL over Poseidon Merkle VC (BLS12-381 Fr, ark 0.6), native — p = {p} ==");
    println!("Merkle mode = sibling-hash chain (prove_hash/verify_hash); the row to");
    println!("compare against `zkcreds-merkle-raw`. digest = {} B.\n", digest_len());
    println!(
        "| n | p | height | build | prove (hash) | verify (hash) | proof (hash) | proof (commit) | siblings/proof |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");

    for &n in sizes {
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        let (s, build) = timed(|| Ibsl::<PoseidonMerkleVc>::new_with_promotion(&keys, 0xC0FFEE, p));
        let sigma = s.root_commitment();

        // Evenly spread member keys — same sampling as the other drivers.
        let sample: Vec<u64> = (0..10).map(|i| keys[i * keys.len() / 10]).collect();

        // Merkle-mode prove/verify (the headline).
        let (hash_proofs, prove_total) = timed(|| {
            sample
                .iter()
                .map(|&k| s.prove_hash(k).expect("member proof"))
                .collect::<Vec<_>>()
        });
        let prove = prove_total / sample.len() as u32;

        let (ok, verify_total) = timed(|| {
            sample
                .iter()
                .zip(&hash_proofs) // key : hash_proof tuples
                .all(|(&k, pi)| Ibsl::verify_hash(s.vc(), &sigma, k, pi))
        });
        assert!(ok, "IBSL Merkle-mode verification failed");
        let verify = verify_total / sample.len() as u32;

        let hash_bytes = hash_proofs.iter().map(hash_proof_bytes).sum::<usize>() / hash_proofs.len();
        // Total sibling hashes across the chain (the merkle-path length analogue).
        let siblings = hash_proofs
            .iter()
            .map(|pi| pi.iter().map(|s| s.witness.siblings.len()).sum::<usize>())
            .sum::<usize>()
            / hash_proofs.len();

        // Commitment-mode proof size, for contrast, on the same keys.
        let commit_proofs: Vec<Proof<PoseidonMerkleVc>> =
            sample.iter().map(|&k| s.prove(k).expect("member proof")).collect();
        let commit_bytes =
            commit_proofs.iter().map(commit_proof_bytes).sum::<usize>() / commit_proofs.len();

        println!(
            "| {n} | {p} | {} | {build:.2?} | {prove:.2?} | {verify:.2?} | {hash_bytes} B | {commit_bytes} B | {siblings} |",
            s.height()
        );
    }
}

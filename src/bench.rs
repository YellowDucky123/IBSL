//! IBSL vs plain Merkle tree benchmark, both over the Rescue (f128) hash —
//! the STARK-friendly configuration. Run with:
//!
//!     cargo run --release -- bench [n1 n2 ...]
//!
//! For each size n it benchmarks the same membership workload on
//! `Ibsl<RescueMerkleVc>` and `MerkleList<RescueHash>`: build, search,
//! prove, verify, insert, delete, native proof size — and then compiles one
//! membership proof of each into a STARK (the seam-chained IBSL circuit vs
//! the plain single-path circuit on the same `MerkleAir`) and times
//! prove/verify there too. Results are appended to `bench_results.md` in
//! the crate root.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::fields::f128::BaseElement;

use crate::hashes::{Hash, RescueHash};
use crate::ibsl::{Ibsl, Proof, Step};
use crate::merkle_list::{MerkleList, PathProof};
use crate::stark;
use crate::vc::{RescueMerkleVc, VectorCommitment};

/// The STARK's own FRI/Merkle hasher (outside the circuit).
type FriHash = Blake3_256<BaseElement>;

const DEFAULT_SIZES: &[usize] = &[100, 400, 1_000];
const RESULTS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/bench_results.md");

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

fn fmt_d(d: Duration) -> String {
    format!("{d:.2?}")
}

/// Structural byte size of a native IBSL proof: per step, the commitment,
/// the position (8 bytes), and the witness's sibling digests.
fn ibsl_proof_bytes(pi: &Proof<RescueMerkleVc>) -> usize {
    pi.iter()
        .map(|s: &Step<RescueMerkleVc>| {
            RescueMerkleVc::commitment_bytes(&s.commitment).len()
                + 8
                + s.witness
                    .siblings
                    .iter()
                    .map(|d| RescueHash::digest_bytes(d).len())
                    .sum::<usize>()
        })
        .sum()
}

/// Structural byte size of a native plain-Merkle proof: the position plus
/// the sibling digests.
fn path_proof_bytes(p: &PathProof<RescueHash>) -> usize {
    8 + p
        .siblings
        .iter()
        .map(|d| RescueHash::digest_bytes(d).len())
        .sum::<usize>()
}

/// One structure's native numbers for the report table.
struct NativeRow {
    name: &'static str,
    build: Duration,
    search: Duration,
    prove: Duration,
    verify: Duration,
    insert: Duration,
    delete: Duration,
    proof_bytes: usize,
    proof_shape: String,
}

/// One circuit's STARK numbers for the report table.
struct StarkRow {
    name: &'static str,
    path_cycles: usize,
    trace_rows: usize,
    prove: Duration,
    proof_bytes: usize,
    verify: Duration,
}

/// Evenly spread sample of member keys for prove/verify timing.
fn sample(keys: &[u64], count: usize) -> Vec<u64> {
    let count = count.min(keys.len());
    (0..count).map(|i| keys[i * keys.len() / count]).collect()
}

fn bench_ibsl(s: &mut Ibsl<RescueMerkleVc>, build: Duration, keys: &[u64], fresh: &[u64]) -> NativeRow {
    let sigma = s.root_commitment();

    // search: members and misses alternating, per-op average
    let probes: Vec<u64> = sample(keys, 100).iter().flat_map(|&k| [k, k + 1]).collect();
    let (_, search_total) = timed(|| probes.iter().filter(|&&k| s.search(k)).count());
    let search = search_total / probes.len() as u32;

    let sample_keys = sample(keys, 10);
    let (proofs, prove_total) = timed(|| {
        sample_keys
            .iter()
            .map(|&k| s.prove(k).expect("member proof"))
            .collect::<Vec<_>>()
    });
    let prove = prove_total / sample_keys.len() as u32;

    let (ok, verify_total) = timed(|| {
        sample_keys
            .iter()
            .zip(&proofs)
            .all(|(&k, pi)| Ibsl::verify(s.vc(), &sigma, k, pi))
    });
    assert!(ok, "IBSL native verification failed during bench");
    let verify = verify_total / sample_keys.len() as u32;

    let proof_bytes =
        proofs.iter().map(ibsl_proof_bytes).sum::<usize>() / proofs.len();
    let steps = proofs.iter().map(Vec::len).sum::<usize>() / proofs.len();
    let proof_shape = format!("{steps} (com, pi) pairs");

    let (_, insert_total) = timed(|| fresh.iter().for_each(|&k| s.insert(k)));
    let insert = insert_total / fresh.len() as u32;
    let (_, delete_total) = timed(|| fresh.iter().for_each(|&k| assert!(s.delete(k))));
    let delete = delete_total / fresh.len() as u32;

    NativeRow {
        name: "IBSL (Rescue Merkle VC)",
        build,
        search,
        prove,
        verify,
        insert,
        delete,
        proof_bytes,
        proof_shape,
    }
}

fn bench_merkle_list(s: &mut MerkleList<RescueHash>, build: Duration, keys: &[u64], fresh: &[u64]) -> NativeRow {
    let root = s.root();

    let probes: Vec<u64> = sample(keys, 100).iter().flat_map(|&k| [k, k + 1]).collect();
    let (_, search_total) = timed(|| probes.iter().filter(|&&k| s.search(k)).count());
    let search = search_total / probes.len() as u32;

    let sample_keys = sample(keys, 10);
    let (proofs, prove_total) = timed(|| {
        sample_keys
            .iter()
            .map(|&k| s.prove(k).expect("member proof"))
            .collect::<Vec<_>>()
    });
    let prove = prove_total / sample_keys.len() as u32;

    let (ok, verify_total) = timed(|| {
        sample_keys
            .iter()
            .zip(&proofs)
            .all(|(&k, p)| MerkleList::verify(&root, k, p))
    });
    assert!(ok, "MerkleList native verification failed during bench");
    let verify = verify_total / sample_keys.len() as u32;

    let proof_bytes =
        proofs.iter().map(path_proof_bytes).sum::<usize>() / proofs.len();
    let proof_shape = format!("1 path, {} siblings", proofs[0].siblings.len());

    let (_, insert_total) = timed(|| fresh.iter().for_each(|&k| assert!(s.insert(k))));
    let insert = insert_total / fresh.len() as u32;
    let (_, delete_total) = timed(|| fresh.iter().for_each(|&k| assert!(s.delete(k))));
    let delete = delete_total / fresh.len() as u32;

    NativeRow {
        name: "Merkle tree (Rescue)",
        build,
        search,
        prove,
        verify,
        insert,
        delete,
        proof_bytes,
        proof_shape,
    }
}

fn bench_starks(
    s: &Ibsl<RescueMerkleVc>,
    m: &MerkleList<RescueHash>,
    keys: &[u64],
) -> Vec<StarkRow> {
    let k = keys[keys.len() / 2];
    let mut rows = Vec::new();

    // IBSL chain circuit (seam register active).
    let sigma = s.root_commitment();
    let pi = s.prove(k).expect("member proof");
    let ((proof, cycles), prove) = timed(|| stark::membership::prove::<_, FriHash>(k, &pi));
    let proof_bytes = proof.to_bytes().len();
    let (ok, verify) = timed(|| stark::membership::verify::<FriHash>(&sigma, cycles, proof).is_ok());
    assert!(ok, "IBSL STARK verification failed during bench");
    rows.push(StarkRow {
        name: "IBSL chain circuit",
        path_cycles: cycles,
        trace_rows: cycles.next_power_of_two() * 8,
        prove,
        proof_bytes,
        verify,
    });

    // Plain single-path circuit (Winterfell's original merkle shape).
    let root = m.root();
    let p = m.prove(k).expect("member proof");
    let ((proof, cycles), prove) = timed(|| stark::path::prove::<FriHash>(k, &p));
    let proof_bytes = proof.to_bytes().len();
    let (ok, verify) = timed(|| stark::path::verify::<FriHash>(&root, cycles, proof).is_ok());
    assert!(ok, "Merkle-path STARK verification failed during bench");
    rows.push(StarkRow {
        name: "plain path circuit",
        path_cycles: cycles,
        trace_rows: cycles.next_power_of_two() * 8,
        prove,
        proof_bytes,
        verify,
    });

    rows
}

pub fn run(sizes: &[usize]) {
    let sizes = if sizes.is_empty() { DEFAULT_SIZES } else { sizes };

    let mut md = String::new();
    let _ = writeln!(md, "# IBSL vs plain Merkle tree — benchmark\n");
    let _ = writeln!(
        md,
        "Both structures use the Rescue hash over Winterfell's f128 — the \
         configuration the STARK circuit (`crate::stark`) arithmetises. \
         Sizes: {sizes:?}. Single-run timings (per-op figures are averages \
         over the op counts noted below).\n"
    );
    let _ = writeln!(
        md,
        "- search: avg over 200 probes (members and misses alternating)\n\
         - prove / verify / proof size: avg over 10 evenly spread member keys\n\
         - insert / delete: avg over 2 fresh (odd) keys each\n\
         - STARK: one membership proof of the middle key per circuit; \
         options 28 queries, blowup 8, ~96-bit conjectured; FRI hasher BLAKE3\n"
    );

    for &n in sizes {
        println!("=== n = {n} ===");
        let keys: Vec<u64> = (1..=n as u64).map(|i| i * 2).collect();
        // Odd keys: guaranteed non-members, for insert/delete timing.
        let fresh: Vec<u64> = (0..2).map(|i| keys[(i + 1) * n / 3] + 1).collect();

        // Build each structure once; the STARK section reuses them.
        let (mut ibsl, ibsl_build) = timed(|| Ibsl::<RescueMerkleVc>::new(&keys, 0xC0FFEE));
        let (mut list, list_build) = timed(|| MerkleList::<RescueHash>::new(&keys));

        let _ = writeln!(md, "## n = {n} keys\n");
        let _ = writeln!(md, "### Native\n");
        let _ = writeln!(
            md,
            "| structure | build | search | prove | verify | insert | delete | proof size | proof shape |"
        );
        let _ = writeln!(md, "|---|---|---|---|---|---|---|---|---|");
        for row in [
            bench_ibsl(&mut ibsl, ibsl_build, &keys, &fresh),
            bench_merkle_list(&mut list, list_build, &keys, &fresh),
        ] {
            println!(
                "  {:<24} build {:>10}  prove {:>10}  verify {:>10}  insert {:>10}",
                row.name,
                fmt_d(row.build),
                fmt_d(row.prove),
                fmt_d(row.verify),
                fmt_d(row.insert)
            );
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} | {} | {} B | {} |",
                row.name,
                fmt_d(row.build),
                fmt_d(row.search),
                fmt_d(row.prove),
                fmt_d(row.verify),
                fmt_d(row.insert),
                fmt_d(row.delete),
                row.proof_bytes,
                row.proof_shape
            );
        }

        let _ = writeln!(md, "\n### STARK (Rescue circuit, f128)\n");
        let _ = writeln!(
            md,
            "| circuit | path cycles | trace rows | prove | proof size | verify |"
        );
        let _ = writeln!(md, "|---|---|---|---|---|---|");
        for row in bench_starks(&ibsl, &list, &keys) {
            println!(
                "  {:<24} cycles {:>4}  prove {:>10}  proof {:>7} B  verify {:>10}",
                row.name,
                row.path_cycles,
                fmt_d(row.prove),
                row.proof_bytes,
                fmt_d(row.verify)
            );
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} B | {} |",
                row.name,
                row.path_cycles,
                row.trace_rows,
                fmt_d(row.prove),
                row.proof_bytes,
                fmt_d(row.verify)
            );
        }
        let _ = writeln!(md);
    }

    let _ = writeln!(
        md,
        "## Caveats\n\n\
         - This IBSL implementation recomputes ALL commitments after every \
         insert/delete (a documented simplification; the paper updates only \
         the O(log n) affected path), so IBSL updates here cost about one \
         full rebuild and do NOT show the theoretical update advantage.\n\
         - IBSL vector commitments are sized to each node's actual fan-out \
         (typically 2-4 children with p = 1/2 promotion), so a node commit \
         costs a handful of Rescue permutations and witness lengths vary \
         per node.\n\
         - The plain Merkle tree rebuilds on update too, but its rebuild is \
         one tree of ~2n hashes total, not ~2n node-trees of 1023 hashes.\n\
         - Timings are single runs on this machine, not statistics.\n"
    );

    std::fs::write(RESULTS_PATH, &md).expect("write bench_results.md");
    println!("\nresults written to {RESULTS_PATH}");
}

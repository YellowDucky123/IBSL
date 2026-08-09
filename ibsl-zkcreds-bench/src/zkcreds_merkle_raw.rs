//! zkcreds-rs's Merkle tree (`ComTree`, Poseidon two-to-one over BLS12-381
//! Fr) run RAW — native operations only, NO Groth16:
//!   - build: insert n commitments into a fixed-height sparse Merkle tree;
//!   - prove: obtain a membership auth path (in this API a path is produced
//!     by `ComTree::insert`, so proof generation == an insert);
//!   - verify: `SparseMerkleTreePath::verify` — re-hash leaf..root natively;
//!   - delete: `ComTree::remove`;
//!   - proof size: the auth path's siblings (one 32-byte Fr digest per level).
//!
//! These are the numbers to set against raw IBSL-KZG (aggregated).

use std::time::{Duration, Instant};

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, SeedableRng};
use zkcreds::{
    com_tree::ComTree,
    poseidon_utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh},
};

type AC = Bls12PoseidonCommitter;
type H = Bls12PoseidonCrh;
type Tree = ComTree<Fr, H, AC>;
type Path = zkcreds::com_tree::ComTreePath<Fr, H, AC>;

/// IBSL sizes and the matching zkcreds tree height (capacity 2^(h-1) >= n).
const DEFAULT: &[(usize, u32)] = &[(1_000, 11), (10_000, 15)];

fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let s = Instant::now();
    let o = f();
    (o, s.elapsed())
}

/// Native membership check: re-hash the path leaf->root (Poseidon) and
/// compare to the root. Params are `()` for both the identity leaf hash and
/// the Poseidon two-to-one hash.
fn verify_native(path: &Path, root: &Fr, leaf: &Fr) -> bool {
    path.path.verify(&(), &(), root, leaf).expect("verify")
}

pub fn run(sizes: &[usize]) {
    // Map requested n's to heights (smallest h with 2^(h-1) >= n); default set
    // otherwise.
    let jobs: Vec<(usize, u32)> = if sizes.is_empty() {
        DEFAULT.to_vec()
    } else {
        sizes
            .iter()
            .map(|&n| {
                let mut h = 2u32;
                while (1u64 << (h - 1)) < n as u64 {
                    h += 1;
                }
                (n, h)
            })
            .collect()
    };

    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    // One 32-byte Fr digest per level; a minimal auth path is (h-1) siblings
    // plus the leaf index.
    let digest_bytes = {
        let mut v = Vec::new();
        Fr::rand(&mut rng).serialize(&mut v).unwrap();
        v.len()
    };

    println!("== zkcreds-rs Merkle tree (Poseidon, BLS12-381) — RAW, no Groth16 ==");
    println!("| n | height | capacity | build | prove/path-gen | verify | insert | delete | proof size |");
    println!("|---|---|---|---|---|---|---|---|---|");

    for (n, h) in jobs {
        // Distinct leaves: n random Fr commitments (what a real credential set
        // would look like to the tree).
        let leaves: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        // Build: insert every leaf.
        let sample_idx: Vec<u64> = (0..10).map(|i| (i * n / 10) as u64).collect();
        let (mut tree, build) = timed(|| {
            let mut tree = Tree::empty((), h);
            for (i, leaf) in leaves.iter().enumerate() {
                let _ = tree.insert(i as u64, leaf);
            }
            tree
        });
        let root = tree.root();

        // Prove / path-gen: in this API a membership path is produced by an
        // insert of the (existing) leaf, so re-inserting the sampled leaves
        // regenerates auth paths consistent with the now-final tree.
        let mut sample_paths: Vec<Path> = Vec::new();
        let (_, prove_total) = timed(|| {
            for &i in &sample_idx {
                sample_paths.push(tree.insert(i, &leaves[i as usize]));
            }
        });
        let prove = prove_total / sample_idx.len() as u32;

        // Verify the paths natively (re-hash leaf..root) against the root.
        let (ok, verify_total) = timed(|| {
            sample_idx
                .iter()
                .zip(&sample_paths)
                .all(|(&i, p)| verify_native(p, &root, &leaves[i as usize]))
        });
        assert!(ok, "n={n}: native Merkle verification failed");
        let verify = verify_total / sample_idx.len() as u32;

        // Insert: 10 fresh leaves at unused indices near the top of the range.
        let fresh_idx: Vec<u64> = (0..10).map(|i| (n as u64) + i).collect();
        let fresh_leaves: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        assert!(fresh_idx.iter().all(|&i| i < (1u64 << (h - 1))), "fresh indices fit capacity");
        let (_, insert_total) = timed(|| {
            for (i, leaf) in fresh_idx.iter().zip(&fresh_leaves) {
                let _ = tree.insert(*i, leaf);
            }
        });
        let insert = insert_total / fresh_idx.len() as u32;

        // Delete: remove those 10.
        let (_, delete_total) = timed(|| {
            for &i in &fresh_idx {
                tree.remove(i);
            }
        });
        let delete = delete_total / fresh_idx.len() as u32;

        let proof_size = 8 + (h as usize - 1) * digest_bytes;

        println!(
            "| {n} | {h} | 2^{} | {build:.2?} | {prove:.2?} | {verify:.2?} | {insert:.2?} | {delete:.2?} | {proof_size} B |",
            h - 1
        );
    }
}

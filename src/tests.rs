use crate::ibsl::Ibsl;
use crate::merkle_list::MerkleList;
use crate::vc::{Blake3MerkleVc, KzgVc, LigeroVc, PoseidonMerkleVc, RescueMerkleVc, Sha2MerkleVc, VectorCommitment};
use ark_ec::AffineRepr;
use std::collections::BTreeSet;

fn search_correctness<V: VectorCommitment>() {
    let keys: Vec<u64> = (0..500).map(|i| i * 3).collect();
    let s = Ibsl::<V>::new(&keys, 42);
    for &k in &keys {
        assert!(s.search(k), "member {k} not found");
    }
    for k in [1, 2, 4, 100_000, 1_499] {
        assert!(!s.search(k), "non-member {k} found");
    }
}

#[test]
fn search_correctness_kzg() {
    search_correctness::<KzgVc>();
}

#[test]
fn search_correctness_merkle() {
    search_correctness::<Sha2MerkleVc>();
}

/// Search must find *every* member and reject *every* non-member, across many
/// randomizing seeds and several key layouts. A single seed / single layout (as
/// the test above used) is not enough: the tower/shortcut shape a build produces
/// depends on the coin flips, and a recompute bug once slipped through because
/// it only corrupted certain shapes. Sweeping seeds exercises many shapes.
fn search_correctness_sweep<V: VectorCommitment>(seeds: std::ops::RangeInclusive<u64>) {
    // Layouts chosen to vary tower heights and shortcut placement:
    // (member keys, sample non-members that must NOT be found).
    let layouts: Vec<(Vec<u64>, Vec<u64>)> = vec![
        // Dense contiguous — the shape that exposed the off-chain-node bug.
        ((1..=60).collect(), vec![0, 61, 1_000]),
        // Sparse even keys: odds and interior gaps are non-members.
        ((0..80).map(|i| i * 2).collect(), vec![1, 3, 79, 159, 1_000]),
        // Widely spaced: large interior gaps.
        ((1..=40).map(|i| i * 1_000).collect(), vec![0, 500, 1_500, 40_001]),
        // Degenerate small lists.
        (vec![42], vec![41, 43, 0]),
        (vec![7, 9], vec![6, 8, 10]),
    ];

    for seed in seeds {
        for (keys, non_members) in &layouts {
            let s = Ibsl::<V>::new(keys, seed);
            let missing: Vec<u64> = keys.iter().copied().filter(|&k| !s.search(k)).collect();
            assert!(
                missing.is_empty(),
                "seed {seed}, n={}: members not found: {missing:?}",
                keys.len()
            );
            for &k in non_members {
                assert!(!s.search(k), "seed {seed}: non-member {k} found");
            }
        }
    }
}

#[test]
fn search_correctness_sweep_merkle() {
    search_correctness_sweep::<Sha2MerkleVc>(1..=64);
}

#[test]
fn search_correctness_sweep_kzg() {
    // Fewer seeds: KZG setup per build is comparatively expensive.
    search_correctness_sweep::<KzgVc>(1..=6);
}

/// Pinned regression: keys 1..=50 with seed 99 built a tree whose upper-level
/// nodes sat off their level's head-chain. `recompute` used to walk head-chains
/// only, so it never refreshed those nodes' intervals and search fell into an
/// interval gap — 21 of 50 members were unreachable. Every member must be found.
#[test]
fn search_correctness_regression_seed99() {
    let keys: Vec<u64> = (1..=50).collect();
    let s = Ibsl::<Sha2MerkleVc>::new(&keys, 99);
    let missing: Vec<u64> = keys.iter().copied().filter(|&k| !s.search(k)).collect();
    assert!(missing.is_empty(), "members not found: {missing:?}");
}

#[test]
fn empty_list() {
    let s = Ibsl::<Sha2MerkleVc>::new(&[], 7);
    assert!(!s.search(0));
    assert!(!s.search(u64::MAX));
}

#[test]
fn insert_then_search() {
    let mut s = Ibsl::<Sha2MerkleVc>::new(&[10, 20, 30], 1);
    for k in [5, 15, 25, 35, 0, 40] {
        s.insert(k);
    }
    for k in [0, 5, 10, 15, 20, 25, 30, 35, 40] {
        assert!(s.search(k), "member {k} not found");
    }
    assert!(!s.search(11));
}

#[test]
fn delete_then_search() {
    let keys: Vec<u64> = (1..=50).collect();
    let mut s = Ibsl::<Sha2MerkleVc>::new(&keys, 99);
    for k in [1, 25, 50, 13] {
        assert!(s.delete(k));
        assert!(!s.search(k), "revoked {k} still found");
    }
    assert!(!s.delete(25)); // already gone
    for k in [2, 24, 26, 49] {
        assert!(s.search(k), "member {k} lost after deletes");
    }
}

fn proofs_verify<V: VectorCommitment>() {
    let keys: Vec<u64> = (1..=100).map(|i| i * 7).collect();
    let s = Ibsl::<V>::new(&keys, 5);
    let sigma = s.root_commitment();
    for &k in &keys {
        let pi = s.prove(k).expect("member must have a proof");
        assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "proof for {k} rejected");
    }
    assert!(s.prove(8).is_none()); // non-member
}

#[test]
fn proofs_verify_kzg() {
    proofs_verify::<KzgVc>();
}

#[test]
fn proofs_verify_merkle() {
    proofs_verify::<Sha2MerkleVc>();
}

#[test]
fn proofs_verify_merkle_poseidon() {
    proofs_verify::<PoseidonMerkleVc>();
}

#[test]
fn proofs_verify_merkle_blake3() {
    proofs_verify::<Blake3MerkleVc>();
}

#[test]
fn proofs_verify_merkle_rescue() {
    proofs_verify::<RescueMerkleVc>();
}

#[test]
fn proofs_verify_ligero() {
    proofs_verify::<LigeroVc>();
}

#[test]
fn tampered_proof_rejected_ligero() {
    // Scheme-independent tamperings only (wrong key / position / truncation /
    // stale root); Ligero-specific ones would poke at RS columns.
    tampered_proof_rejected::<LigeroVc>();
}

/// Scheme-independent tamperings: wrong key, wrong position, stale root.
fn tampered_proof_rejected<V: VectorCommitment>() {
    let s = Ibsl::<V>::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // proof for the wrong key
    assert!(!Ibsl::verify(s.vc(), &sigma, 20, &pi));

    // opening claimed at the wrong position
    let mut bad = pi.clone();
    bad[0].position += 1;
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // truncated chain no longer ends at the leaf commitment
    let mut bad = pi.clone();
    bad.pop();
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // stale root after an update
    let mut s2 = Ibsl::<V>::new(&[10, 20, 30, 40], 3);
    s2.insert(35);
    assert!(!Ibsl::verify(s2.vc(), &s2.root_commitment(), 30, &pi));
}

#[test]
fn tampered_proof_rejected_kzg() {
    tampered_proof_rejected::<KzgVc>();

    // Scheme-specific tamperings against the KZG group elements.
    let s = Ibsl::<KzgVc>::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // swapped child commitment breaks the opening chain
    let mut bad = pi.clone();
    bad[1].commitment = ark_poly_commit::kzg10::Commitment(ark_bls12_381::G1Affine::generator());
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // tampered opening witness
    let mut bad = pi.clone();
    bad[0].witness.w = ark_bls12_381::G1Affine::generator();
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));
}

#[test]
fn tampered_proof_rejected_merkle() {
    tampered_proof_rejected::<Sha2MerkleVc>();

    // Scheme-specific tamperings against the Merkle hashes.
    let s = Ibsl::<Sha2MerkleVc>::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // swapped child commitment breaks the opening chain
    let mut bad = pi.clone();
    bad[1].commitment = [0xAB; 32];
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // tampered sibling hash in an opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings[0][0] ^= 1;
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // truncated opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings.pop();
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));
}

#[test]
fn tampered_proof_rejected_merkle_blake3() {
    tampered_proof_rejected::<Blake3MerkleVc>();

    // Scheme-specific tamperings against the BLAKE3 hashes.
    let s = Ibsl::<Blake3MerkleVc>::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // swapped child commitment breaks the opening chain
    let mut bad = pi.clone();
    bad[1].commitment = [0xAB; 32];
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // tampered sibling hash in an opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings[0][0] ^= 1;
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // truncated opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings.pop();
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));
}

#[test]
fn tampered_proof_rejected_merkle_poseidon() {
    tampered_proof_rejected::<PoseidonMerkleVc>();

    // Scheme-specific tamperings against the Poseidon digests.
    let s = Ibsl::<PoseidonMerkleVc>::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // swapped child commitment breaks the opening chain
    let mut bad = pi.clone();
    bad[1].commitment = ark_bls12_381::Fr::from(0xAB_u64);
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // tampered sibling digest in an opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings[0] += ark_bls12_381::Fr::from(1u64);
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));

    // truncated opening witness
    let mut bad = pi.clone();
    bad[0].witness.siblings.pop();
    assert!(!Ibsl::verify(s.vc(), &sigma, 30, &bad));
}

/// The plain-Merkle baseline: search/prove/verify over members and
/// non-members, plus proofs invalidating across updates.
#[test]
fn merkle_list_correctness() {
    use crate::hashes::RescueHash;

    let keys: Vec<u64> = (1..=50).map(|i| i * 3).collect();
    let mut s = MerkleList::<RescueHash>::new(&keys);
    let root = s.root();
    for &k in &keys {
        assert!(s.search(k), "member {k} not found");
        let p = s.prove(k).expect("member proof");
        assert!(MerkleList::verify(&root, k, &p), "proof for {k} rejected");
    }
    assert!(!s.search(4));
    assert!(s.prove(4).is_none());

    // proof for the wrong key / wrong position
    let p = s.prove(3).unwrap();
    assert!(!MerkleList::verify(&root, 6, &p));
    let mut bad = p.clone();
    bad.position ^= 1;
    assert!(!MerkleList::verify(&root, 3, &bad));

    // a stale proof no longer verifies after an update
    assert!(s.insert(4));
    assert!(s.search(4));
    assert!(!MerkleList::verify(&s.root(), 3, &p));
    assert!(s.delete(4));
    assert!(!s.search(4));
    assert!(!s.delete(4)); // already gone
}

fn randomized_against_btreeset<V: VectorCommitment>() {
    let mut s = Ibsl::<V>::new(&[], 0xDEAD);
    let mut model = BTreeSet::new();
    let mut rng = 0xBEEFu64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for _ in 0..400 {
        let k = next() % 200;
        if next() % 3 == 0 {
            s.delete(k);
            model.remove(&k);
        } else {
            s.insert(k);
            model.insert(k);
        }
    }
    let sigma = s.root_commitment();
    for k in 0..200 {
        assert_eq!(s.search(k), model.contains(&k), "mismatch at key {k}");
        if model.contains(&k) {
            let pi = s.prove(k).expect("member proof");
            assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "proof for {k} rejected");
        }
    }
}

//#[test]
//fn randomized_against_btreeset_kzg() {
 //   randomized_against_btreeset::<KzgVc>();
//}

#[test]
fn randomized_against_btreeset_merkle() {
    randomized_against_btreeset::<Sha2MerkleVc>();
}

use crate::ibsl::Ibsl;
use ark_ec::AffineRepr;
use std::collections::BTreeSet;

#[test]
fn search_correctness() {
    let keys: Vec<u64> = (0..500).map(|i| i * 3).collect();
    let s = Ibsl::new(&keys, 42);
    for &k in &keys {
        assert!(s.search(k), "member {k} not found");
    }
    for k in [1, 2, 4, 100_000, 1_499] {
        assert!(!s.search(k), "non-member {k} found");
    }
}

#[test]
fn empty_list() {
    let s = Ibsl::new(&[], 7);
    assert!(!s.search(0));
    assert!(!s.search(u64::MAX));
}

#[test]
fn insert_then_search() {
    let mut s = Ibsl::new(&[10, 20, 30], 1);
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
    let mut s = Ibsl::new(&keys, 99);
    for k in [1, 25, 50, 13] {
        assert!(s.delete(k));
        assert!(!s.search(k), "revoked {k} still found");
    }
    assert!(!s.delete(25)); // already gone
    for k in [2, 24, 26, 49] {
        assert!(s.search(k), "member {k} lost after deletes");
    }
}

#[test]
fn proofs_verify() {
    let keys: Vec<u64> = (1..=100).map(|i| i * 7).collect();
    let s = Ibsl::new(&keys, 5);
    let sigma = s.root_commitment();
    for &k in &keys {
        let pi = s.prove(k).expect("member must have a proof");
        assert!(Ibsl::verify(&sigma, k, &pi), "proof for {k} rejected");
    }
    assert!(s.prove(8).is_none()); // non-member
}

#[test]
fn tampered_proof_rejected() {
    let s = Ibsl::new(&[10, 20, 30, 40], 3);
    let sigma = s.root_commitment();
    let pi = s.prove(30).unwrap();

    // proof for the wrong key
    assert!(!Ibsl::verify(&sigma, 20, &pi));

    // tampered metadata claim
    let mut bad = pi.clone();
    bad[0].level += 1;
    assert!(!Ibsl::verify(&sigma, 30, &bad));

    // swapped child commitment breaks the opening chain
    let mut bad = pi.clone();
    bad[0].child = Some(ark_poly_commit::kzg10::Commitment(
        ark_bls12_381::G1Affine::generator(),
    ));
    assert!(!Ibsl::verify(&sigma, 30, &bad));

    // tampered opening witness
    let mut bad = pi.clone();
    bad[0].meta_witness[0].w = ark_bls12_381::G1Affine::generator();
    assert!(!Ibsl::verify(&sigma, 30, &bad));

    // stale root after an update
    let mut s2 = Ibsl::new(&[10, 20, 30, 40], 3);
    s2.insert(35);
    assert!(!Ibsl::verify(&s2.root_commitment(), 30, &pi));
}

#[test]
fn randomized_against_btreeset() {
    let mut s = Ibsl::new(&[], 0xDEAD);
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
            assert!(Ibsl::verify(&sigma, k, &pi), "proof for {k} rejected");
        }
    }
}

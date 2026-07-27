//! Correctness of the Greyhound backend: positional opening, commitment
//! binding, and the aggregated (one composite per proof, not per node) path.
//!
//! AVX512-only — run the built test binary under Intel SDE, e.g.
//!   cargo test --features greyhound --test greyhound --no-run
//!   $SDE -icx -- ./target/debug/deps/greyhound-<hash>
#![cfg(feature = "greyhound")]

use ibsl::field::NodeDigest;
use ibsl::ibsl::Ibsl;
use ibsl::vc::greyhound::{set_quiet, GreyhoundField};
use ibsl::vc::{GreyhoundVc, VectorCommitment};

#[test]
fn opens_a_slot_without_revealing_the_vector() {
    set_quiet(true);
    let vc = GreyhoundVc::setup(4);
    let values: Vec<GreyhoundField> = [7u128, 11, 13, 999_983]
        .iter()
        .map(|&v| GreyhoundField::from_u128(v))
        .collect();
    let (c, opener) = vc.commit(&values);

    for (i, &v) in values.iter().enumerate() {
        let w = vc.open(&opener, i);
        assert!(vc.check(&c, i, v, &w), "slot {i} failed to verify");
        // Wrong value at the right slot must be rejected.
        assert!(!vc.check(&c, i, GreyhoundField::from_u128(4), &w) || v.0 == 4);
    }
}

#[test]
fn opening_is_bound_to_its_commitment() {
    set_quiet(true);
    let vc = GreyhoundVc::setup(4);
    let a: Vec<GreyhoundField> = [1u128, 2, 3, 4].iter().map(|&v| GreyhoundField::from_u128(v)).collect();
    let b: Vec<GreyhoundField> = [9u128, 8, 7, 6].iter().map(|&v| GreyhoundField::from_u128(v)).collect();
    let (ca, _) = vc.commit(&a);
    let (_cb, ob) = vc.commit(&b);

    // A perfectly valid opening of b's slot 0, offered against a's commitment.
    let w = vc.open(&ob, 0);
    assert!(!vc.check(&ca, 0, b[0], &w), "opening was accepted under a foreign commitment");
}

#[test]
fn wrong_slot_is_rejected() {
    set_quiet(true);
    let vc = GreyhoundVc::setup(4);
    let values: Vec<GreyhoundField> = [5u128, 6, 7, 8].iter().map(|&v| GreyhoundField::from_u128(v)).collect();
    let (c, opener) = vc.commit(&values);
    let w = vc.open(&opener, 2);
    assert!(vc.check(&c, 2, values[2], &w));
    assert!(!vc.check(&c, 1, values[2], &w), "opening of slot 2 accepted as slot 1");
}

#[test]
fn ibsl_proofs_verify_in_both_modes() {
    set_quiet(true);
    let keys: Vec<u64> = (1..=12u64).map(|i| i * 3).collect();
    let s = Ibsl::<GreyhoundVc>::new_with_promotion(&keys, 0xC0FFEE, 0.3);
    let sigma = s.root_commitment();

    for &k in &[keys[0], keys[keys.len() / 2], keys[keys.len() - 1]] {
        let pi = s.prove(k).expect("member proof");
        assert!(Ibsl::verify(s.vc(), &sigma, k, &pi), "per-node proof for {k} failed");

        let agg = s.prove_agg(k).expect("aggregated member proof");
        assert!(Ibsl::verify_agg(s.vc(), &sigma, k, &agg), "aggregated proof for {k} failed");
    }

    // A non-member must not produce a proof.
    assert!(s.prove(keys[0] + 1).is_none());
}

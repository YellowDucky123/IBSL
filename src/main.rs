mod hashes;
mod ibsl;
#[cfg(test)]
mod tests;
mod vc;

use std::time::Instant;

use ibsl::Ibsl;
use vc::{Blake3MerkleVc, KzgVc, PoseidonMerkleVc, Sha2MerkleVc, VectorCommitment};

fn hex<V: VectorCommitment>(c: &V::Commitment) -> String {
    V::commitment_bytes(c).iter().map(|b| format!("{b:02x}")).collect()
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, std::time::Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}

fn demo<V: VectorCommitment>() {
    // Issue 20 credentials (keys stand in for commitments com_i).
    let keys: Vec<u64> = (1..=20).map(|i| i * 10).collect();
    let (mut s, t) = timed(|| Ibsl::<V>::new(&keys, 0xC0FFEE));
    println!(
        "IBSL over {} credentials, height {}  [built in {:.2?}]",
        keys.len(),
        s.height(),
        t
    );
    println!("sigma = {}", hex::<V>(&s.root_commitment()));

    let (found, t) = timed(|| s.search(70));
    println!("\nSearch(S, 70)  = {found}  [{t:.2?}]");
    let (found, t) = timed(|| s.search(75));
    println!("Search(S, 75)  = {found}  [{t:.2?}]");

    // Issuance: Insert(S, com_new) -> new root commitment sigma'.
    let (_, t) = timed(|| s.insert(75));
    println!("\nafter Insert(S, 75)  [{t:.2?}]:");
    println!("sigma' = {}", hex::<V>(&s.root_commitment()));
    println!("Search(S, 75)  = {}", s.search(75));

    // Membership proof: Prove(S, com) -> pi, checked against sigma'.
    let sigma = s.root_commitment();
    let (pi, t) = timed(|| s.prove(75).expect("75 is a member"));
    println!("\npi for 75: {} steps  [Prove: {t:.2?}]", pi.len());
    let (ok, t) = timed(|| Ibsl::verify(s.vc(), &sigma, 75, &pi));
    println!("Verify(sigma, 75, pi) = {ok}  [{t:.2?}]");

    // Revocation: Delete(S, com) actually removes the node...
    let (_, t) = timed(|| s.delete(75));
    println!("\nafter Delete(S, 75) (revocation)  [{t:.2?}]:");
    println!("Search(S, 75)  = {}", s.search(75));
    // ...and the old proof no longer verifies against the new root.
    let sigma2 = s.root_commitment();
    let (ok, t) = timed(|| Ibsl::verify(s.vc(), &sigma2, 75, &pi));
    println!("old pi against new sigma = {ok}  [{t:.2?}]");
}

fn timed_demo<V: VectorCommitment>(name: &str) {
    println!("==== IBSL over {name} vector commitments ====\n");
    let start = Instant::now();
    demo::<V>();
    println!("\nelapsed: {:.2?}\n", start.elapsed());
}

fn main() {
    timed_demo::<KzgVc>("KZG10");
    timed_demo::<Sha2MerkleVc>("SHA-256 Merkle");
    timed_demo::<Blake3MerkleVc>("BLAKE3 Merkle");
    timed_demo::<PoseidonMerkleVc>("Poseidon Merkle");
}

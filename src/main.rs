mod bench;
mod field;
mod hashes;
mod ibsl;
mod merkle_list;
mod stark;
#[cfg(test)]
mod tests;
mod vc;

use std::time::Instant;

use ibsl::Ibsl;
use vc::{
    Blake3MerkleVc, KzgVc, LigeroVc, PoseidonMerkleVc, RescueMerkleVc, Sha2MerkleVc,
    VectorCommitment,
};

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

/// Rescue backend + STARK: a real IBSL proof re-verified inside a STARK,
/// so the verifier sees only sigma (and the path length), not k or pi.
fn stark_demo() {
    use winterfell::crypto::hashers::Blake3_256;
    use winterfell::math::fields::f128::BaseElement;
    type H = Blake3_256<BaseElement>;

    println!("==== IBSL membership as a STARK (Rescue over f128) ====\n");
    let keys: Vec<u64> = (1..=20).map(|i| i * 10).collect();
    let (s, t) = timed(|| Ibsl::<RescueMerkleVc>::new(&keys, 0xC0FFEE));
    println!("IBSL over {} credentials, height {}  [built in {:.2?}]", keys.len(), s.height(), t);
    let sigma = s.root_commitment();
    println!("sigma = {}", hex::<RescueMerkleVc>(&sigma));

    let pi = s.prove(70).expect("70 is a member");
    println!("\npi for 70: {} (com, pi_com) pairs", pi.len());
    println!("native Verify(sigma, 70, pi) = {}", Ibsl::verify(s.vc(), &sigma, 70, &pi));

    let ((proof, cycles), t) = timed(|| stark::membership::prove::<_, H>(70, &pi));
    println!(
        "\nSTARK: {} path cycles, proof {} bytes  [Prove: {t:.2?}]",
        cycles,
        proof.to_bytes().len()
    );
    let (ok, t) = timed(|| stark::membership::verify::<H>(&sigma, cycles, proof).is_ok());
    println!("STARK Verify(sigma, proof) = {ok}  [{t:.2?}]");
    println!();
}

fn main() {
    // `cargo run --release -- bench [n1 n2 ...]`: IBSL vs plain Merkle tree.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("bench") {
        let sizes: Vec<usize> = args[1..]
            .iter()
            .map(|a| a.parse().expect("bench sizes must be integers"))
            .collect();
        bench::run(&sizes);
        return;
    }

    timed_demo::<KzgVc>("KZG10");
    timed_demo::<Sha2MerkleVc>("SHA-256 Merkle");
    timed_demo::<Blake3MerkleVc>("BLAKE3 Merkle");
    timed_demo::<PoseidonMerkleVc>("Poseidon Merkle");
    timed_demo::<LigeroVc>("Ligero (RS + SHA-256 columns)");
    timed_demo::<RescueMerkleVc>("Rescue (f128) Merkle");
    stark_demo();
}

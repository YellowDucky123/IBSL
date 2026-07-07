mod ibsl;
mod kzg;
#[cfg(test)]
mod tests;

use ark_serialize::CanonicalSerialize;
use ibsl::Ibsl;
use kzg::Commitment;

fn hex(c: &Commitment) -> String {
    let mut bytes = Vec::new();
    c.serialize_compressed(&mut bytes).expect("serialization");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // Issue 20 credentials (keys stand in for commitments com_i).
    let keys: Vec<u64> = (1..=20).map(|i| i * 10).collect();
    let mut s = Ibsl::new(&keys, 0xC0FFEE);
    println!("IBSL over {} credentials, height {}", keys.len(), s.height());
    println!("sigma = {}", hex(&s.root_commitment()));

    println!("\nSearch(S, 70)  = {}", s.search(70));
    println!("Search(S, 75)  = {}", s.search(75));

    // Issuance: Insert(S, com_new) -> new root commitment sigma'.
    s.insert(75);
    println!("\nafter Insert(S, 75):");
    println!("sigma' = {}", hex(&s.root_commitment()));
    println!("Search(S, 75)  = {}", s.search(75));

    // Membership proof: Prove(S, com) -> pi, checked against sigma'.
    let sigma = s.root_commitment();
    let pi = s.prove(75).expect("75 is a member");
    println!("\npi for 75: {} steps", pi.len());
    println!("Verify(sigma, 75, pi) = {}", Ibsl::verify(&sigma, 75, &pi));

    // Revocation: Delete(S, com) actually removes the node...
    s.delete(75);
    println!("\nafter Delete(S, 75) (revocation):");
    println!("Search(S, 75)  = {}", s.search(75));
    // ...and the old proof no longer verifies against the new root.
    let sigma2 = s.root_commitment();
    println!(
        "old pi against new sigma = {}",
        Ibsl::verify(&sigma2, 75, &pi)
    );
}

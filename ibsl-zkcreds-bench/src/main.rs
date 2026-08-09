//! Benchmark harness: zkcreds-rs (Groth16, BLS12-381) vs IBSL-KZG.
//!
//! Subcommands:
//!   zkcreds-merkle [h1 h2 ...]   Groth16 Merkle membership (zkcreds circuit,
//!                                Poseidon, driven via linkg16). Default
//!                                heights: 11 15 18 32 (capacity 2^(h-1)).
//!   zkcreds-merkle-raw [n ...]   The same zkcreds Merkle tree run natively
//!                                (no Groth16): build/prove/verify/insert/
//!                                delete + auth-path size. Default: 1000 10000.
//!   ibsl-kzg [n1 n2 ...]         IBSL with the KZG backend, native ops
//!                                (BLS12-381, ark 0.6). Default sizes:
//!                                1000 10000.
//!   kzg-groth16 [n1 n2 ...]      IBSL-KZG membership chain re-verified
//!                                inside linkg16's Groth16 over the
//!                                MNT4-298/MNT6-298 cycle.
//!   ibsl-flat-stwo [p] [n ...]   The flat-hash membership chain proven in
//!                                BOTH Winterfell (Rescue/f128) and Stwo's
//!                                Circle STARK (Poseidon2/M31), side by side.
//!                                Needs --features stwo and a nightly rustc.
//!   ibsl-flat-hash [p] [n ...]   IBSL with the flat-hash backend (one hash
//!                                per node, witness = all siblings), native,
//!                                for Poseidon / SHA-256 / BLAKE3. Same arg
//!                                convention as ibsl-merkle; default p 0.5.

mod ibsl_flat_hash;
mod ibsl_flat_stark;
#[cfg(feature = "stwo")]
mod ibsl_flat_stwo;
#[cfg(feature = "greyhound")]
mod ibsl_greyhound;
mod ibsl_kzg_native;
mod ibsl_merkle;
mod kzg_groth16;
mod probe;
mod zkcreds_merkle;
mod zkcreds_merkle_raw;

fn parse_usizes(args: &[String]) -> Vec<usize> {
    args.iter()
        .map(|a| a.parse().expect("arguments must be integers"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("zkcreds-merkle") => zkcreds_merkle::run(&parse_usizes(&args[1..])),
        Some("zkcreds-merkle-raw") => zkcreds_merkle_raw::run(&parse_usizes(&args[1..])),
        Some("ibsl-kzg") => ibsl_kzg_native::run(&parse_usizes(&args[1..])),
        Some("ibsl-merkle") => {
            // ibsl-merkle [p] [n1 n2 ...] — a leading arg containing '.' is
            // the promotion probability p (default 0.5, the on-par-with-a-
            // binary-Merkle-tree regime); the rest are sizes.
            let rest = &args[1..];
            let (p, nums) = match rest.first() {
                Some(first) if first.contains('.') => {
                    (first.parse().expect("p must be a float"), &rest[1..])
                }
                _ => (0.5, rest),
            };
            ibsl_merkle::run(p, &parse_usizes(nums));
        }
        Some("ibsl-flat-stark") => {
            // ibsl-flat-stark [p] [n1 n2 ...] — flat-hash IBSL chain proven
            // in a ZK-STARK, sizes set against the recorded Greyhound row.
            // Default p 0.15 to match the Greyhound reference numbers.
            let rest = &args[1..];
            let (p, nums) = match rest.first() {
                Some(first) if first.contains('.') => {
                    (first.parse().expect("p must be a float"), &rest[1..])
                }
                _ => (0.15, rest),
            };
            ibsl_flat_stark::run(p, &parse_usizes(nums));
        }
        #[cfg(feature = "stwo")]
        Some("ibsl-flat-stwo") => {
            // ibsl-flat-stwo [p] [n1 n2 ...] — the same flat-hash chain proven
            // in Winterfell and in Stwo, side by side. Default p 0.15 to match
            // the ibsl-flat-stark row.
            let rest = &args[1..];
            let (p, nums) = match rest.first() {
                Some(first) if first.contains('.') => {
                    (first.parse().expect("p must be a float"), &rest[1..])
                }
                _ => (0.15, rest),
            };
            ibsl_flat_stwo::run(p, &parse_usizes(nums));
        }
        Some("ibsl-flat-hash") => {
            // ibsl-flat-hash [p] [n1 n2 ...] — same argument convention as
            // ibsl-merkle: a leading arg containing '.' is the promotion
            // probability p (default 0.5), the rest are sizes.
            let rest = &args[1..];
            let (p, nums) = match rest.first() {
                Some(first) if first.contains('.') => {
                    (first.parse().expect("p must be a float"), &rest[1..])
                }
                _ => (0.5, rest),
            };
            ibsl_flat_hash::run(p, &parse_usizes(nums));
        }
        #[cfg(feature = "greyhound")]
        Some("ibsl-greyhound") => {
            let rest = &args[1..];
            let (p, nums) = match rest.first() {
                Some(first) if first.contains('.') => {
                    (first.parse().expect("p must be a float"), &rest[1..])
                }
                _ => (0.15, rest),
            };
            ibsl_greyhound::run(p, &parse_usizes(nums));
        }
        Some("probe") => probe::run(),
        Some("kzg-selftest") => {
            ibsl::vc::mnt_kzg::self_test();
            println!("native MNT4-298 KZG IBSL: ok");
        }
        Some("kzg-groth16") => kzg_groth16::run(&parse_usizes(&args[1..])),
        _ => {
            eprintln!("usage: ibsl-zkcreds-bench <zkcreds-merkle|ibsl-kzg> [args...]");
            std::process::exit(1);
        }
    }
}

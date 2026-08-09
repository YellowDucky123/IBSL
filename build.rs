// Compiles the labrador/greyhound C sources plus our shim into a static lib,
// backing `vc::greyhound`, but ONLY when the `greyhound` feature is on. The
// code requires AVX512 (+VAES), so it is built with -march=icelake-server and
// can only run on AVX512 hardware or under Intel SDE. Without the feature, the
// crate builds as pure Rust and this script does nothing.

fn main() {
    if std::env::var("CARGO_FEATURE_GREYHOUND").is_err() {
        return;
    }

    let dir = "/home/kelvin/labrador";
    let c_sources = [
        "greyhound_shim.c", "greyhound_batch.c", "pack.c", "greyhound.c", "dachshund.c", "chihuahua.c",
        "labrador.c", "data.c", "jlproj.c", "polx.c", "poly.c", "polz.c",
        "sparsemat.c", "aesctr.c", "fips202.c", "randombytes.c", "cpucycles.c",
    ];
    let asm_sources = ["ntt.S", "invntt.S"];

    let mut build = cc::Build::new();
    build
        .include(dir)
        .flag("-std=c2x")
        .flag("-march=icelake-server")
        .flag("-mtune=icelake-server")
        .flag("-O2")
        .flag("-fwrapv")
        .flag("-Wno-unused-function")
        .warnings(false);
    for f in c_sources {
        build.file(format!("{dir}/{f}"));
        println!("cargo:rerun-if-changed={dir}/{f}");
    }
    for f in asm_sources {
        build.file(format!("{dir}/{f}"));
        println!("cargo:rerun-if-changed={dir}/{f}");
    }
    build.compile("greyhound_shim");

    println!("cargo:rustc-link-lib=m");
}

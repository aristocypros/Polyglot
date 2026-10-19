fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // On Linux (ELF), export `#[no_mangle] extern "C" fn C_GetFunctionList` into the dynamic
    // symbol table (.dynsym) of test executables so `cryptoki::context::Pkcs11::new_from_self()`
    // (`dlopen(NULL)` + `dlsym("C_GetFunctionList")`) resolves the in-process PKCS#11 harness.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "linux" {
        println!("cargo:rustc-link-arg=-Wl,--export-dynamic");
    }
}

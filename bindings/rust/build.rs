use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Get the directory where ZQUIC is built
    let zquic_dir = env::var("ZQUIC_DIR").unwrap_or_else(|_| "../../".to_string());
    
    println!("cargo:rerun-if-changed={}", zquic_dir);
    println!("cargo:rerun-if-changed={}/src", zquic_dir);
    println!("cargo:rerun-if-changed={}/build.zig", zquic_dir);
    
    // Build ZQUIC library first
    build_zquic(&zquic_dir);
    
    // Tell cargo to look for shared libraries in the ZQUIC build output
    let lib_path = format!("{}/zig-out/lib", zquic_dir);
    if std::path::Path::new(&lib_path).exists() {
        println!("cargo:rustc-link-search=native={}", lib_path);
        println!("cargo:rustc-link-lib=static=zquic");
    } else {
        println!("cargo:warning=ZQUIC library not found, bindings will not link");
    }
    
    // Link required system libraries
    println!("cargo:rustc-link-lib=c");
    println!("cargo:rustc-link-lib=m");
    
    // Generate C headers
    generate_headers(&zquic_dir);
    
    // Generate Rust bindings for each header
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    
    // Core ZQUIC bindings
    generate_bindings(&zquic_dir, "zquic.h", &out_path, "zquic_bindings.rs");
    
    // ZCrypto bindings
    if cfg!(feature = "post-quantum") {
        generate_bindings(&zquic_dir, "zcrypto.h", &out_path, "zcrypto_bindings.rs");
    }
    
    // GhostBridge bindings
    if cfg!(feature = "ghostbridge") {
        generate_bindings(&zquic_dir, "ghostbridge.h", &out_path, "ghostbridge_bindings.rs");
    }
    
    // Services bindings
    if cfg!(feature = "services") {
        generate_bindings(&zquic_dir, "zquic_services.h", &out_path, "services_bindings.rs");
    }
}

fn build_zquic(zquic_dir: &str) {
    // For now, just check if zig is available and headers exist
    // In production, this would actually build the library
    let zig_check = Command::new("zig")
        .args(&["version"])
        .output();
    
    match zig_check {
        Ok(output) if output.status.success() => {
            println!("Found Zig: {}", String::from_utf8_lossy(&output.stdout).trim());
        }
        _ => {
            println!("cargo:warning=Zig not found, skipping library build");
            return;
        }
    }
    
    // Check if include directory exists
    let include_path = format!("{}/include", zquic_dir);
    if !std::path::Path::new(&include_path).exists() {
        println!("cargo:warning=Include directory not found, generating headers");
        generate_headers(zquic_dir);
    }
}

fn generate_headers(zquic_dir: &str) {
    let output = Command::new("zig")
        .args(&["run", "src/ffi/header_gen.zig", "--", "--output-dir", "include"])
        .current_dir(zquic_dir)
        .output()
        .expect("Failed to generate C headers");
    
    if !output.status.success() {
        panic!(
            "Failed to generate C headers:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn generate_bindings(zquic_dir: &str, header_name: &str, out_path: &PathBuf, output_name: &str) {
    let header_path = format!("{}/include/{}", zquic_dir, header_name);
    
    // Check if header exists
    if !std::path::Path::new(&header_path).exists() {
        println!("cargo:warning=Header {} not found, creating minimal bindings", header_name);
        create_minimal_bindings(out_path, output_name);
        return;
    }
    
    let mut builder = bindgen::Builder::default()
        .header(&header_path)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("zquic_.*")
        .allowlist_function("zcrypto_.*")
        .allowlist_function("ghostbridge_.*")
        .allowlist_function("wraith_.*")
        .allowlist_function("cns_.*")
        .allowlist_type("ZQuic.*")
        .allowlist_type("ZCrypto.*")
        .allowlist_type("Ghost.*")
        .allowlist_type("Grpc.*")
        .allowlist_type("Wraith.*")
        .allowlist_type("Cns.*")
        .allowlist_type("Dns.*")
        .allowlist_var("ZQUIC_.*")
        .allowlist_var("ZCRYPTO_.*")
        .allowlist_var("GRPC_.*")
        .allowlist_var("WRAITH_.*")
        .allowlist_var("DNS_.*")
        .allowlist_var("ED25519_.*")
        .allowlist_var("SECP256K1_.*")
        .allowlist_var("BLAKE3_.*")
        .allowlist_var("SHA256_.*")
        .allowlist_var("ML_KEM_.*")
        .allowlist_var("SLH_DSA_.*")
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .derive_eq(true)
        .derive_partialeq(true)
        .derive_hash(true)
        .layout_tests(false)
        .generate_comments(true);
    
    // Add feature-specific includes
    if header_name == "zcrypto.h" {
        builder = builder.clang_arg("-DZCRYPTO_FEATURE_ENABLED");
    }
    
    match builder.generate() {
        Ok(bindings) => {
            bindings
                .write_to_file(out_path.join(output_name))
                .expect(&format!("Couldn't write bindings for {}!", header_name));
        }
        Err(e) => {
            println!("cargo:warning=Failed to generate bindings for {}: {}", header_name, e);
            create_minimal_bindings(out_path, output_name);
        }
    }
}

fn create_minimal_bindings(out_path: &PathBuf, output_name: &str) {
    let minimal_content = r#"
// Minimal bindings for compilation
#![allow(dead_code)]

pub const ZQUIC_OK: i32 = 0;
pub const ZQUIC_ERROR: i32 = -1;
pub const ZQUIC_INVALID_PARAM: i32 = -2;
pub const ZQUIC_TIMEOUT: i32 = -3;
pub const ZQUIC_CONNECTION_REFUSED: i32 = -4;
pub const ZQUIC_CRYPTO_ERROR: i32 = -5;
pub const ZQUIC_PROTOCOL_ERROR: i32 = -6;

pub const ED25519_PUBLIC_KEY_SIZE: u32 = 32;
pub const ED25519_PRIVATE_KEY_SIZE: u32 = 32;
pub const ED25519_SIGNATURE_SIZE: u32 = 64;

pub const ML_KEM_768_PUBLIC_KEY_SIZE: u32 = 1184;
pub const ML_KEM_768_PRIVATE_KEY_SIZE: u32 = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: u32 = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: u32 = 32;

pub const SLH_DSA_128F_PUBLIC_KEY_SIZE: u32 = 32;
pub const SLH_DSA_128F_PRIVATE_KEY_SIZE: u32 = 64;
pub const SLH_DSA_128F_SIGNATURE_SIZE: u32 = 17088;

// Placeholder function for testing
extern "C" {
    pub fn zquic_test_add(a: i32, b: i32) -> i32;
    pub fn zquic_test_echo(input: *const i8) -> *const i8;
}
"#;
    
    std::fs::write(out_path.join(output_name), minimal_content)
        .expect("Failed to write minimal bindings");
}

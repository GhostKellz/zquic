
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

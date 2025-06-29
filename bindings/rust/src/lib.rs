//! ZQUIC-sys: Low-level FFI bindings for ZQUIC post-quantum QUIC library
//!
//! This crate provides automatically generated FFI bindings for the ZQUIC library,
//! enabling Rust services (ghostd, walletd) to use ZQUIC for high-performance
//! post-quantum QUIC transport.
//!
//! ## Features
//!
//! - `post-quantum`: Enable post-quantum cryptographic functions (default)
//! - `services`: Enable high-level service bindings (Wraith, CNS)
//! - `ghostbridge`: Enable gRPC-over-QUIC transport bindings
//! - `wraith`: Enable reverse proxy service bindings
//! - `cns`: Enable DNS-over-QUIC resolver bindings
//!
//! ## Example
//!
//! ```no_run
//! use zquic_sys::*;
//! use std::ffi::CString;
//! use std::ptr;
//!
//! unsafe {
//!     let config = ZQuicConfig {
//!         address: CString::new("0.0.0.0").unwrap().into_raw(),
//!         port: 8080,
//!         max_connections: 1000,
//!         timeout_ms: 30000,
//!         enable_post_quantum: true,
//!         cert_path: ptr::null(),
//!         key_path: ptr::null(),
//!     };
//!     
//!     let ctx = zquic_init(&config);
//!     if !ctx.is_null() {
//!         // Use ZQUIC context...
//!         zquic_destroy(ctx);
//!     }
//! }
//! ```

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::os::raw::{c_char, c_int};

/// Re-export libc types for convenience
pub use libc::{size_t, ssize_t};

// ===== CORE FFI BINDINGS =====

// Core constants
pub const ZQUIC_OK: c_int = 0;
pub const ZQUIC_ERROR: c_int = -1;
pub const ZQUIC_INVALID_PARAM: c_int = -2;
pub const ZQUIC_TIMEOUT: c_int = -3;
pub const ZQUIC_CONNECTION_REFUSED: c_int = -4;
pub const ZQUIC_CRYPTO_ERROR: c_int = -5;
pub const ZQUIC_PROTOCOL_ERROR: c_int = -6;

// Crypto constants
pub const ED25519_PUBLIC_KEY_SIZE: u32 = 32;
pub const ED25519_PRIVATE_KEY_SIZE: u32 = 32;
pub const ED25519_SIGNATURE_SIZE: u32 = 64;

pub const SECP256K1_PUBLIC_KEY_SIZE: u32 = 33;
pub const SECP256K1_PRIVATE_KEY_SIZE: u32 = 32;
pub const SECP256K1_SIGNATURE_SIZE: u32 = 64;

pub const BLAKE3_HASH_SIZE: u32 = 32;
pub const SHA256_HASH_SIZE: u32 = 32;

// Post-quantum constants
pub const ML_KEM_768_PUBLIC_KEY_SIZE: u32 = 1184;
pub const ML_KEM_768_PRIVATE_KEY_SIZE: u32 = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: u32 = 1088;
pub const ML_KEM_768_SHARED_SECRET_SIZE: u32 = 32;

pub const SLH_DSA_128F_PUBLIC_KEY_SIZE: u32 = 32;
pub const SLH_DSA_128F_PRIVATE_KEY_SIZE: u32 = 64;
pub const SLH_DSA_128F_SIGNATURE_SIZE: u32 = 17088;

// GhostBridge constants
#[cfg(feature = "ghostbridge")]
pub const GRPC_OK: u32 = 0;

// Opaque types
#[repr(C)]
pub struct ZQuicContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZQuicConnection {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ZQuicStream {
    _private: [u8; 0],
}

#[cfg(feature = "ghostbridge")]
#[repr(C)]
pub struct GhostBridge {
    _private: [u8; 0],
}

#[cfg(feature = "ghostbridge")]
#[repr(C)]
pub struct GrpcConnection {
    _private: [u8; 0],
}

#[cfg(feature = "ghostbridge")]
#[repr(C)]
pub struct GrpcResponse {
    _private: [u8; 0],
}

#[cfg(feature = "ghostbridge")]
pub type GrpcStatusCode = u32;

// Configuration structures
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZQuicConfig {
    pub address: *const c_char,
    pub port: u16,
    pub max_connections: u32,
    pub timeout_ms: u32,
    pub enable_post_quantum: bool,
    pub cert_path: *const c_char,
    pub key_path: *const c_char,
}

#[cfg(feature = "ghostbridge")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GhostBridgeConfig {
    pub address: *const c_char,
    pub port: u16,
    pub max_connections: u32,
    pub cert_path: *const c_char,
    pub key_path: *const c_char,
    pub enable_compression: bool,
    pub enable_post_quantum: bool,
}

// FFI function declarations
unsafe extern "C" {
    // Core ZQUIC functions
    pub fn zquic_init(config: *const ZQuicConfig) -> *mut ZQuicContext;
    pub fn zquic_destroy(ctx: *mut ZQuicContext);
    pub fn zquic_create_connection(ctx: *mut ZQuicContext, addr: *const c_char) -> *mut ZQuicConnection;
    pub fn zquic_close_connection(conn: *mut ZQuicConnection) -> c_int;
    pub fn zquic_send_data(conn: *mut ZQuicConnection, data: *const u8, len: size_t) -> ssize_t;
    pub fn zquic_receive_data(conn: *mut ZQuicConnection, buffer: *mut u8, max_len: size_t) -> ssize_t;
    
    // Crypto functions
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ed25519_keypair(public_key: *mut u8, private_key: *mut u8) -> c_int;
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ed25519_sign(private_key: *const u8, message: *const u8, message_len: size_t, signature: *mut u8) -> c_int;
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ed25519_verify(public_key: *const u8, message: *const u8, message_len: size_t, signature: *const u8) -> c_int;
    
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ml_kem_768_keypair(public_key: *mut u8, private_key: *mut u8) -> c_int;
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ml_kem_768_encaps(public_key: *const u8, ciphertext: *mut u8, shared_secret: *mut u8) -> c_int;
    #[cfg(feature = "post-quantum")]
    pub fn zcrypto_ml_kem_768_decaps(private_key: *const u8, ciphertext: *const u8, shared_secret: *mut u8) -> c_int;
    
    // GhostBridge functions
    #[cfg(feature = "ghostbridge")]
    pub fn ghostbridge_init(config: *const GhostBridgeConfig) -> *mut GhostBridge;
    #[cfg(feature = "ghostbridge")]
    pub fn ghostbridge_destroy(bridge: *mut GhostBridge);
    #[cfg(feature = "ghostbridge")]
    pub fn ghostbridge_create_grpc_connection(bridge: *mut GhostBridge, service_name: *const c_char) -> *mut GrpcConnection;
    #[cfg(feature = "ghostbridge")]
    pub fn ghostbridge_close_grpc_connection(conn: *mut GrpcConnection);
    #[cfg(feature = "ghostbridge")]
    pub fn ghostbridge_call_method(conn: *mut GrpcConnection, method: *const c_char, request_data: *const u8, request_len: size_t) -> *mut GrpcResponse;
    
    // Test functions
    pub fn zquic_test_add(a: c_int, b: c_int) -> c_int;
    pub fn zquic_test_echo(input: *const c_char) -> *const c_char;
}

// ===== CONVENIENCE TYPE ALIASES =====

pub type ZQuicResult<T> = std::result::Result<T, ZQuicError>;

// ===== ERROR HANDLING =====

/// Error types for ZQUIC operations
#[derive(Debug, Clone, PartialEq)]
pub enum ZQuicError {
    /// Invalid parameter passed to function
    InvalidParam = ZQUIC_INVALID_PARAM as isize,
    /// Operation timed out
    Timeout = ZQUIC_TIMEOUT as isize,
    /// Connection was refused
    ConnectionRefused = ZQUIC_CONNECTION_REFUSED as isize,
    /// Cryptographic error occurred
    CryptoError = ZQUIC_CRYPTO_ERROR as isize,
    /// Protocol error
    ProtocolError = ZQUIC_PROTOCOL_ERROR as isize,
    /// Generic error
    Error = ZQUIC_ERROR as isize,
}

impl std::fmt::Display for ZQuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ZQuicError::InvalidParam => write!(f, "Invalid parameter"),
            ZQuicError::Timeout => write!(f, "Operation timed out"),
            ZQuicError::ConnectionRefused => write!(f, "Connection refused"),
            ZQuicError::CryptoError => write!(f, "Cryptographic error"),
            ZQuicError::ProtocolError => write!(f, "Protocol error"),
            ZQuicError::Error => write!(f, "Generic ZQUIC error"),
        }
    }
}

impl std::error::Error for ZQuicError {}

impl From<c_int> for ZQuicError {
    fn from(code: c_int) -> Self {
        match code {
            ZQUIC_INVALID_PARAM => ZQuicError::InvalidParam,
            ZQUIC_TIMEOUT => ZQuicError::Timeout,
            ZQUIC_CONNECTION_REFUSED => ZQuicError::ConnectionRefused,
            ZQUIC_CRYPTO_ERROR => ZQuicError::CryptoError,
            ZQUIC_PROTOCOL_ERROR => ZQuicError::ProtocolError,
            _ => ZQuicError::Error,
        }
    }
}

// ===== HELPER FUNCTIONS =====

/// Convert a C-style result code to a Rust Result
pub fn check_result(code: c_int) -> ZQuicResult<()> {
    if code == ZQUIC_OK {
        Ok(())
    } else {
        Err(ZQuicError::from(code))
    }
}

/// Convert a size result to a Rust Result
pub fn check_size_result(result: ssize_t) -> ZQuicResult<usize> {
    if result >= 0 {
        Ok(result as usize)
    } else {
        Err(ZQuicError::Error)
    }
}

// ===== POST-QUANTUM CRYPTO CONSTANTS =====

#[cfg(feature = "post-quantum")]
pub mod crypto {
    /// Ed25519 key and signature sizes
    pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
    pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;
    pub const ED25519_SIGNATURE_SIZE: usize = 64;
    
    /// Secp256k1 key and signature sizes
    pub const SECP256K1_PUBLIC_KEY_SIZE: usize = 33;
    pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
    pub const SECP256K1_SIGNATURE_SIZE: usize = 64;
    
    /// Hash sizes
    pub const BLAKE3_HASH_SIZE: usize = 32;
    pub const SHA256_HASH_SIZE: usize = 32;
    
    /// Post-quantum ML-KEM-768 sizes
    pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
    pub const ML_KEM_768_PRIVATE_KEY_SIZE: usize = 2400;
    pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
    pub const ML_KEM_768_SHARED_SECRET_SIZE: usize = 32;
    
    /// Post-quantum SLH-DSA-128f sizes
    pub const SLH_DSA_128F_PUBLIC_KEY_SIZE: usize = 32;
    pub const SLH_DSA_128F_PRIVATE_KEY_SIZE: usize = 64;
    pub const SLH_DSA_128F_SIGNATURE_SIZE: usize = 17088;
}

// ===== GHOSTBRIDGE HELPERS =====

#[cfg(feature = "ghostbridge")]
pub mod ghostbridge {
    use super::*;
    use std::ffi::CString;
    
    /// Safe wrapper for GrpcResponse (simplified for now)
    pub struct GrpcResponseWrapper {
        inner: *mut GrpcResponse,
    }
    
    impl GrpcResponseWrapper {
        pub fn new(response: *mut GrpcResponse) -> Option<Self> {
            if response.is_null() {
                None
            } else {
                Some(Self { inner: response })
            }
        }
        
        pub fn status(&self) -> GrpcStatusCode {
            // For now, just return OK
            GRPC_OK
        }
        
        pub fn data(&self) -> &[u8] {
            // For now, return empty slice
            &[]
        }
        
        pub fn status_message(&self) -> Option<&str> {
            // For now, return None
            None
        }
    }
    
    impl Drop for GrpcResponseWrapper {
        fn drop(&mut self) {
            // For now, no-op (would call actual destructor in production)
        }
    }
    
    /// Helper to create a C string safely
    pub fn to_cstring(s: &str) -> Result<CString, std::ffi::NulError> {
        CString::new(s)
    }
}

// ===== TESTING UTILITIES =====

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    
    #[test]
    fn test_error_conversion() {
        let err = ZQuicError::from(ZQUIC_TIMEOUT);
        assert_eq!(err, ZQuicError::Timeout);
        assert_eq!(format!("{}", err), "Operation timed out");
    }
    
    #[test]
    fn test_check_result() {
        assert!(check_result(ZQUIC_OK).is_ok());
        assert!(check_result(ZQUIC_ERROR).is_err());
    }
    
    #[test]
    fn test_check_size_result() {
        assert_eq!(check_size_result(42).unwrap(), 42);
        assert!(check_size_result(-1).is_err());
    }
    
    #[cfg(feature = "post-quantum")]
    #[test]
    fn test_crypto_constants() {
        assert_eq!(crypto::ED25519_PUBLIC_KEY_SIZE, 32);
        assert_eq!(crypto::ED25519_SIGNATURE_SIZE, 64);
        assert_eq!(crypto::ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(crypto::SLH_DSA_128F_SIGNATURE_SIZE, 17088);
    }
}

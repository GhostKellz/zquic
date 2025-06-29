//! Integration tests for ZQUIC Rust bindings
//!
//! Tests the complete FFI integration and functionality

use std::ffi::CString;
use zquic_sys::*;

#[test]
fn test_basic_ffi_connectivity() {
    // Test basic arithmetic function
    let result = unsafe { zquic_test_add(42, 8) };
    assert_eq!(result, 50);
    
    // Test string echo function
    let input = CString::new("integration_test").unwrap();
    let output = unsafe { zquic_test_echo(input.as_ptr()) };
    let output_str = unsafe { std::ffi::CStr::from_ptr(output) };
    
    // The echo function should return a confirmation message
    assert!(output_str.to_str().unwrap().contains("ZQUIC FFI Test OK"));
}

#[test]
fn test_error_conversion() {
    let ok_result = check_result(ZQUIC_OK);
    assert!(ok_result.is_ok());
    
    let error_result = check_result(ZQUIC_ERROR);
    assert!(error_result.is_err());
    assert_eq!(error_result.unwrap_err(), ZQuicError::Error);
    
    let timeout_error = ZQuicError::from(ZQUIC_TIMEOUT);
    assert_eq!(timeout_error, ZQuicError::Timeout);
    assert_eq!(format!("{}", timeout_error), "Operation timed out");
}

#[test]
fn test_size_result_conversion() {
    let positive_result = check_size_result(1024);
    assert_eq!(positive_result.unwrap(), 1024);
    
    let negative_result = check_size_result(-1);
    assert!(negative_result.is_err());
}

#[cfg(feature = "post-quantum")]
#[test]
fn test_crypto_constants() {
    use crypto::*;
    
    // Test classic crypto sizes
    assert_eq!(ED25519_PUBLIC_KEY_SIZE, 32);
    assert_eq!(ED25519_PRIVATE_KEY_SIZE, 32);
    assert_eq!(ED25519_SIGNATURE_SIZE, 64);
    
    assert_eq!(SECP256K1_PUBLIC_KEY_SIZE, 33);
    assert_eq!(SECP256K1_PRIVATE_KEY_SIZE, 32);
    assert_eq!(SECP256K1_SIGNATURE_SIZE, 64);
    
    // Test hash sizes
    assert_eq!(BLAKE3_HASH_SIZE, 32);
    assert_eq!(SHA256_HASH_SIZE, 32);
    
    // Test post-quantum sizes
    assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
    assert_eq!(ML_KEM_768_PRIVATE_KEY_SIZE, 2400);
    assert_eq!(ML_KEM_768_CIPHERTEXT_SIZE, 1088);
    assert_eq!(ML_KEM_768_SHARED_SECRET_SIZE, 32);
    
    assert_eq!(SLH_DSA_128F_PUBLIC_KEY_SIZE, 32);
    assert_eq!(SLH_DSA_128F_PRIVATE_KEY_SIZE, 64);
    assert_eq!(SLH_DSA_128F_SIGNATURE_SIZE, 17088);
}

#[cfg(feature = "ghostbridge")]
#[test]
fn test_ghostbridge_types() {
    use ghostbridge::*;
    
    // Test string conversion helper
    let test_str = "test.service";
    let cstring = to_cstring(test_str).unwrap();
    assert_eq!(cstring.to_str().unwrap(), test_str);
    
    // Test that we can't create a cstring with null bytes
    let bad_str = "test\0service";
    assert!(to_cstring(bad_str).is_err());
}

#[test]
fn test_context_lifecycle() {
    // This is a more comprehensive test that would ideally
    // test the full lifecycle of a ZQUIC context, but since
    // we don't have the actual implementation running yet,
    // we'll focus on testing the binding generation and type safety
    
    // Test that we can create the config structure
    let config = ZQuicConfig {
        address: CString::new("127.0.0.1").unwrap().into_raw(),
        port: 8080,
        max_connections: 100,
        timeout_ms: 30000,
        enable_post_quantum: true,
        cert_path: std::ptr::null(),
        key_path: std::ptr::null(),
    };
    
    // In a real implementation, we would call zquic_init here
    // For now, just verify the struct can be constructed
    assert_eq!(config.port, 8080);
    assert_eq!(config.max_connections, 100);
    assert!(config.enable_post_quantum);
    
    // Clean up the CString we allocated
    unsafe {
        let _ = CString::from_raw(config.address as *mut i8);
    }
}

#[test]
fn test_thread_safety() {
    use std::sync::Arc;
    use std::thread;
    
    // Test that our types can be shared between threads
    let handles: Vec<_> = (0..10).map(|i| {
        thread::spawn(move || {
            // Test that constants are accessible from multiple threads
            #[cfg(feature = "post-quantum")]
            {
                assert_eq!(crypto::ED25519_PUBLIC_KEY_SIZE, 32);
                assert_eq!(crypto::ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
            }
            
            // Test basic FFI call from thread
            let result = unsafe { zquic_test_add(i, 10) };
            assert_eq!(result, i + 10);
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}

#[cfg(all(feature = "post-quantum", feature = "ghostbridge"))]
#[test]
fn test_feature_combination() {
    // Test that multiple features work together
    use crypto::*;
    use ghostbridge::*;
    
    // Should be able to use both post-quantum crypto constants
    // and ghostbridge utilities together
    assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
    
    let service_name = "test.service";
    let cstring = to_cstring(service_name).unwrap();
    assert_eq!(cstring.to_str().unwrap(), service_name);
}
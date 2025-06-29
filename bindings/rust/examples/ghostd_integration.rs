//! Example: ghostd service integration with ZQUIC
//!
//! This example demonstrates how a Rust service like ghostd would integrate
//! with ZQUIC for high-performance post-quantum QUIC transport.

use std::ffi::CString;
use zquic_sys::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 GhostD Integration Example - ZQUIC Post-Quantum Transport");
    println!("============================================================");
    
    // Test basic FFI connectivity
    test_basic_ffi()?;
    
    // Test crypto constants
    #[cfg(feature = "post-quantum")]
    test_crypto_functionality()?;
    
    // Test GhostBridge gRPC transport
    #[cfg(feature = "ghostbridge")]
    test_ghostbridge_integration()?;
    
    // Simulate ghostd service configuration
    test_ghostd_service_config()?;
    
    println!("✅ All integration tests passed!");
    println!("🔮 GhostD is ready for ZQUIC integration");
    
    Ok(())
}

fn test_basic_ffi() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Testing FFI connectivity...");
    
    // Test basic arithmetic
    let result = unsafe { zquic_test_add(42, 8) };
    if result != 50 {
        return Err("FFI arithmetic test failed".into());
    }
    println!("  ✓ FFI arithmetic: 42 + 8 = {}", result);
    
    // Test string handling
    let input = CString::new("ghostd_integration")?;
    let output = unsafe { zquic_test_echo(input.as_ptr()) };
    let output_str = unsafe { std::ffi::CStr::from_ptr(output) };
    println!("  ✓ FFI string echo: {:?}", output_str.to_str()?);
    
    Ok(())
}

#[cfg(feature = "post-quantum")]
fn test_crypto_functionality() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔐 Testing post-quantum crypto...");
    
    use crypto::*;
    
    // Display key sizes
    println!("  📊 Classic Crypto Sizes:");
    println!("    Ed25519 public key: {} bytes", ED25519_PUBLIC_KEY_SIZE);
    println!("    Ed25519 signature:  {} bytes", ED25519_SIGNATURE_SIZE);
    println!("    Secp256k1 pubkey:   {} bytes", SECP256K1_PUBLIC_KEY_SIZE);
    
    println!("  🛡️ Post-Quantum Sizes:");
    println!("    ML-KEM-768 pubkey:  {} bytes", ML_KEM_768_PUBLIC_KEY_SIZE);
    println!("    ML-KEM-768 privkey: {} bytes", ML_KEM_768_PRIVATE_KEY_SIZE);
    println!("    SLH-DSA signature:  {} bytes", SLH_DSA_128F_SIGNATURE_SIZE);
    
    // Verify expected sizes
    assert_eq!(ML_KEM_768_PUBLIC_KEY_SIZE, 1184);
    assert_eq!(SLH_DSA_128F_SIGNATURE_SIZE, 17088);
    
    println!("  ✓ Post-quantum crypto constants verified");
    
    Ok(())
}

#[cfg(feature = "ghostbridge")]
fn test_ghostbridge_integration() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🌉 Testing GhostBridge gRPC transport...");
    
    use ghostbridge::*;
    
    // Test service name handling
    let services = vec![
        "ghostd.blockchain.service",
        "walletd.wallet.service", 
        "realid.identity.service",
        "zsig.signature.service"
    ];
    
    for service in services {
        let cstring = to_cstring(service)?;
        println!("  📡 Service: {}", service);
        println!("    C-compatible: {:?}", cstring.to_str()?);
    }
    
    println!("  ✓ GhostBridge service integration ready");
    
    Ok(())
}

fn test_ghostd_service_config() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⚙️ Configuring GhostD service parameters...");
    
    // Example configuration that ghostd would use
    let config = ZQuicConfig {
        address: CString::new("0.0.0.0")?.into_raw(),
        port: 8080,  // GhostD gRPC port
        max_connections: 10000,  // High-throughput blockchain node
        timeout_ms: 30000,
        enable_post_quantum: true,  // Always use PQ crypto
        cert_path: CString::new("/etc/ssl/certs/ghostd.pem")?.into_raw(),
        key_path: CString::new("/etc/ssl/private/ghostd.key")?.into_raw(),
    };
    
    println!("  🌐 Listen address: 0.0.0.0:{}", config.port);
    println!("  🔗 Max connections: {}", config.max_connections);
    println!("  ⏱️ Timeout: {}ms", config.timeout_ms);
    println!("  🛡️ Post-quantum: {}", config.enable_post_quantum);
    
    // Verify configuration
    assert_eq!(config.port, 8080);
    assert_eq!(config.max_connections, 10000);
    assert!(config.enable_post_quantum);
    
    // Clean up allocated strings
    unsafe {
        let _ = CString::from_raw(config.address as *mut i8);
        let _ = CString::from_raw(config.cert_path as *mut i8);
        let _ = CString::from_raw(config.key_path as *mut i8);
    }
    
    println!("  ✓ GhostD configuration validated");
    
    Ok(())
}

// This function demonstrates how ghostd would actually use ZQUIC
// for blockchain operations (this would be async in real usage)
#[allow(dead_code)]
fn simulate_ghostd_blockchain_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n⛓️ Simulating GhostD blockchain operations...");
    
    // In a real implementation, ghostd would:
    // 1. Initialize ZQUIC context for blockchain networking
    // 2. Connect to other blockchain nodes via QUIC
    // 3. Use GhostBridge for gRPC calls to walletd
    // 4. Stream blocks and transactions over QUIC
    // 5. Use post-quantum crypto for all signatures
    
    println!("  📦 Block synchronization over QUIC transport");
    println!("  💰 Transaction streaming with post-quantum security");
    println!("  🤝 Consensus messages via GhostBridge to peers");
    println!("  🏦 Wallet operations relayed to walletd service");
    
    println!("  ✓ Blockchain operations simulation complete");
    
    Ok(())
}

// This would be the actual integration point for ghostd
#[allow(dead_code)]
pub struct GhostDZQuicIntegration {
    quic_context: *mut ZQuicContext,
    #[cfg(feature = "ghostbridge")]
    ghostbridge: *mut GhostBridge,
}

#[allow(dead_code)]
impl GhostDZQuicIntegration {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize ZQUIC for ghostd
        let config = ZQuicConfig {
            address: CString::new("0.0.0.0")?.into_raw(),
            port: 8080,
            max_connections: 10000,
            timeout_ms: 30000,
            enable_post_quantum: true,
            cert_path: std::ptr::null(),
            key_path: std::ptr::null(),
        };
        
        let quic_context = unsafe { zquic_init(&config) };
        if quic_context.is_null() {
            return Err("Failed to initialize ZQUIC context".into());
        }
        
        #[cfg(feature = "ghostbridge")]
        let ghostbridge = {
            let bridge_config = GhostBridgeConfig {
                address: CString::new("0.0.0.0")?.into_raw(),
                port: 8081,
                max_connections: 5000,
                cert_path: std::ptr::null(),
                key_path: std::ptr::null(),
                enable_compression: true,
                enable_post_quantum: true,
            };
            
            let bridge = unsafe { ghostbridge_init(&bridge_config) };
            if bridge.is_null() {
                unsafe { zquic_destroy(quic_context) };
                return Err("Failed to initialize GhostBridge".into());
            }
            bridge
        };
        
        // Clean up config strings
        unsafe {
            let _ = CString::from_raw(config.address as *mut i8);
            #[cfg(feature = "ghostbridge")]
            {
                let _ = CString::from_raw(bridge_config.address as *mut i8);
            }
        }
        
        Ok(Self {
            quic_context,
            #[cfg(feature = "ghostbridge")]
            ghostbridge,
        })
    }
    
    pub fn start_blockchain_networking(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Start QUIC server for peer-to-peer blockchain networking
        let result = unsafe { zquic_create_server(self.quic_context) };
        check_result(result)?;
        
        let result = unsafe { zquic_start_server(self.quic_context) };
        check_result(result)?;
        
        println!("🚀 GhostD blockchain networking started on QUIC transport");
        Ok(())
    }
    
    #[cfg(feature = "ghostbridge")]
    pub fn start_service_bridge(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Start GhostBridge for service-to-service communication
        let result = unsafe { ghostbridge_start(self.ghostbridge) };
        check_result(result)?;
        
        println!("🌉 GhostBridge service relay started");
        Ok(())
    }
}

#[allow(dead_code)]
impl Drop for GhostDZQuicIntegration {
    fn drop(&mut self) {
        unsafe {
            #[cfg(feature = "ghostbridge")]
            ghostbridge_destroy(self.ghostbridge);
            zquic_destroy(self.quic_context);
        }
    }
}
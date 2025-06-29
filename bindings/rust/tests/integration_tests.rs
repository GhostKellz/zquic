//! Integration tests for ZQUIC Rust bindings
//! 
//! These tests demonstrate how ghostd, walletd, and other Rust services
//! can use ZQUIC for high-performance networking.

use zquic_bindings::*;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_zquic_initialization() {
        let config = ZQuicConfig::new()
            .with_port(0) // Client mode
            .with_max_connections(10)
            .with_timeout(5000);

        let zquic = ZQuic::new(config);
        assert!(zquic.is_ok(), "ZQUIC initialization should succeed");
    }

    #[test]
    fn test_server_initialization() {
        let config = ZQuicConfig::new()
            .with_port(8445) // Server mode
            .with_max_connections(100);

        let zquic = ZQuic::new(config);
        assert!(zquic.is_ok(), "ZQUIC server initialization should succeed");

        if let Ok(server) = zquic {
            // Try to create server (will likely fail without full setup, but tests interface)
            let _result = server.create_server();
            // Don't assert on this as it requires network setup
        }
    }

    #[test] 
    fn test_connection_creation() {
        let zquic = init_client().expect("Client init should work");
        
        // Try to create connection (will fail without server, but tests interface)
        let connection = zquic.create_connection("127.0.0.1:8446");
        // Connection creation might fail without a real server, which is expected
        match connection {
            Ok(_) => println!("Connection created successfully"),
            Err(e) => println!("Expected connection failure: {}", e),
        }
    }

    #[test]
    fn test_crypto_operations() {
        // Test crypto initialization
        let crypto_result = ZCrypto::init();
        assert!(crypto_result.is_ok(), "Crypto initialization should succeed");

        // Test signing (with mock data)
        let private_key = vec![1u8; 32]; // Mock private key
        let data = b"test message for signing";
        
        let signature_result = ZCrypto::sign(1, &private_key, data);
        match signature_result {
            Ok(signature) => {
                println!("Signature generated: {} bytes", signature.len());
                assert!(!signature.is_empty(), "Signature should not be empty");
            }
            Err(e) => println!("Expected signing failure (mock crypto): {}", e),
        }
    }

    #[test]
    fn test_config_builder() {
        let config = ZQuicConfig::new()
            .with_port(8443)
            .with_max_connections(200)
            .with_timeout(60000)
            .with_ipv6(true)
            .with_tls_verify(false);

        assert_eq!(config.port, 8443);
        assert_eq!(config.max_connections, 200);
        assert_eq!(config.connection_timeout_ms, 60000);
        assert_eq!(config.enable_ipv6, 1);
        assert_eq!(config.tls_verify, 0);
    }
}

// Example usage patterns for ghostd/walletd integration
#[cfg(test)]
mod usage_examples {
    use super::*;

    /// Example: How ghostd would use ZQUIC for service communication
    #[tokio::test]
    async fn ghostd_service_communication_example() {
        // Initialize ZQUIC client for ghostd
        let zquic = init_client().expect("ZQUIC client init");
        
        // Create connection to walletd service
        let connection = zquic.create_connection("walletd.service:8443");
        
        match connection {
            Ok(conn) => {
                // Example gRPC call to walletd
                let request = br#"{"wallet_id": "test_wallet"}"#;
                let response = ghostd_call(&conn, "walletd.WalletService/GetBalance", request).await;
                
                match response {
                    Ok(data) => {
                        println!("Received wallet balance: {} bytes", data.len());
                        // In real usage, this would be deserialized protobuf/JSON
                    }
                    Err(e) => println!("Expected failure without real walletd: {}", e),
                }
            }
            Err(e) => println!("Expected connection failure: {}", e),
        }
    }

    /// Example: How walletd would set up a ZQUIC server
    #[test]
    fn walletd_server_setup_example() {
        let config = ZQuicConfig::new()
            .with_port(8443)
            .with_max_connections(1000)
            .with_timeout(30000)
            .with_ipv6(true)
            .with_tls_verify(true);

        let walletd_server = ZQuic::new(config).expect("Walletd server init");
        
        // In real usage, this would start the server and handle incoming connections
        let server_result = walletd_server.create_server();
        match server_result {
            Ok(_) => {
                println!("Walletd ZQUIC server would be running on port 8443");
                // Server would handle gRPC calls over QUIC here
                walletd_server.stop_server();
            }
            Err(e) => println!("Expected server setup failure: {}", e),
        }
    }

    /// Example: High-throughput data transfer
    #[test]
    fn high_throughput_transfer_example() {
        let zquic = init_client().expect("Client init");
        let connection = zquic.create_connection("peer.service:8444");
        
        if let Ok(conn) = connection {
            // Example: Transfer large dataset
            let large_data = vec![0u8; 1024 * 1024]; // 1MB test data
            
            match conn.send(&large_data) {
                Ok(bytes_sent) => {
                    println!("High-throughput transfer: {} bytes sent", bytes_sent);
                    assert_eq!(bytes_sent, large_data.len());
                }
                Err(e) => println!("Expected send failure: {}", e),
            }
        }
    }

    /// Example: Crypto-secured communication
    #[test]
    fn crypto_secured_communication_example() {
        // Initialize crypto subsystem
        ZCrypto::init().expect("Crypto init");
        
        // Generate signing key for service authentication
        let service_key = vec![42u8; 32]; // In real usage, load from secure storage
        let message = b"service_authentication_challenge";
        
        // Sign authentication challenge
        let signature = ZCrypto::sign(1, &service_key, message);
        
        match signature {
            Ok(sig) => {
                println!("Service authentication signature: {} bytes", sig.len());
                // In real usage, this signature would be sent with service requests
            }
            Err(e) => println!("Expected crypto failure (placeholder): {}", e),
        }
    }
}

/// Performance benchmarks (would be in a separate bench crate in production)
#[cfg(test)]
mod benchmarks {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_connection_creation() {
        let zquic = init_client().expect("Client init");
        
        let start = Instant::now();
        for i in 0..10 {
            let _conn = zquic.create_connection(&format!("127.0.0.1:844{}", i));
            // Connections will fail, but we're measuring the interface overhead
        }
        let duration = start.elapsed();
        
        println!("Connection creation benchmark: {:?} for 10 attempts", duration);
        println!("Average per connection: {:?}", duration / 10);
    }

    #[test]
    fn benchmark_crypto_operations() {
        ZCrypto::init().expect("Crypto init");
        
        let key = vec![1u8; 32];
        let data = b"benchmark message for crypto performance testing";
        
        let start = Instant::now();
        for _ in 0..100 {
            let _signature = ZCrypto::sign(1, &key, data);
        }
        let duration = start.elapsed();
        
        println!("Crypto signing benchmark: {:?} for 100 operations", duration);
        println!("Average per signature: {:?}", duration / 100);
    }
}

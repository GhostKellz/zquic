//! ZQUIC: Safe Rust bindings for post-quantum QUIC transport
//!
//! This crate provides safe, high-level Rust bindings for the ZQUIC library,
//! with full async/await support for integration with Tokio-based Rust services
//! like ghostd and walletd.
//!
//! ## Features
//!
//! - **Post-quantum cryptography**: ML-KEM-768 key exchange and SLH-DSA signatures
//! - **High-performance QUIC transport**: Zero-copy packet processing
//! - **Async/await support**: Full Tokio integration
//! - **gRPC-over-QUIC**: GhostBridge transport for service communication
//! - **Service integrations**: Wraith proxy and CNS resolver support
//!
//! ## Example: Basic QUIC client
//!
//! ```no_run
//! use zquic::{QuicClient, QuicConfig};
//!
//! #[tokio::main]
//! async fn main() -> zquic::Result<()> {
//!     let config = QuicConfig::new()
//!         .with_post_quantum(true)
//!         .with_timeout(30000);
//!     
//!     let mut client = QuicClient::new(config).await?;
//!     let mut connection = client.connect("127.0.0.1:8080").await?;
//!     
//!     connection.send(b"Hello, QUIC!").await?;
//!     let response = connection.receive().await?;
//!     
//!     println!("Received: {:?}", response);
//!     Ok(())
//! }
//! ```
//!
//! ## Example: GhostBridge gRPC client for ghostd/walletd
//!
//! ```no_run
//! use zquic::ghostbridge::{GrpcClient, GrpcConfig};
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> zquic::Result<()> {
//!     let config = GrpcConfig::new()
//!         .with_service_discovery(true)
//!         .with_compression(true);
//!     
//!     let mut client = GrpcClient::new(config).await?;
//!     let mut conn = client.connect_to_service("ghostd").await?;
//!     
//!     let request = Bytes::from(b"wallet_balance_request".to_vec());
//!     let response = conn.call("WalletService/GetBalance", request).await?;
//!     
//!     println!("Balance response: {:?}", response);
//!     Ok(())
//! }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures::channel::oneshot;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

// Re-export core types
pub use zquic_sys::{uint8_t, uint16_t, uint32_t, uint64_t, size_t, ssize_t};

// ===== ERROR HANDLING =====

/// Result type for ZQUIC operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for ZQUIC operations
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// ZQUIC library error
    #[error("ZQUIC error: {0}")]
    ZQuic(#[from] zquic_sys::ZQuicError),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    
    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Timeout error
    #[error("Operation timed out")]
    Timeout,
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Serialization error
    #[cfg(feature = "serde-support")]
    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ===== CONFIGURATION =====

/// Configuration for QUIC client/server
#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub address: String,
    pub port: u16,
    pub max_connections: u32,
    pub timeout_ms: u32,
    pub enable_post_quantum: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub enable_ipv6: bool,
    pub tls_verify: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 0, // Client mode
            max_connections: 1000,
            timeout_ms: 30000,
            enable_post_quantum: true,
            cert_path: None,
            key_path: None,
            enable_ipv6: true,
            tls_verify: true,
        }
    }
}

impl QuicConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Default::default()
    }
    
    /// Set the bind address (for servers)
    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = address.into();
        self
    }
    
    /// Set the port (0 for client-only mode)
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
    
    /// Set maximum concurrent connections
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }
    
    /// Set connection timeout in milliseconds
    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
    
    /// Enable or disable post-quantum cryptography
    pub fn with_post_quantum(mut self, enable: bool) -> Self {
        self.enable_post_quantum = enable;
        self
    }
    
    /// Set TLS certificate and key paths
    pub fn with_tls_cert(mut self, cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        self.cert_path = Some(cert_path.into());
        self.key_path = Some(key_path.into());
        self
    }
    
    /// Enable or disable IPv6
    pub fn with_ipv6(mut self, enable: bool) -> Self {
        self.enable_ipv6 = enable;
        self
    }
    
    /// Enable or disable TLS verification
    pub fn with_tls_verify(mut self, verify: bool) -> Self {
        self.tls_verify = verify;
        self
    }
}

// ===== QUIC CLIENT =====

/// High-level QUIC client
pub struct QuicClient {
    config: QuicConfig,
    ctx: *mut zquic_sys::ZQuicContext,
}

impl QuicClient {
    /// Create a new QUIC client
    pub async fn new(config: QuicConfig) -> Result<Self> {
        let sys_config = zquic_sys::ZQuicConfig {
            address: std::ffi::CString::new(config.address.clone())?.into_raw(),
            port: config.port,
            max_connections: config.max_connections,
            timeout_ms: config.timeout_ms,
            enable_post_quantum: config.enable_post_quantum,
            cert_path: config.cert_path.as_ref()
                .map(|p| std::ffi::CString::new(p.clone()).unwrap().into_raw())
                .unwrap_or(std::ptr::null_mut()),
            key_path: config.key_path.as_ref()
                .map(|p| std::ffi::CString::new(p.clone()).unwrap().into_raw())
                .unwrap_or(std::ptr::null_mut()),
        };
        
        let ctx = unsafe { zquic_sys::zquic_init(&sys_config) };
        if ctx.is_null() {
            return Err(Error::Connection("Failed to initialize QUIC context".to_string()));
        }
        
        info!("QUIC client initialized with post-quantum: {}", config.enable_post_quantum);
        
        Ok(Self { config, ctx })
    }
    
    /// Connect to a remote server
    pub async fn connect(&mut self, address: &str) -> Result<QuicConnection> {
        let addr_cstring = std::ffi::CString::new(address)?;
        
        let conn = unsafe { 
            zquic_sys::zquic_create_connection(self.ctx, addr_cstring.as_ptr()) 
        };
        
        if conn.is_null() {
            return Err(Error::Connection(format!("Failed to connect to {}", address)));
        }
        
        debug!("Connected to {}", address);
        
        Ok(QuicConnection {
            conn,
            local_addr: self.config.address.clone(),
            remote_addr: address.to_string(),
        })
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        unsafe {
            zquic_sys::zquic_destroy(self.ctx);
        }
    }
}

// Safety: QuicClient can be Send + Sync since the underlying C library
// is designed for multi-threaded use
unsafe impl Send for QuicClient {}
unsafe impl Sync for QuicClient {}

// ===== QUIC CONNECTION =====

/// A QUIC connection
pub struct QuicConnection {
    conn: *mut zquic_sys::ZQuicConnection,
    local_addr: String,
    remote_addr: String,
}

impl QuicConnection {
    /// Send data over the connection
    pub async fn send(&mut self, data: &[u8]) -> Result<usize> {
        let result = unsafe {
            zquic_sys::zquic_send_data(self.conn, data.as_ptr(), data.len())
        };
        
        zquic_sys::check_size_result(result).map_err(Error::ZQuic)
    }
    
    /// Receive data from the connection
    pub async fn receive(&mut self) -> Result<Bytes> {
        let mut buffer = vec![0u8; 65536]; // 64KB buffer
        
        let result = unsafe {
            zquic_sys::zquic_receive_data(self.conn, buffer.as_mut_ptr(), buffer.len())
        };
        
        let bytes_received = zquic_sys::check_size_result(result).map_err(Error::ZQuic)?;
        buffer.truncate(bytes_received);
        
        Ok(Bytes::from(buffer))
    }
    
    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        // This would call into the FFI to get actual stats
        ConnectionStats {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            rtt_us: 0,
        }
    }
    
    /// Get local address
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
    
    /// Get remote address
    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        unsafe {
            zquic_sys::zquic_close_connection(self.conn);
        }
    }
}

unsafe impl Send for QuicConnection {}
unsafe impl Sync for QuicConnection {}

// ===== CONNECTION STATISTICS =====

/// Connection statistics
#[derive(Debug, Clone, Copy)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub rtt_us: u64,
}

// ===== GHOSTBRIDGE MODULE =====

#[cfg(feature = "ghostbridge")]
pub mod ghostbridge {
    use super::*;
    
    /// Configuration for GrpcClient
    #[derive(Debug, Clone)]
    pub struct GrpcConfig {
        pub service_discovery: bool,
        pub compression: bool,
        pub timeout_ms: u32,
        pub max_message_size: usize,
    }
    
    impl Default for GrpcConfig {
        fn default() -> Self {
            Self {
                service_discovery: true,
                compression: true,
                timeout_ms: 30000,
                max_message_size: 4 * 1024 * 1024, // 4MB
            }
        }
    }
    
    impl GrpcConfig {
        pub fn new() -> Self {
            Default::default()
        }
        
        pub fn with_service_discovery(mut self, enable: bool) -> Self {
            self.service_discovery = enable;
            self
        }
        
        pub fn with_compression(mut self, enable: bool) -> Self {
            self.compression = enable;
            self
        }
        
        pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
            self.timeout_ms = timeout_ms;
            self
        }
        
        pub fn with_max_message_size(mut self, size: usize) -> Self {
            self.max_message_size = size;
            self
        }
    }
    
    /// High-level gRPC client for ghostd/walletd communication
    pub struct GrpcClient {
        config: GrpcConfig,
        bridge: *mut zquic_sys::GhostBridge,
    }
    
    impl GrpcClient {
        /// Create a new gRPC client
        pub async fn new(config: GrpcConfig) -> Result<Self> {
            let bridge_config = zquic_sys::GhostBridgeConfig {
                address: std::ffi::CString::new("0.0.0.0")?.into_raw(),
                port: 0, // Client mode
                max_connections: 1000,
                cert_path: std::ptr::null(),
                key_path: std::ptr::null(),
                enable_compression: config.compression,
                enable_post_quantum: true,
            };
            
            let bridge = unsafe { zquic_sys::ghostbridge_init(&bridge_config) };
            if bridge.is_null() {
                return Err(Error::Connection("Failed to initialize GhostBridge".to_string()));
            }
            
            info!("GrpcClient initialized with compression: {}", config.compression);
            
            Ok(Self { config, bridge })
        }
        
        /// Connect to a service by name
        pub async fn connect_to_service(&mut self, service_name: &str) -> Result<GrpcConnection> {
            let service_cstring = std::ffi::CString::new(service_name)?;
            
            let conn = unsafe {
                zquic_sys::ghostbridge_create_grpc_connection(self.bridge, service_cstring.as_ptr())
            };
            
            if conn.is_null() {
                return Err(Error::Connection(format!("Failed to connect to service {}", service_name)));
            }
            
            debug!("Connected to service: {}", service_name);
            
            Ok(GrpcConnection {
                conn,
                service_name: service_name.to_string(),
            })
        }
    }
    
    impl Drop for GrpcClient {
        fn drop(&mut self) {
            unsafe {
                zquic_sys::ghostbridge_destroy(self.bridge);
            }
        }
    }
    
    unsafe impl Send for GrpcClient {}
    unsafe impl Sync for GrpcClient {}
    
    /// A gRPC connection to a specific service
    pub struct GrpcConnection {
        conn: *mut zquic_sys::GrpcConnection,
        service_name: String,
    }
    
    impl GrpcConnection {
        /// Make a gRPC call
        pub async fn call(&mut self, method: &str, request: Bytes) -> Result<Bytes> {
            let method_cstring = std::ffi::CString::new(method)?;
            
            let response = unsafe {
                zquic_sys::ghostbridge_call_method(
                    self.conn,
                    method_cstring.as_ptr(),
                    request.as_ptr(),
                    request.len(),
                )
            };
            
            if response.is_null() {
                return Err(Error::Protocol("gRPC call failed".to_string()));
            }
            
            let response_wrapper = zquic_sys::ghostbridge::GrpcResponseWrapper::new(response)
                .ok_or_else(|| Error::Protocol("Invalid gRPC response".to_string()))?;
            
            let status = response_wrapper.status();
            if status != zquic_sys::GRPC_OK {
                let status_msg = response_wrapper.status_message()
                    .unwrap_or("Unknown error");
                return Err(Error::Protocol(format!("gRPC error {}: {}", status as u32, status_msg)));
            }
            
            Ok(Bytes::copy_from_slice(response_wrapper.data()))
        }
        
        /// Get the service name
        pub fn service_name(&self) -> &str {
            &self.service_name
        }
    }
    
    impl Drop for GrpcConnection {
        fn drop(&mut self) {
            unsafe {
                zquic_sys::ghostbridge_close_grpc_connection(self.conn);
            }
        }
    }
    
    unsafe impl Send for GrpcConnection {}
    unsafe impl Sync for GrpcConnection {}
}

// ===== UTILITIES =====

/// Initialize the ZQUIC library
pub async fn init() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Initialize crypto subsystem if post-quantum features are enabled
    #[cfg(feature = "post-quantum")]
    {
        let result = unsafe { zquic_sys::zcrypto_random_bytes(std::ptr::null_mut(), 0) };
        if result != 0 {
            warn!("Post-quantum crypto initialization may have issues");
        }
    }
    
    info!("ZQUIC library initialized");
    Ok(())
}

// ===== TESTS =====

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_builder() {
        let config = QuicConfig::new()
            .with_port(8443)
            .with_max_connections(500)
            .with_timeout(60000)
            .with_post_quantum(true)
            .with_ipv6(false);
        
        assert_eq!(config.port, 8443);
        assert_eq!(config.max_connections, 500);
        assert_eq!(config.timeout_ms, 60000);
        assert!(config.enable_post_quantum);
        assert!(!config.enable_ipv6);
    }
    
    #[tokio::test]
    async fn test_init() {
        init().await.expect("Library initialization should succeed");
    }
}
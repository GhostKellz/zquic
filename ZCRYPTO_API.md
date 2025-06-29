# 🔌 ZCRYPTO v0.5.0 API REFERENCE

**Complete API Documentation for Post-Quantum Cryptographic Library**

---

## 📋 **TABLE OF CONTENTS**

1. [Core Cryptographic Primitives](#core-cryptographic-primitives)
2. [Post-Quantum Algorithms](#post-quantum-algorithms)
3. [Advanced Protocols](#advanced-protocols)
4. [QUIC Cryptography](#quic-cryptography)
5. [Zero-Knowledge Proofs](#zero-knowledge-proofs)
6. [Assembly Optimizations](#assembly-optimizations)
7. [Foreign Function Interface](#foreign-function-interface)
8. [Error Handling](#error-handling)
9. [Memory Management](#memory-management)
10. [Configuration](#configuration)

---

## 🔑 **CORE CRYPTOGRAPHIC PRIMITIVES**

### **Hash Functions**

#### `zcrypto.hash`

```zig
pub const hash = struct {
    /// SHA-256 hash function
    pub fn sha256(input: []const u8) [32]u8;
    
    /// SHA-3 256-bit hash
    pub fn sha3_256(input: []const u8) [32]u8;
    
    /// SHA-3 512-bit hash
    pub fn sha3_512(input: []const u8) [64]u8;
    
    /// BLAKE2b hash function
    pub fn blake2b(input: []const u8) [64]u8;
    
    /// SHAKE-128 extendable output function
    pub fn shake128(input: []const u8, output: []u8) void;
    
    /// SHAKE-256 extendable output function
    pub fn shake256(input: []const u8, output: []u8) void;
};
```

**Example Usage:**
```zig
const input = "Hello, World!";
const digest = zcrypto.hash.sha256(input);
const blake_digest = zcrypto.hash.blake2b(input);

var shake_output: [64]u8 = undefined;
zcrypto.hash.shake128(input, &shake_output);
```

### **Symmetric Cryptography**

#### `zcrypto.sym`

```zig
pub const sym = struct {
    /// AES-256-GCM encryption
    pub fn aes256_gcm_encrypt(
        plaintext: []const u8,
        key: *const [32]u8,
        nonce: *const [12]u8,
        ciphertext: []u8,
        tag: *[16]u8
    ) CryptoError!void;
    
    /// AES-256-GCM decryption
    pub fn aes256_gcm_decrypt(
        ciphertext: []const u8,
        key: *const [32]u8,
        nonce: *const [12]u8,
        tag: *const [16]u8,
        plaintext: []u8
    ) CryptoError!void;
    
    /// ChaCha20-Poly1305 encryption
    pub fn chacha20_poly1305_encrypt(
        plaintext: []const u8,
        key: *const [32]u8,
        nonce: *const [12]u8,
        ciphertext: []u8,
        tag: *[16]u8
    ) CryptoError!void;
    
    /// ChaCha20-Poly1305 decryption
    pub fn chacha20_poly1305_decrypt(
        ciphertext: []const u8,
        key: *const [32]u8,
        nonce: *const [12]u8,
        tag: *const [16]u8,
        plaintext: []u8
    ) CryptoError!void;
};
```

### **Asymmetric Cryptography**

#### `zcrypto.asym`

```zig
pub const asym = struct {
    pub const Ed25519 = struct {
        pub const KeyPair = struct {
            public_key: [32]u8,
            secret_key: [64]u8,
            
            /// Generate a new Ed25519 key pair
            pub fn generate() CryptoError!KeyPair;
            
            /// Create key pair from seed
            pub fn fromSeed(seed: [32]u8) KeyPair;
            
            /// Sign a message
            pub fn sign(self: *const KeyPair, message: []const u8) CryptoError![64]u8;
            
            /// Verify a signature
            pub fn verify(self: *const KeyPair, message: []const u8, signature: [64]u8) bool;
        };
        
        /// Verify signature with public key only
        pub fn verify(message: []const u8, signature: [64]u8, public_key: [32]u8) bool;
    };
    
    pub const X25519 = struct {
        pub const KeyPair = struct {
            public_key: [32]u8,
            secret_key: [32]u8,
            
            /// Generate a new X25519 key pair
            pub fn generate() CryptoError!KeyPair;
            
            /// Create key pair from seed
            pub fn fromSeed(seed: [32]u8) KeyPair;
            
            /// Perform key exchange
            pub fn exchange(self: *const KeyPair, peer_public: [32]u8) CryptoError![32]u8;
        };
    };
    
    pub const secp256k1 = struct {
        pub const KeyPair = struct {
            public_key: [33]u8,  // Compressed
            secret_key: [32]u8,
            
            pub fn generate() CryptoError!KeyPair;
            pub fn sign(self: *const KeyPair, message_hash: [32]u8) CryptoError![64]u8;
            pub fn verify(message_hash: [32]u8, signature: [64]u8, public_key: [33]u8) bool;
        };
    };
};
```

---

## 🌌 **POST-QUANTUM ALGORITHMS**

### **ML-KEM (Key Encapsulation Mechanism)**

#### `zcrypto.pq.ml_kem`

```zig
pub const ml_kem = struct {
    pub const ML_KEM_768 = struct {
        pub const PUBLIC_KEY_SIZE = 1184;
        pub const SECRET_KEY_SIZE = 2400;
        pub const CIPHERTEXT_SIZE = 1088;
        pub const SHARED_SECRET_SIZE = 32;
        
        pub const KeyPair = struct {
            public_key: [PUBLIC_KEY_SIZE]u8,
            secret_key: [SECRET_KEY_SIZE]u8,
            
            /// Generate ML-KEM-768 key pair
            pub fn generate(seed: [32]u8) PQError!KeyPair;
            
            /// Encapsulate to create shared secret
            pub fn encapsulate(
                public_key: [PUBLIC_KEY_SIZE]u8,
                randomness: [32]u8
            ) PQError!struct {
                ciphertext: [CIPHERTEXT_SIZE]u8,
                shared_secret: [SHARED_SECRET_SIZE]u8,
            };
            
            /// Decapsulate to recover shared secret
            pub fn decapsulate(
                self: *const KeyPair,
                ciphertext: [CIPHERTEXT_SIZE]u8
            ) PQError![SHARED_SECRET_SIZE]u8;
        };
    };
};
```

### **ML-DSA (Digital Signature Algorithm)**

#### `zcrypto.pq.ml_dsa`

```zig
pub const ml_dsa = struct {
    pub const ML_DSA_65 = struct {
        pub const PUBLIC_KEY_SIZE = 1952;
        pub const SECRET_KEY_SIZE = 4032;
        pub const SIGNATURE_SIZE = 3309;
        
        pub const KeyPair = struct {
            public_key: [PUBLIC_KEY_SIZE]u8,
            secret_key: [SECRET_KEY_SIZE]u8,
            
            /// Generate ML-DSA-65 key pair
            pub fn generate(seed: [32]u8) PQError!KeyPair;
            
            /// Sign a message
            pub fn sign(
                self: *const KeyPair,
                message: []const u8
            ) PQError![SIGNATURE_SIZE]u8;
        };
        
        /// Verify ML-DSA-65 signature
        pub fn verify(
            message: []const u8,
            signature: [SIGNATURE_SIZE]u8,
            public_key: [PUBLIC_KEY_SIZE]u8
        ) PQError!bool;
    };
};
```

### **SLH-DSA (Hash-Based Signatures)**

#### `zcrypto.pq.slh_dsa`

```zig
pub const slh_dsa = struct {
    pub const SLH_DSA_128s = struct {
        pub const PUBLIC_KEY_SIZE = 32;
        pub const SECRET_KEY_SIZE = 64;
        pub const SIGNATURE_SIZE = 7856;
        
        pub const KeyPair = struct {
            public_key: [PUBLIC_KEY_SIZE]u8,
            secret_key: [SECRET_KEY_SIZE]u8,
            
            /// Generate SLH-DSA-128s key pair
            pub fn generate(seed: [32]u8) PQError!KeyPair;
            
            /// Sign a message
            pub fn sign(
                self: *const KeyPair,
                message: []const u8
            ) PQError![SIGNATURE_SIZE]u8;
        };
        
        /// Verify SLH-DSA-128s signature
        pub fn verify(
            message: []const u8,
            signature: [SIGNATURE_SIZE]u8,
            public_key: [PUBLIC_KEY_SIZE]u8
        ) PQError!bool;
    };
};
```

### **Hybrid Algorithms**

#### `zcrypto.pq.hybrid`

```zig
pub const hybrid = struct {
    /// X25519 + ML-KEM-768 hybrid key exchange
    pub fn x25519_ml_kem_768_kex(
        classical_shared: *[32]u8,
        pq_shared: *[32]u8,
        combined_secret: *[64]u8,
        entropy: []const u8
    ) PQError!void;
    
    /// Ed25519 + ML-DSA-65 hybrid signatures
    pub const Ed25519_ML_DSA_65 = struct {
        pub const KeyPair = struct {
            classical_keypair: asym.Ed25519.KeyPair,
            pq_keypair: ml_dsa.ML_DSA_65.KeyPair,
            
            pub fn generate(seed: [32]u8) PQError!KeyPair;
            
            pub fn sign(self: *const KeyPair, message: []const u8) PQError!HybridSignature;
            
            pub fn verify(
                self: *const KeyPair,
                message: []const u8,
                signature: HybridSignature
            ) bool;
        };
        
        pub const HybridSignature = struct {
            classical_signature: [64]u8,
            pq_signature: [ml_dsa.ML_DSA_65.SIGNATURE_SIZE]u8,
        };
    };
};
```

---

## 🔒 **ADVANCED PROTOCOLS**

### **Signal Protocol**

#### `zcrypto.protocols.signal`

```zig
pub const signal = struct {
    pub const IdentityKey = struct {
        keypair: asym.Ed25519.KeyPair,
        
        pub fn generate() CryptoError!IdentityKey;
        pub const public_key = keypair.public_key;
    };
    
    pub const PreKey = struct {
        id: u32,
        keypair: asym.X25519.KeyPair,
        
        pub fn generate() CryptoError!PreKey;
    };
    
    pub const OneTimeKey = struct {
        id: u32,
        keypair: asym.X25519.KeyPair,
        
        pub fn generate() CryptoError!OneTimeKey;
    };
    
    /// X3DH key agreement
    pub fn x3dh(
        identity_key: [32]u8,
        signed_prekey: [32]u8,
        one_time_prekey: [32]u8
    ) CryptoError!struct {
        shared_secret: [32]u8,
        associated_data: []const u8,
    };
    
    pub const DoubleRatchet = struct {
        root_key: [32]u8,
        chain_key_send: [32]u8,
        chain_key_recv: [32]u8,
        send_counter: u32,
        recv_counter: u32,
        
        pub fn init(initial_shared_secret: [32]u8) DoubleRatchet;
        
        pub fn encrypt(self: *DoubleRatchet, plaintext: []const u8) CryptoError!EncryptedMessage;
        
        pub fn decrypt(self: *DoubleRatchet, encrypted: EncryptedMessage) CryptoError![]u8;
        
        pub fn performDHRatchet(self: *DoubleRatchet, peer_public: [32]u8) CryptoError!void;
    };
    
    pub const EncryptedMessage = struct {
        header: MessageHeader,
        ciphertext: []const u8,
        
        pub const MessageHeader = struct {
            sender_chain_length: u32,
            message_number: u32,
            public_key: [32]u8,
        };
    };
    
    /// Post-quantum enhanced Signal Protocol
    pub const PQSignal = struct {
        pub fn init(initial_shared_secret: [32]u8) PQDoubleRatchet;
        
        pub const PQDoubleRatchet = struct {
            classical_ratchet: DoubleRatchet,
            pq_root_key: [32]u8,
            pq_chain_key: [32]u8,
            
            pub fn encrypt(self: *PQDoubleRatchet, plaintext: []const u8) CryptoError!PQEncryptedMessage;
            pub fn decrypt(self: *PQDoubleRatchet, encrypted: PQEncryptedMessage) CryptoError![]u8;
        };
        
        pub const PQEncryptedMessage = struct {
            classical_message: EncryptedMessage,
            pq_ciphertext: []const u8,
        };
    };
};
```

### **Noise Protocol Framework**

#### `zcrypto.protocols.noise`

```zig
pub const noise = struct {
    pub const NoisePattern = enum {
        NN, // No static keys
        XX, // Mutual authentication
        IK, // Known responder identity
        // Post-quantum patterns
        pqNN,
        pqXX,
        pqIK,
    };
    
    pub const NoiseSession = struct {
        pattern: NoisePattern,
        is_initiator: bool,
        handshake_state: HandshakeState,
        transport_state: ?TransportState,
        
        pub fn init(pattern: NoisePattern, is_initiator: bool) CryptoError!NoiseSession;
        
        pub fn writeMessage(
            self: *NoiseSession,
            payload: []const u8,
            message_buffer: ?[]u8
        ) CryptoError![]const u8;
        
        pub fn readMessage(
            self: *NoiseSession,
            message: []const u8
        ) CryptoError!?[]const u8;
        
        pub fn encryptMessage(self: *NoiseSession, plaintext: []const u8) CryptoError![]u8;
        pub fn decryptMessage(self: *NoiseSession, ciphertext: []const u8) CryptoError![]u8;
    };
    
    const HandshakeState = struct {
        symmetric_state: SymmetricState,
        static_keypair: ?asym.X25519.KeyPair,
        ephemeral_keypair: ?asym.X25519.KeyPair,
        remote_static: ?[32]u8,
        remote_ephemeral: ?[32]u8,
    };
    
    const TransportState = struct {
        send_cipher: CipherState,
        recv_cipher: CipherState,
    };
    
    /// Post-quantum Noise
    pub const PQNoise = struct {
        pub fn init(pattern: NoisePattern, is_initiator: bool) CryptoError!PQNoiseSession;
        
        pub const PQNoiseSession = struct {
            classical_session: NoiseSession,
            pq_handshake_state: PQHandshakeState,
            
            pub fn writeMessage(self: *PQNoiseSession, payload: []const u8) CryptoError![]const u8;
            pub fn readMessage(self: *PQNoiseSession, message: []const u8) CryptoError!?[]const u8;
        };
    };
};
```

### **MLS (Message Layer Security)**

#### `zcrypto.protocols.mls`

```zig
pub const mls = struct {
    pub const CipherSuite = enum(u16) {
        MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
        MLS_128_HYBRID_X25519_KYBER768_AES256GCM_SHA384_Ed25519_Dilithium3 = 0x1001,
    };
    
    pub const Credential = struct {
        credential_type: CredentialType,
        identity: []const u8,
        
        pub fn basic(identity: []const u8) Credential;
    };
    
    pub const KeyPackage = struct {
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        init_key: [32]u8,
        leaf_node: LeafNode,
        signature: [64]u8,
        
        pub fn generate(
            allocator: std.mem.Allocator,
            cipher_suite: CipherSuite,
            identity: []const u8,
            credential: Credential
        ) MLSError!KeyPackage;
    };
    
    pub const Group = struct {
        context: GroupContext,
        tree: RatchetTree,
        epoch_secrets: EpochSecrets,
        
        pub fn init(
            allocator: std.mem.Allocator,
            group_id: []const u8,
            cipher_suite: CipherSuite,
            creator_key_package: KeyPackage
        ) MLSError!Group;
        
        pub fn addMember(self: *Group, key_package: KeyPackage) MLSError!Proposal;
        pub fn removeMember(self: *Group, member_index: LeafIndex) MLSError!Proposal;
        
        pub fn createCommit(self: *Group) MLSError!Commit;
        pub fn processCommit(self: *Group, commit: Commit) MLSError!void;
        
        pub fn encryptMessage(
            self: *Group,
            plaintext: []const u8,
            ciphertext_buffer: []u8
        ) MLSError![]const u8;
        
        pub fn decryptMessage(
            self: *Group,
            ciphertext: []const u8,
            plaintext_buffer: []u8
        ) MLSError![]const u8;
    };
};
```

---

## 🌐 **QUIC CRYPTOGRAPHY**

### **QUIC Core**

#### `zcrypto.quic`

```zig
pub const quic = struct {
    pub const CipherSuite = enum {
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
        TLS_ML_KEM_768_X25519_AES256_GCM_SHA384, // Post-quantum hybrid
    };
    
    pub const EncryptionLevel = enum {
        initial,
        early_data,    // 0-RTT
        handshake,
        application,   // 1-RTT
    };
    
    pub const QuicCrypto = struct {
        cipher_suite: CipherSuite,
        initial_keys_client: PacketKeys,
        initial_keys_server: PacketKeys,
        handshake_keys_client: PacketKeys,
        handshake_keys_server: PacketKeys,
        application_keys_client: PacketKeys,
        application_keys_server: PacketKeys,
        
        pub fn init(cipher_suite: CipherSuite) QuicCrypto;
        
        /// Derive initial keys from connection ID (RFC 9001)
        pub fn deriveInitialKeys(self: *QuicCrypto, connection_id: []const u8) QuicError!void;
        
        /// Encrypt QUIC packet
        pub fn encryptPacket(
            self: *const QuicCrypto,
            level: EncryptionLevel,
            is_server: bool,
            packet_number: u64,
            header: []const u8,
            payload: []const u8,
            output: []u8
        ) QuicError!usize;
        
        /// Decrypt QUIC packet
        pub fn decryptPacket(
            self: *const QuicCrypto,
            level: EncryptionLevel,
            is_server: bool,
            packet_number: u64,
            header: []const u8,
            ciphertext: []const u8,
            output: []u8
        ) QuicError!usize;
        
        /// Protect packet header (RFC 9001 Section 5.4)
        pub fn protectHeader(
            self: *const QuicCrypto,
            level: EncryptionLevel,
            is_server: bool,
            header: []u8,
            sample: []const u8
        ) QuicError!void;
        
        /// Unprotect packet header
        pub fn unprotectHeader(
            self: *const QuicCrypto,
            level: EncryptionLevel,
            is_server: bool,
            header: []u8,
            sample: []const u8
        ) QuicError!void;
    };
    
    pub const PacketKeys = struct {
        aead_key: [32]u8,
        iv: [12]u8,
        header_protection_key: [32]u8,
        
        pub fn zero() PacketKeys;
    };
};
```

### **Post-Quantum QUIC**

#### `zcrypto.quic.PostQuantumQuic`

```zig
pub const PostQuantumQuic = struct {
    /// Generate hybrid key share for QUIC ClientHello
    pub fn generateHybridKeyShare(
        classical_share: *[32]u8,    // X25519 public key
        pq_share: *[ml_kem.ML_KEM_768.PUBLIC_KEY_SIZE]u8,  // ML-KEM-768 public key
        entropy: []const u8
    ) PQError!void;
    
    /// Process hybrid key share in QUIC ServerHello
    pub fn processHybridKeyShare(
        client_classical: []const u8,
        client_pq: []const u8,
        server_classical: *[32]u8,
        server_pq: *[ml_kem.ML_KEM_768.CIPHERTEXT_SIZE]u8,
        shared_secret: *[64]u8
    ) PQError!void;
    
    /// Post-quantum key update for QUIC
    pub fn performPQKeyUpdate(
        current_secret: []const u8,
        pq_entropy: []const u8,
        new_secret: []u8,
    ) PQError!void;
    
    /// Quantum-safe 0-RTT protection
    pub fn protectZeroRTTPQ(
        classical_psk: []const u8,
        pq_psk: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
    ) PQError!void;
    
    pub const PqTransportParams = struct {
        max_pq_key_update_interval: u64,
        pq_algorithm_preference: []const u8,
        hybrid_mode_required: bool,
        
        pub fn encode(self: *const PqTransportParams, output: []u8) usize;
        pub fn decode(data: []const u8) ?PqTransportParams;
    };
};
```

---

## 🔬 **ZERO-KNOWLEDGE PROOFS**

### **Groth16 zk-SNARKs**

#### `zcrypto.zkp.groth16`

```zig
pub const groth16 = struct {
    pub const Fr = struct {
        value: u256,
        
        pub fn zero() Fr;
        pub fn one() Fr;
        pub fn fromInt(x: u64) Fr;
        pub fn add(self: Fr, other: Fr) Fr;
        pub fn mul(self: Fr, other: Fr) Fr;
        pub fn inverse(self: Fr) Fr;
        pub fn random() Fr;
    };
    
    pub const G1 = struct {
        x: Fr,
        y: Fr,
        infinity: bool,
        
        pub fn zero() G1;
        pub fn generator() G1;
        pub fn add(self: G1, other: G1) G1;
        pub fn scalarMul(self: G1, scalar: Fr) G1;
        pub fn random() G1;
    };
    
    pub const G2 = struct {
        x: [2]Fr,
        y: [2]Fr,
        infinity: bool,
        
        pub fn zero() G2;
        pub fn generator() G2;
        pub fn scalarMul(self: G2, scalar: Fr) G2;
        pub fn random() G2;
    };
    
    pub const Proof = struct {
        a: G1,
        b: G2,
        c: G1,
        
        pub fn toBytes(self: *const Proof, allocator: std.mem.Allocator) ![]u8;
        pub fn fromBytes(bytes: []const u8) !Proof;
    };
    
    pub const Circuit = struct {
        num_variables: usize,
        num_constraints: usize,
        num_public_inputs: usize,
        constraints: []Constraint,
        
        pub fn createMultiplicationCircuit(allocator: std.mem.Allocator) !Circuit;
        pub fn deinit(self: *Circuit, allocator: std.mem.Allocator) void;
    };
    
    pub const Witness = struct {
        variables: []Fr,
        
        pub fn createMultiplicationWitness(allocator: std.mem.Allocator, x: Fr, y: Fr) !Witness;
        pub fn deinit(self: *Witness, allocator: std.mem.Allocator) void;
    };
    
    /// Groth16 trusted setup
    pub fn setup(allocator: std.mem.Allocator, circuit: Circuit) !struct {
        proving_key: ProvingKey,
        verifying_key: VerifyingKey,
    };
    
    /// Generate Groth16 proof
    pub fn prove(
        allocator: std.mem.Allocator,
        proving_key: ProvingKey,
        witness: Witness,
        circuit: Circuit,
    ) !Proof;
    
    /// Verify Groth16 proof
    pub fn verify(
        verifying_key: VerifyingKey,
        public_inputs: []const Fr,
        proof: Proof,
    ) !bool;
};
```

### **Bulletproofs**

#### `zcrypto.zkp.bulletproofs`

```zig
pub const bulletproofs = struct {
    pub const Scalar = struct {
        value: u256,
        
        pub fn zero() Scalar;
        pub fn one() Scalar;
        pub fn fromInt(x: u64) Scalar;
        pub fn add(self: Scalar, other: Scalar) Scalar;
        pub fn mul(self: Scalar, other: Scalar) Scalar;
        pub fn inverse(self: Scalar) Scalar;
        pub fn random() Scalar;
    };
    
    pub const Point = struct {
        x: Scalar,
        y: Scalar,
        infinity: bool,
        
        pub fn zero() Point;
        pub fn generator() Point;
        pub fn add(self: Point, other: Point) Point;
        pub fn scalarMul(self: Point, scalar: Scalar) Point;
        pub fn random() Point;
    };
    
    pub const Commitment = struct {
        point: Point,
        
        /// Create Pedersen commitment: Com(value, blinding) = value*G + blinding*H
        pub fn commit(value: Scalar, blinding: Scalar) Commitment;
        pub fn add(self: Commitment, other: Commitment) Commitment;
    };
    
    pub const RangeProof = struct {
        a: Point,
        s: Point,
        t1: Point,
        t2: Point,
        tau_x: Scalar,
        mu: Scalar,
        inner_product_proof: InnerProductProof,
        
        pub fn toBytes(self: *const RangeProof, allocator: std.mem.Allocator) ![]u8;
        pub fn deinit(self: *RangeProof, allocator: std.mem.Allocator) void;
    };
    
    /// Generate a range proof for a committed value
    pub fn proveRange(
        allocator: std.mem.Allocator,
        params: BulletproofParams,
        value: u64,
        blinding: Scalar,
        min_value: u64,
        max_value: u64,
    ) !RangeProof;
    
    /// Verify a range proof
    pub fn verifyRange(
        params: BulletproofParams,
        commitment: Commitment,
        proof: RangeProof,
        min_value: u64,
        max_value: u64,
    ) !bool;
    
    /// Aggregate multiple range proofs
    pub fn aggregateRangeProofs(
        allocator: std.mem.Allocator,
        params: BulletproofParams,
        values: []const u64,
        blindings: []const Scalar,
        min_values: []const u64,
        max_values: []const u64,
    ) !RangeProof;
    
    /// Batch verify multiple range proofs
    pub fn batchVerifyRangeProofs(
        params: BulletproofParams,
        commitments: []const Commitment,
        proofs: []const RangeProof,
        min_values: []const u64,
        max_values: []const u64,
    ) !bool;
};
```

---

## ⚡ **ASSEMBLY OPTIMIZATIONS**

### **x86_64 Optimizations**

#### `zcrypto.asm.x86_64`

```zig
pub const x86_64 = struct {
    /// AVX2 optimized ChaCha20
    pub fn chacha20_avx2(
        input: []const u8,
        key: []const u8,
        nonce: []const u8,
        output: []u8
    ) void;
    
    /// AVX-512 optimized ChaCha20
    pub fn chacha20_avx512(
        input: []const u8,
        key: []const u8,
        nonce: []const u8,
        output: []u8
    ) void;
    
    /// AVX2 optimized AES-GCM
    pub fn aes_gcm_encrypt_avx2(
        plaintext: []const u8,
        key: []const u8,
        iv: []const u8,
        ciphertext: []u8
    ) void;
    
    /// AVX-512 optimized AES-GCM
    pub fn aes_gcm_encrypt_avx512(
        plaintext: []const u8,
        key: []const u8,
        iv: []const u8,
        ciphertext: []u8
    ) void;
    
    /// Vectorized field arithmetic for elliptic curves
    pub fn curve25519_mul_avx2(point: *[32]u8, scalar: []const u8) void;
    
    /// Optimized polynomial multiplication for post-quantum crypto
    pub fn poly_mul_ntt_avx2(
        poly_a: []const u16,
        poly_b: []const u16,
        result: []u16
    ) void;
};
```

### **ARM NEON Optimizations**

#### `zcrypto.asm.aarch64`

```zig
pub const aarch64 = struct {
    /// NEON optimized AES-GCM
    pub fn aes_gcm_encrypt_neon(
        plaintext: []const u8,
        key: []const u8,
        iv: []const u8,
        ciphertext: []u8
    ) void;
    
    /// ARM SHA instructions
    pub fn sha256_neon(input: []const u8, output: *[32]u8) void;
    pub fn sha512_neon(input: []const u8, output: *[64]u8) void;
    
    /// NEON optimized ChaCha20
    pub fn chacha20_neon(
        input: []const u8,
        key: []const u8,
        nonce: []const u8,
        output: []u8
    ) void;
    
    /// Vectorized curve operations
    pub fn curve25519_mul_neon(point: *[32]u8, scalar: []const u8) void;
    
    /// Optimized polynomial operations for PQ crypto
    pub fn poly_reduce_neon(poly: []u16) void;
};
```

---

## 🔗 **FOREIGN FUNCTION INTERFACE**

### **C API Exports**

#### Hash Functions

```c
typedef struct {
    bool success;
    uint32_t data_len;
    uint32_t error_code;
} CryptoResult;

// Hash functions
CryptoResult zcrypto_sha256(const uint8_t* input, uint32_t input_len, uint8_t* output);
CryptoResult zcrypto_blake2b(const uint8_t* input, uint32_t input_len, uint8_t* output);
CryptoResult zcrypto_sha3_256(const uint8_t* input, uint32_t input_len, uint8_t* output);
```

#### Classical Cryptography

```c
// Ed25519
CryptoResult zcrypto_ed25519_keygen(uint8_t* public_key, uint8_t* private_key);
CryptoResult zcrypto_ed25519_sign(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* private_key,
    uint8_t* signature
);
CryptoResult zcrypto_ed25519_verify(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* signature,
    const uint8_t* public_key
);

// X25519
CryptoResult zcrypto_x25519_keygen(uint8_t* public_key, uint8_t* private_key);
CryptoResult zcrypto_x25519_exchange(
    const uint8_t* private_key,
    const uint8_t* peer_public_key,
    uint8_t* shared_secret
);

// Symmetric encryption
CryptoResult zcrypto_aes256_gcm_encrypt(
    const uint8_t* plaintext, uint32_t plaintext_len,
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* ciphertext,
    uint8_t* tag
);
```

#### Post-Quantum Cryptography

```c
// ML-KEM-768
CryptoResult zcrypto_ml_kem_768_keygen(uint8_t* public_key, uint8_t* secret_key);
CryptoResult zcrypto_ml_kem_768_encapsulate(
    const uint8_t* public_key,
    uint8_t* ciphertext,
    uint8_t* shared_secret
);
CryptoResult zcrypto_ml_kem_768_decapsulate(
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret
);

// ML-DSA-65
CryptoResult zcrypto_ml_dsa_65_keygen(uint8_t* public_key, uint8_t* secret_key);
CryptoResult zcrypto_ml_dsa_65_sign(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* secret_key,
    uint8_t* signature
);
CryptoResult zcrypto_ml_dsa_65_verify(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* signature,
    const uint8_t* public_key
);

// Hybrid operations
CryptoResult zcrypto_hybrid_x25519_ml_kem_kex(
    uint8_t* shared_secret,
    const uint8_t* classical_public,
    const uint8_t* pq_public
);
```

#### QUIC Integration

```c
// QUIC post-quantum key exchange
CryptoResult zcrypto_quic_pq_keygen(
    uint8_t* classical_share,
    uint8_t* pq_share,
    const uint8_t* entropy
);

CryptoResult zcrypto_quic_pq_process(
    const uint8_t* client_classical,
    const uint8_t* client_pq,
    uint8_t* server_classical,
    uint8_t* server_pq,
    uint8_t* shared_secret
);

// Zero-copy packet operations
CryptoResult zcrypto_quic_encrypt_packet_inplace(
    uint8_t* packet,
    uint32_t packet_len,
    uint32_t header_len,
    uint64_t packet_number,
    const uint8_t* keys
);

CryptoResult zcrypto_quic_decrypt_packet_inplace(
    uint8_t* packet,
    uint32_t packet_len,
    uint32_t header_len,
    uint64_t packet_number,
    const uint8_t* keys
);
```

#### Zero-Knowledge Proofs

```c
// Bulletproofs range proofs
CryptoResult zcrypto_bulletproof_prove_range(
    uint64_t value,
    const uint8_t* blinding,
    uint64_t min_value,
    uint64_t max_value,
    uint8_t* proof,
    uint32_t* proof_len
);

CryptoResult zcrypto_bulletproof_verify_range(
    const uint8_t* commitment,
    const uint8_t* proof,
    uint32_t proof_len,
    uint64_t min_value,
    uint64_t max_value
);

// Groth16 zk-SNARKs
CryptoResult zcrypto_groth16_prove(
    const uint8_t* proving_key,
    const uint8_t* witness,
    uint8_t* proof
);

CryptoResult zcrypto_groth16_verify(
    const uint8_t* verifying_key,
    const uint8_t* public_inputs,
    uint32_t public_inputs_len,
    const uint8_t* proof
);
```

---

## ⚠️ **ERROR HANDLING**

### **Error Types**

```zig
pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    InvalidCiphertext,
    InvalidLength,
    EncryptionFailed,
    DecryptionFailed,
    SigningFailed,
    VerificationFailed,
    KeyGenerationFailed,
    InvalidInput,
    InsufficientBuffer,
    UnsupportedAlgorithm,
};

pub const PQError = error{
    KeyGenFailed,
    EncapsFailed,
    DecapsFailed,
    SigningFailed,
    VerificationFailed,
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidCiphertext,
    InvalidSignature,
    InvalidSharedSecret,
    UnsupportedParameter,
};

pub const QuicError = error{
    InvalidConnectionId,
    InvalidPacketNumber,
    InvalidKeys,
    PacketDecryptionFailed,
    HeaderProtectionFailed,
    KeyDerivationFailed,
    InvalidCipherSuite,
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    PQHandshakeFailed,
    HybridModeRequired,
    UnsupportedPQAlgorithm,
};
```

### **Error Handling Patterns**

```zig
// Basic error handling
const result = zcrypto.hash.sha256(input) catch |err| {
    switch (err) {
        error.InvalidInput => {
            // Handle invalid input
        },
        else => return err,
    }
};

// Optional results for fallible operations
const keypair = zcrypto.asym.Ed25519.KeyPair.generate() catch |err| {
    std.log.err("Key generation failed: {}", .{err});
    return err;
};

// Error propagation
fn encryptData(data: []const u8) ![]u8 {
    const key = try generateKey();
    const encrypted = try zcrypto.sym.aes256_gcm_encrypt(data, &key, &nonce, buffer, &tag);
    return encrypted;
}
```

---

## 💾 **MEMORY MANAGEMENT**

### **Stack-Only Operations**

```zig
// Most cryptographic operations use stack allocation
var keypair: zcrypto.asym.Ed25519.KeyPair = undefined;
try zcrypto.asym.Ed25519.KeyPair.generate(&keypair);

// Zero-copy operations
var packet_buffer: [1500]u8 = undefined;
const encrypted_len = try quic_crypto.encryptPacket(
    .application,
    false,
    packet_number,
    header,
    payload,
    &packet_buffer
);
```

### **Allocator-Based Operations**

```zig
// Operations requiring dynamic allocation
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();

// ZKP operations
var circuit = try zcrypto.zkp.groth16.Circuit.createMultiplicationCircuit(allocator);
defer circuit.deinit(allocator);

var keys = try zcrypto.zkp.groth16.setup(allocator, circuit);
defer keys.proving_key.deinit(allocator);
defer keys.verifying_key.deinit(allocator);
```

### **Secure Memory Handling**

```zig
// Secure zeroing of sensitive data
var secret_key: [32]u8 = undefined;
defer zcrypto.util.secureZero(&secret_key);

// Constant-time operations
const keys_equal = zcrypto.util.constantTimeCompare(&key1, &key2);

// Protected stack operations
const result = zcrypto.util.withStackProtection(struct {
    fn compute() u32 {
        // Sensitive computation here
        return secret_computation();
    }
}.compute);
```

---

## ⚙️ **CONFIGURATION**

### **Global Configuration**

```zig
pub const Config = struct {
    preferred_hash: HashAlgorithm = .SHA3_256,
    preferred_aead: AeadAlgorithm = .ChaCha20Poly1305,
    preferred_kem: KemAlgorithm = .ML_KEM_768,
    preferred_signature: SignatureAlgorithm = .ML_DSA_65,
    use_asm_optimizations: bool = true,
    constant_time_verification: bool = true,
    side_channel_protection: bool = true,
};

pub fn setGlobalConfig(config: Config) void;
pub fn getGlobalConfig() Config;
```

### **Algorithm Selection**

```zig
pub const HashAlgorithm = enum {
    SHA256,
    SHA3_256,
    SHA3_512,
    BLAKE2b,
};

pub const AeadAlgorithm = enum {
    AES128_GCM,
    AES256_GCM,
    ChaCha20Poly1305,
};

pub const KemAlgorithm = enum {
    X25519,
    ML_KEM_768,
    X25519_ML_KEM_768_Hybrid,
};

pub const SignatureAlgorithm = enum {
    Ed25519,
    ML_DSA_65,
    SLH_DSA_128s,
    Ed25519_ML_DSA_65_Hybrid,
};
```

### **Feature Flags**

```zig
// Compile-time feature selection
pub const features = struct {
    pub const enable_pq_algorithms = @import("builtin").is_feature_enabled("pq");
    pub const enable_zkp = @import("builtin").is_feature_enabled("zkp");
    pub const enable_asm_optimizations = @import("builtin").is_feature_enabled("asm");
    pub const enable_protocols = @import("builtin").is_feature_enabled("protocols");
    pub const enable_quic = @import("builtin").is_feature_enabled("quic");
};
```

---

## 🎯 **PERFORMANCE TUNING**

### **Optimization Levels**

```zig
// Performance-critical path optimizations
pub const OptimizationLevel = enum {
    Debug,      // Maximum safety checks
    Balanced,   // Balanced performance and safety
    Performance, // Maximum performance
    Size,       // Minimal code size
};

pub fn setOptimizationLevel(level: OptimizationLevel) void;
```

### **Batch Operations**

```zig
// Batch processing for high throughput
pub fn batchEncrypt(
    algorithm: AeadAlgorithm,
    plaintexts: []const []const u8,
    keys: []const []const u8,
    nonces: []const []const u8,
    ciphertexts: [][]u8,
    tags: [][]u8,
) CryptoError!void;

// SIMD-optimized batch operations
pub fn batchHash(
    algorithm: HashAlgorithm,
    inputs: []const []const u8,
    outputs: [][]u8,
) CryptoError!void;
```

---

**🚀 This API reference provides comprehensive coverage of zcrypto v0.5.0's post-quantum cryptographic capabilities, ready for integration across all GhostChain services and beyond!**
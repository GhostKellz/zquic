# SSH/QUIC Secret Injection

> **Status:** Draft integration. Implements pre-derived secret injection for [draft-denis-ssh-quic](https://datatracker.ietf.org/doc/draft-denis-ssh-quic/), but does not replace SSH key exchange, transcript validation, replay protection, or draft-version negotiation.

## Overview

SSH/QUIC integration allows QUIC connections to bypass the TLS 1.3 handshake by injecting secrets derived from an SSH key exchange. Treat this as an opt-in draft path. It is useful for:

- **SSH-over-QUIC tunnels** — Establish QUIC transport after SSH authentication
- **Reduced latency** — Skip TLS handshake when SSH has already authenticated the peers
- **Hybrid environments** — Bridge SSH infrastructure with QUIC-based services

## How It Works

Per the SSH/QUIC specification, after completing an SSH key exchange (producing shared secret `K` and exchange hash `H`), both peers derive QUIC secrets:

```
client_secret = HMAC-SHA256("ssh/quic client", mpint(K) || string(H))
server_secret = HMAC-SHA256("ssh/quic server", mpint(K) || string(H))
```

These 32-byte secrets are then used to initialize QUIC crypto state directly, skipping the TLS handshake entirely.
The two secrets must be distinct, non-zero, and direction-specific. zquic rejects all-zero secrets and reused client/server secrets.

```
SSH Key Exchange ──▶ Derive Secrets ──▶ SshQuicContext ──▶ QUIC Ready
     (K, H)         (HMAC-SHA256)       (bypasses TLS)    (encrypt/decrypt)
```

## Architecture

### Components

| Type | Purpose |
|------|---------|
| `SshQuicSecrets` | Container for pre-derived 32-byte client/server secrets |
| `SshQuicContext` | Extended TLS context supporting SSH secret injection |

### Key Direction

QUIC uses separate keys for each direction of traffic:

| Peer | Local Keys (sending) | Remote Keys (receiving) |
|------|---------------------|------------------------|
| Client | `client_keys` | `server_keys` |
| Server | `server_keys` | `client_keys` |

This ensures proper bidirectional encryption where each peer encrypts with their own keys and decrypts with the peer's keys.

## Getting Started

### Basic Usage

```zig
const zquic = @import("zquic");
const SshQuic = zquic.SshQuic;

// After SSH key exchange, you have K (shared secret) and H (exchange hash).
// Derive the secrets per draft-denis-ssh-quic (this part is your responsibility):
//   client_secret = HMAC-SHA256("ssh/quic client", mpint(K) || string(H))
//   server_secret = HMAC-SHA256("ssh/quic server", mpint(K) || string(H))

const client_secret: [32]u8 = derivedClientSecret();
const server_secret: [32]u8 = derivedServerSecret();

// Initialize secrets container
var secrets = SshQuic.SshQuicSecrets.init(client_secret, server_secret);
defer secrets.zeroize();  // IMPORTANT: Clear sensitive data when done

// Create SSH/QUIC context (bypasses TLS handshake)
var ctx = try SshQuic.SshQuicContext.initWithSshSecrets(
    allocator,
    is_server,  // true for server, false for client
    &secrets,
);
defer ctx.deinit();

// Ready immediately - no handshake needed!
std.debug.assert(ctx.isReady());
std.debug.assert(ctx.isSshMode());
```

### Encrypting/Decrypting Data

```zig
// Client sending to server
const plaintext = "Hello from client";
const packet_number: u64 = 1;

const ciphertext = try ctx.encrypt(plaintext, packet_number, allocator);
defer allocator.free(ciphertext);

// Server receiving from client
const decrypted = try server_ctx.decrypt(ciphertext, packet_number, allocator);
defer allocator.free(decrypted);

// decrypted == plaintext
```

### Minimizing Secret Copies (Security Best Practice)

```zig
// Use initFromPtrs to avoid copying secrets onto the stack
const client_secret: [32]u8 = ...;
const server_secret: [32]u8 = ...;

var secrets = SshQuic.SshQuicSecrets.initFromPtrs(&client_secret, &server_secret);
defer secrets.zeroize();

// Now explicitly zero the source arrays too
std.crypto.secureZero(u8, &client_secret);
std.crypto.secureZero(u8, &server_secret);
```

### Fallback to TLS Mode

The same context type supports standard TLS handshake for non-SSH scenarios:

```zig
// Standard TLS mode (requires handshake)
var ctx = SshQuic.SshQuicContext.initWithTls(allocator, is_server);
defer ctx.deinit();

std.debug.assert(!ctx.isSshMode());
std.debug.assert(!ctx.isReady());  // Needs TLS handshake first
```

## API Reference

### SshQuicSecrets

```zig
pub const SshQuicSecrets = struct {
    client_secret: [32]u8,
    server_secret: [32]u8,

    /// Initialize from 32-byte secrets (copies values)
    pub fn init(client_secret: [32]u8, server_secret: [32]u8) Self;

    /// Initialize from pointers (avoids stack copies)
    pub fn initFromPtrs(client_secret: *const [32]u8, server_secret: *const [32]u8) Self;

    /// Derive QUIC crypto keys from SSH secrets
    pub fn deriveKeys(self: *const Self) !struct { client: CryptoKeys, server: CryptoKeys };

    /// Securely zero secrets (call after initializing context)
    pub fn zeroize(self: *Self) void;
};
```

### SshQuicContext

```zig
pub const SshQuicContext = struct {
    /// Initialize with SSH-derived secrets (bypasses TLS)
    pub fn initWithSshSecrets(
        allocator: std.mem.Allocator,
        is_server: bool,
        secrets: *const SshQuicSecrets,
    ) !Self;

    /// Initialize with standard TLS handshake
    pub fn initWithTls(allocator: std.mem.Allocator, is_server: bool) Self;

    /// Clean up (automatically zeros key material)
    pub fn deinit(self: *Self) void;

    /// Check if using SSH mode (true) or TLS mode (false)
    pub fn isSshMode(self: *const Self) bool;

    /// Check if ready to encrypt/decrypt (always true in SSH mode)
    pub fn isReady(self: *const Self) bool;

    /// Encrypt data for sending (uses local keys)
    pub fn encrypt(self: *const Self, plaintext: []const u8, packet_number: u64, allocator: std.mem.Allocator) ![]u8;

    /// Decrypt received data (uses remote keys)
    pub fn decrypt(self: *const Self, ciphertext: []const u8, packet_number: u64, allocator: std.mem.Allocator) ![]u8;

    /// Get underlying TLS context for advanced use
    pub fn getTlsContext(self: *Self) *TlsContext;

    /// Get local keys (for sending)
    pub fn getLocalKeys(self: *const Self) ?*const CryptoKeys;

    /// Get remote keys (for receiving)
    pub fn getRemoteKeys(self: *const Self) ?*const CryptoKeys;
};
```

## Security Considerations

### Secret Handling

1. **Minimize lifetime** — Call `secrets.zeroize()` immediately after creating the context
2. **Avoid copies** — Use `initFromPtrs()` and pass secrets by pointer
3. **Automatic cleanup** — `SshQuicContext.deinit()` zeros all key material automatically
4. **Preserve directionality** — Client traffic uses `client_secret`; server traffic uses `server_secret`

### What This Module Does NOT Do

- **SSH key exchange** — You must perform SSH key exchange separately and derive the secrets
- **HMAC-SHA256 derivation** — The module accepts pre-derived 32-byte secrets only
- **SSH protocol handling** — This is purely for QUIC crypto initialization

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Secret leakage via stack | `zeroize()` and `secureZero()` clear memory |
| Key material in core dumps | Automatic zeroing on `deinit()` |
| Wrong key direction | Separate `local_keys`/`remote_keys` prevent misuse |
| Zero or reused directional secrets | `SshQuicSecrets.validate()` rejects invalid inputs |
| Packet tamper or packet-number mismatch | AEAD authentication fails and returns `CryptoError` |

## Maturity Checklist

- [ ] Implement proper HMAC-SHA256 derivation from SSH K and H values
- [ ] Integrate with your SSH library (libssh, openssh, etc.)
- [ ] Add replay protection for packet numbers
- [ ] Consider key rotation for long-lived connections
- [ ] Test bidirectional communication under packet loss
- [ ] Track draft changes and negotiate compatible SSH/QUIC versions

## References

- [draft-denis-ssh-quic](https://datatracker.ietf.org/doc/draft-denis-ssh-quic/) — SSH/QUIC specification
- [RFC 9000](https://datatracker.ietf.org/doc/rfc9000/) — QUIC transport protocol
- [RFC 4253](https://datatracker.ietf.org/doc/rfc4253/) — SSH transport layer (key exchange)

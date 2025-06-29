# 🔗 INTEGRATION.md – GhostChain Project Integration Guide

This document provides a unified integration reference for all GhostChain core projects, including Zig and Rust libraries such as `zwallet`, `zsig`, `zcrypto`, `ghostbridge`, `ghostlink`, `enoc`, `ghostd`, `walletd`, and associated VMs and identity layers. Use this guide when wiring together FFI interfaces, libraries, or service layers.

---

## 🧩 Project Integration Matrix

| Project        | Type     | Language | Integrates With                      | Notes                                        |
| -------------- | -------- | -------- | ------------------------------------ | -------------------------------------------- |
| `zwallet`      | Library  | Zig      | `walletd`, `ghostd`                  | Zig CLI + FFI for account/key handling       |
| `realid`       | Library  | Zig      | `walletd`, `ghostd`, `znsd`          | Identity + Signing (FFI-exported)            |
| `zsig`         | Library  | Zig      | `walletd`, `ghostd`                  | Signature + verification helpers             |
| `zcrypto`      | Library  | Zig      | `walletd`, `ghostd`                  | Cryptographic primitives                     |
| `gcrypt`       | Library  | Rust     | `ghostd`, `walletd`                  | Rust-native crypto tools                     |
| `ghostbridge`  | Daemon   | Zig      | All gRPC services                    | gRPC relay over QUIC                         |
| `ghostlink`    | Utility  | Zig      | `ghostd`, `ghostbridge`              | Identity + P2P handshake client library      |
| `enoc`         | Node     | Zig      | `ghostd`, `ghostbridge`, `walletd`   | Zig prototype of GhostChain runtime          |
| `walletd`      | Service  | Rust     | `zwallet`, `realid`, `zsig`          | Key mgmt, signing, identity API              |
| `ghostd`       | Node     | Rust     | `walletd`, `zvm`, `rvm`, `ghostlink` | Blockchain daemon, primary chain logic       |
| `zvm` / `zevm` | Runtime  | Rust     | `ghostd`, `walletd`                  | Smart contracts on GhostChain (WASM, hybrid) |
| `rvm` / `revm` | Runtime  | Rust     | `ghostd`, `walletd`                  | EVM-compatible, used for ETH/ENS integration |
| `wraith`       | Proxy    | Zig      | All services                         | QUIC-based reverse proxy and edge router     |
| `cns`          | Resolver | Zig      | `znsd`, `ghostd`, `walletd`          | IPv6/QUIC resolver for ENS, ZNS, UD          |
| `zns`          | Resolver | Zig      | `walletd`, `ghostd`, `znsd`          | GhostChain's ENS alternative                 |
| `jarvis`       | Agent    | TBD      | `walletd`, `ghostd`, `znsd`          | AI-driven automation for smart contract ops  |

---

## 💼 ZWallet Integration

To integrate your Zig-based `zwallet` project with `walletd` and `ghostd`, follow the FFI standard below:

### 1. 🔧 FFI Interface Requirements

Implement the following C ABI functions in `src/ffi.zig`:

```zig
pub export fn zwallet_init(...) callconv(.C) ...;
pub export fn zwallet_destroy(...) callconv(.C) ...;
pub export fn zwallet_create_account(...) callconv(.C) ...;
pub export fn zwallet_get_balance(...) callconv(.C) ...;

pub export fn realid_init(...) callconv(.C) ...;
pub export fn realid_generate_identity(...) callconv(.C) ...;
pub export fn realid_sign_data(...) callconv(.C) ...;
pub export fn realid_verify_signature(...) callconv(.C) ...;
```

### 2. 📦 Data Structure Compatibility

Ensure structs in Zig match the C headers and Rust FFI:

```zig
const ZWalletContext = extern struct { ... };
const WalletAccount = extern struct { ... };
const RealIdContext = extern struct { ... };
const ZidIdentity = extern struct { ... };
const SignatureResult = extern struct { ... };
```

Support both `Ed25519` and `Secp256k1` types.

### 3. ⚙️ Build System Integration

* Compile `zwallet` to `.a` or `.so`:

```bash
zig build-lib src/main.zig -target native-native-gnu -dynamic -O ReleaseFast
```

* In Rust (`build.rs`):

```rust
println!("cargo:rustc-link-lib=dylib=zwallet");
println!("cargo:rustc-link-search=native=./zig-out/lib");
```

---

## 📡 ghostbridge Integration

* Expose your Rust/Zig services via gRPC (use `tonic` or `zig-grpc`)
* QUIC-based transport via GhostBridge allows cross-platform, encrypted API layers
* Use GhostBridge to forward:

  * `walletd` → `ghostd`
  * `ghostd` → `ghostbridge` → edge nodes/clients

---

## 🔐 Crypto & Signing (zsig / zcrypto / gcrypt)

* `zsig` and `zcrypto` are core Zig cryptographic libraries
* `gcrypt` is a Rust-native fallback or companion lib
* Ensure consistent encoding (SHA256, Blake3, hex/base58)
* Use extern `C` for cross-lang compatibility

---

## 🔐 Identity Integration (`realid`)

* Zig library for passphrase → keypair + QID
* Used in `walletd` and `ghostd`
* FFI-exported and embeddable via `librealid.a`

---

## 📜 Standard Function Naming

| Prefix       | Used For            |
| ------------ | ------------------- |
| `zwallet_`   | Wallet/account ops  |
| `realid_`    | Identity/signature  |
| `zcrypto_`   | Crypto utils        |
| `zsig_`      | Signature support   |
| `ghostd_`    | Blockchain node     |
| `walletd_`   | Wallet microservice |
| `ghostlink_` | P2P & session link  |
| `wraith_`    | QUIC proxy ops      |
| `cns_`       | Name resolution     |

---

## ✅ Integration Summary

* Use FFI or gRPC to bind Zig to Rust
* Standardize function names and C ABI exports
* Compile static/shared libraries for each Zig project
* Link against them in Rust projects (`walletd`, `ghostd`)
* Use GhostBridge and CNS/ZNS for secure transport + identity resolution

---

## 🧪 Status Tracking (Dev Checklist)

* [x] `zwallet` → FFI interface
* [x] `realid` → compiled + integrated
* [x] `zsig/zcrypto` → usable via C ABI
* [ ] `walletd` → linked to Zig libs
* [ ] `ghostd` → running with Zig VM + identity
* [ ] `ghostbridge` → multiplexing QUIC over IPv6
* [ ] `ghostlink` → active session handshake with `ghostd`
* [ ] `enoc` → running prototype w/ ghostchain logic
* [ ] `wraith` → proxy config + edge transport
* [ ] `cns` → live resolution for `.ghost`, `.zns`, `.eth`
* [ ] `jarvis` → service orchestration layer

---

## 📜 License

MIT © GhostKellz


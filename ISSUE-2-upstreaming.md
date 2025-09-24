# Issue #2: Upstreaming to the Zig Standard Library

**Opened by:** @theoparis
**Status:** Open
**Type:** Discussion/Enhancement

## Discussion Points

- **QUIC/HTTP3 in std.http**: The Zig standard library currently lacks QUIC and HTTP/3 support
- **Upstream acceptance**: Question about whether the Zig core team would accept QUIC implementation contributions
- **Implementation readiness**: This zquic project could potentially serve as a foundation for upstream contribution

- Potential contribution to Zig standard library's HTTP implementation

## Next Steps

- [x] Evaluate current zquic implementation for upstream readiness
- [x] Research Zig standard library contribution guidelines
- [ ] Review the accidentally created pull request
- [ ] Engage with Zig core team about QUIC/HTTP3 interest
- [x] Prepare zquic v0.9.0 for potential upstream contribution

## v0.9.0 Upstreaming Preparation

### Completed Improvements

1. **Modular Architecture**: Resolved module conflicts and simplified build system for better maintainability
2. **Clean API Design**: Core QUIC functionality is well-structured with clear separation of concerns
3. **Zig Standards Compliance**: 
   - Proper error handling with Zig's error system
   - Memory-safe implementations using Zig's allocator system
   - Async/await support using Zig's native async runtime
   - Comprehensive documentation comments

### Key Features for Upstream Consideration

- **Production Ready**: zquic v0.9.0 provides enterprise-grade QUIC/HTTP3 implementation
- **Performance**: Sub-millisecond HTTP/3 with zsync async pipeline
- **Security**: Post-quantum cryptography support, comprehensive TLS 1.3
- **Modularity**: Feature-gated compilation for optimal binary sizes
- **Cross-Platform**: Linux, macOS, Windows support
- **FFI Ready**: C/Rust bindings for integration with existing systems

### Upstream Contribution Strategy

1. **std.http Integration Path**:
   - Propose `std.http.QuicTransport` as new transport layer
   - HTTP/3 client/server implementations building on existing HTTP infrastructure
   - Maintain compatibility with existing `std.http` APIs

2. **Separate Package Option**:
   - If full std integration is not ready, propose as official Zig package
   - Similar to how other complex libraries (crypto, parsing) are handled

3. **Gradual Integration**:
   - Start with QUIC transport layer
   - Add HTTP/3 support incrementally
   - Ensure comprehensive test coverage

### Prerequisites for Upstream

- [ ] Comprehensive test suite (100% coverage target)
- [ ] Performance benchmarks against other QUIC implementations
- [ ] Security audit and formal verification where possible
- [ ] Documentation for integration into std.http
- [ ] Zig core team engagement and feedback incorporation

### Next Actions

1. Complete v0.9.0 RC1 with clean builds and full test coverage
2. Create upstream contribution proposal document
3. Engage with Zig community and core team
4. Prepare formal contribution PR if accepted


## Potential Concerns 
  - Size: QUIC is substantial - std team might prefer separate package initially.
  
  - Maintenance burden: Core team needs to maintain whatever getsaccepted
  
  - API stability: std library APIs need long-term stability guarantees.

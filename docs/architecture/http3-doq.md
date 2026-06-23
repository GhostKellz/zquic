# HTTP/3 And DoQ Architecture

HTTP/3 and DNS-over-QUIC both sit on the same QUIC stream table but have
different lifecycle rules.

## HTTP/3 Server Lifecycle

```mermaid
flowchart TD
    CONN["QUIC connection"] --> EVENTS["Stream events"]
    EVENTS --> ACCEPT["Advanced HTTP/3 acceptance\nstop if shutdown or overloaded"]
    ACCEPT --> REQ["Request parse\nheaders/body"]
    REQ --> MW["Middleware stack"]
    MW --> ROUTER["Router\nroute, 404, 405"]
    ROUTER --> RESP["Response frames\nHEADERS + DATA"]
    RESP --> STREAM["Same request stream"]
    ACCEPT -. graceful shutdown .-> GOAWAY["GOAWAY + CONNECTION_CLOSE"]
```

## DoQ Server Lifecycle

```mermaid
flowchart TD
    STREAM["QUIC stream"] --> LEN["2-byte length prefix"]
    LEN --> DNS["DNS wire parser\ncompression aware"]
    DNS --> HANDLER["Resolver handler"]
    HANDLER --> RCODE["NOERROR / NXDOMAIN / SERVFAIL"]
    RCODE --> SERIALIZE["DNS response serialization"]
    SERIALIZE --> OUT["Length-framed stream response"]

    DNS -. malformed .-> FAIL["query failure metric"]
    HANDLER -. timeout/cancel .-> CLEANUP["pending query cleanup"]
```

## Hardening Coverage

| Area | Coverage |
|------|----------|
| Body limits | Oversized request bodies produce 413 and clean active request state |
| Response streaming | Responses generate HTTP/3 frame sequences on the request stream |
| Middleware cleanup | Route handling tests verify short-circuit and global middleware behavior |
| 404/405 | Router tests cover fallback and `allow` header generation |
| Concurrent streams | Stream IDs stay isolated across concurrent requests |
| DoQ compression | Valid pointers parse; malformed compression pointers reject |
| DoQ lifecycle | Pending queries can be cancelled, timed out, and freed on deinit |
| Oversized DNS | Oversized and over-counted DNS messages reject deterministically |

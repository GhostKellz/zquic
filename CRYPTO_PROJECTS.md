# ZQUIC for CNS & Ghostplane L2 Crypto Projects

## What is ZQUIC?

ZQUIC is a **quantum-resistant QUIC protocol** implementation. Think of it as HTTPS but:
- **Faster** (0-RTT handshakes)
- **Quantum-safe** (ML-KEM-768 + X25519 hybrid crypto)
- **Built for blockchain** (optimized for L2s and decentralized networks)

## Quick Start for Crypto Projects

### 1. Installation

```bash
# For Node.js projects
npm install zquic

# For Rust projects
cargo add zquic

# For Go projects
go get github.com/your-org/zquic
```

### 2. Basic Integration for CNS/Ghostplane L2

#### Client Setup (Connect to Your L2 Node)

```javascript
const { ZquicClient } = require('zquic');

// Initialize client with your L2 endpoint
const client = new ZquicClient({
  // Replace with your actual L2 node
  endpoint: 'your-l2-node.ghostplane.io:4433',
  
  // Your project's certificate (get from your L2 provider)
  cert: '/path/to/your-cert.pem',
  key: '/path/to/your-key.pem',
  
  // Enable quantum-resistant crypto
  quantumSafe: true,
  
  // Connection pooling for better performance
  poolSize: 10
});

// Connect and send data
async function sendTransaction(txData) {
  try {
    const stream = await client.connect();
    const response = await stream.send(txData);
    console.log('Transaction sent:', response);
  } catch (err) {
    console.error('Failed:', err);
  }
}
```

#### Server Setup (For Node Operators)

```javascript
const { ZquicServer } = require('zquic');

const server = new ZquicServer({
  port: 4433,
  cert: '/path/to/server-cert.pem',
  key: '/path/to/server-key.pem',
  
  // Quantum-resistant settings
  quantumSafe: true,
  
  // Performance optimizations
  congestionControl: 'bbr',  // Better for blockchain traffic
  maxStreams: 1000,
  
  // Anti-replay for security
  antiReplay: true
});

server.on('stream', (stream) => {
  stream.on('data', async (data) => {
    // Process blockchain transactions
    const tx = JSON.parse(data);
    // Your transaction processing logic
    stream.send({ status: 'confirmed', txHash: '0x...' });
  });
});

server.listen();
```

## Why ZQUIC for Blockchain?

### 1. **Quantum Resistance**
- Your L2 transactions are safe from future quantum computers
- Uses ML-KEM-768 (formerly Kyber) + X25519 hybrid

### 2. **0-RTT Connections**
- Resume connections instantly
- Perfect for frequent blockchain queries
- Reduces latency by 50%+

### 3. **Connection Pooling**
- Multiplex thousands of transactions over single connection
- Reduces overhead for high-frequency trading

### 4. **Built-in DoQ (DNS over QUIC)**
- Resolve .eth/.crypto domains securely
- No more DNS hijacking risks

## Common Use Cases

### High-Frequency Trading on L2
```javascript
// Pool connections for HFT
const hftClient = new ZquicClient({
  endpoint: 'ghostplane-hft.io:4433',
  poolSize: 50,  // 50 concurrent connections
  keepAlive: true,
  zeroRTT: true  // Enable 0-RTT for speed
});

// Fire and forget trades
async function executeTrade(order) {
  const stream = await hftClient.getStream();  // Reuses connection
  stream.sendImmediate(order);  // Non-blocking send
}
```

### Secure RPC for DeFi
```javascript
// Quantum-safe RPC client
const rpcClient = new ZquicClient({
  endpoint: 'your-defi-rpc.cns.io:4433',
  quantumSafe: true,
  tlsVersion: 'TLS_1_3',  // Enforce TLS 1.3
  verifyPeer: true  // Verify server identity
});

async function callContract(method, params) {
  const response = await rpcClient.rpc({
    jsonrpc: '2.0',
    method: method,
    params: params,
    id: Date.now()
  });
  return response.result;
}
```

### Blockchain Event Streaming
```javascript
// Subscribe to blockchain events
const eventClient = new ZquicClient({
  endpoint: 'events.ghostplane.io:4433',
  streamMode: true
});

eventClient.on('stream', (stream) => {
  stream.subscribe('blocks');
  stream.subscribe('pending_txs');
  
  stream.on('event', (event) => {
    if (event.type === 'block') {
      console.log('New block:', event.data.number);
    }
  });
});
```

## Performance Tips

1. **Enable BBR Congestion Control**
   ```javascript
   congestionControl: 'bbr'  // Better than CUBIC for crypto
   ```

2. **Use Connection Pooling**
   ```javascript
   poolSize: 20  // Adjust based on your load
   ```

3. **Enable 0-RTT for Repeat Connections**
   ```javascript
   zeroRTT: true,
   sessionCache: true
   ```

4. **Monitor with Built-in Telemetry**
   ```javascript
   telemetry: {
     endpoint: 'your-monitoring.io',
     metrics: ['latency', 'throughput', 'errors']
   }
   ```

## Security Best Practices

1. **Always Use Quantum-Safe Mode**
   ```javascript
   quantumSafe: true  // Non-negotiable for crypto
   ```

2. **Enable Anti-Replay Protection**
   ```javascript
   antiReplay: true  // Prevents replay attacks
   ```

3. **Verify Peer Certificates**
   ```javascript
   verifyPeer: true,
   ca: '/path/to/ca-bundle.pem'
   ```

4. **Rotate Session Keys**
   ```javascript
   sessionRotation: 3600  // Rotate every hour
   ```

## Troubleshooting

### "Connection refused"
- Check firewall allows UDP on port 4433
- Verify server is running with `netstat -ulnp | grep 4433`

### "Certificate verification failed"
- Ensure your cert matches the domain
- Check certificate hasn't expired
- Verify CA bundle is correct

### "Quantum crypto not available"
- Update to latest zquic version
- Ensure OpenSSL 3.0+ is installed
- Check CPU supports required instructions

## Need Help?

- **Docs**: [Full documentation link]
- **Discord**: [Your Discord for crypto devs]
- **Examples**: Check `/examples/crypto` folder

## TL;DR for Absolute Beginners

1. Install: `npm install zquic`
2. Copy the client example above
3. Replace `your-l2-node.ghostplane.io` with your actual endpoint
4. Run it
5. Your blockchain traffic is now quantum-safe and 50% faster

That's it. You're now using military-grade quantum-resistant networking for your crypto project. Welcome to the future.
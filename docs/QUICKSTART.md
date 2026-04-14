# Quick Start Guide - Post-Quantum OIDC using KEMTLS

## What You Have So Far

You have successfully implemented the **core cryptographic foundation** for Post-Quantum OpenID Connect using KEMTLS. Here's what's working:

### ✅ Working Components

1. **Post-Quantum Cryptography** (`src/pq_crypto/`)
   - Kyber KEM (all variants)
   - ML-DSA/Dilithium signatures (all variants)
   - Falcon signatures
   - Key derivation functions
   - All tested and verified

2. **KEMTLS Protocol** (`src/kemtls/`)
   - Complete handshake protocol
   - Server and client implementations
   - Certificate creation and verification
   - Session key derivation

3. **Post-Quantum JWT** (`src/oidc/`)
   - JWT creation with PQ signatures
   - JWT verification
   - ID Token creation (OIDC-compliant)
   - All standard claims supported

## Environment Setup

### One-Time Setup (Already Done)
```bash
cd /home/aniket/PQC

# Virtual environment created
# liboqs installed at ~/.local/lib
# Python packages installed
```

### Every Time You Work
```bash
cd /home/aniket/PQC
source setup_env.sh  # Sets up environment variables and activates venv
```

Or manually:
```bash
export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH
source venv/bin/activate
```

## Testing What's Built

### Test All PQ Crypto
```bash
python3 src/pq_crypto/test_crypto.py
```

**Output**: All KEM and signature algorithm tests

### Test KEMTLS Components
```bash
# Test protocol basics
python3 src/kemtls/protocol.py

# Test server
python3 src/kemtls/server.py

# Test client
python3 src/kemtls/client.py
```

### Test PQ-JWT
```bash
python3 src/oidc/pq_jwt.py
```

**Output**: JWT creation and verification with multiple algorithms

## What's Next (Your Roadmap)

### Phase 1: OIDC Server (Next 2-3 days)
Implement OpenID Connect server with these endpoints:

1. **Authorization Endpoint** (`/authorize`)
   - Handle OAuth 2.0 authorization requests
   - Generate authorization codes

2. **Token Endpoint** (`/token`)
   - Exchange authorization codes for tokens
   - Issue PQ-signed ID tokens using your `PQJWTHandler`

3. **UserInfo Endpoint** (`/userinfo`)
   - Return user claims

4. **Discovery Endpoint** (`/.well-known/openid-configuration`)
   - Advertise PQ algorithms

**Key Decision**: Use Flask for HTTP layer, but you'll replace it with KEMTLS later.

### Phase 2: OIDC Client (1-2 days)
Implement client that:
1. Initiates authorization
2. Receives authorization code
3. Exchanges for tokens
4. Validates PQ-signed tokens

### Phase 3: KEMTLS Integration (2-3 days)
Replace HTTP/TLS with your KEMTLS:
1. Wrap Flask app with KEMTLS server
2. Client uses KEMTLS instead of HTTPS
3. End-to-end PQ security

### Phase 4: Benchmarking (2-3 days)
Measure performance:
1. KEMTLS handshake time
2. JWT signing/verification time
3. End-to-end authentication latency
4. Message sizes

### Phase 5: Demo & Documentation (3-4 days)
1. Complete demo script
2. Record video
3. Write technical documentation
4. Generate benchmark reports

## Project Structure

```
PQC/
├── src/
│   ├── pq_crypto/          ✅ DONE - PQ crypto wrappers
│   ├── kemtls/             ✅ DONE - KEMTLS protocol
│   ├── oidc/               🔄 IN PROGRESS - OIDC server/client
│   │   └── pq_jwt.py       ✅ DONE
│   └── benchmarks/         ⏳ TODO
├── tests/                  ⏳ TODO
├── examples/               ⏳ TODO
├── docs/                   🔄 IN PROGRESS
└── results/                ⏳ TODO
```

## Key Files Reference

| File | Purpose | Status |
|------|---------|--------|
| `src/pq_crypto/kem.py` | Kyber KEM wrapper | ✅ Done |
| `src/pq_crypto/signature.py` | ML-DSA/Falcon wrapper | ✅ Done |
| `src/pq_crypto/utils.py` | Crypto utilities | ✅ Done |
| `src/kemtls/protocol.py` | KEMTLS protocol | ✅ Done |
| `src/kemtls/server.py` | KEMTLS server | ✅ Done |
| `src/kemtls/client.py` | KEMTLS client | ✅ Done |
| `src/oidc/pq_jwt.py` | PQ-JWT handler | ✅ Done |
| `src/oidc/server.py` | OIDC server | ⏳ Next |
| `src/oidc/client.py` | OIDC client | ⏳ Next |

## Important Notes

### Algorithms Used
- **KEM**: Kyber512 (default), also supports Kyber768, Kyber1024
- **Signatures**: ML-DSA-44 (default), also supports ML-DSA-65, ML-DSA-87, Falcon-512, Falcon-1024

### JWT Sizes
- **ML-DSA-44**: ~3.5 KB (moderate security, moderate size)
- **ML-DSA-65**: ~4.7 KB (high security, larger)
- **Falcon-512**: ~1.1 KB (smaller, good for bandwidth)

**Recommendation**: Use Falcon-512 for better performance/size tradeoff.

### Configuration
Edit `config.py` to change algorithms:
```python
KEM_ALGORITHM = "Kyber512"
SIGNATURE_ALGORITHM = "ML-DSA-44"  # or "Falcon-512"
```

## Troubleshooting

### If tests fail with "No module named 'oqs'"
```bash
# Make sure environment is activated
source setup_env.sh

# Or manually:
export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH
source venv/bin/activate
```

### If liboqs not found
```bash
# Check if library exists
ls ~/.local/lib/liboqs.so*

# If not, rebuild:
cd ~/liboqs/build
cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local -DBUILD_SHARED_LIBS=ON ..
make -j$(nproc) && make install
```

## Performance Expectations

Based on typical liboqs performance:

- **Kyber512 encapsulation**: ~50 μs
- **Kyber512 decapsulation**: ~60 μs
- **ML-DSA-44 sign**: ~500 μs
- **ML-DSA-44 verify**: ~250 μs
- **Falcon-512 sign**: ~9 ms (slower, but smaller signatures)
- **Falcon-512 verify**: ~100 μs

**KEMTLS handshake**: Expected ~1-2 ms (vs ~50-100 ms for RSA/ECDSA TLS)

## Development Tips

1. **Start with HTTP OIDC first** - Get OIDC working over plain HTTP, then add KEMTLS
2. **Test incrementally** - Test each endpoint as you build it
3. **Use the existing PQJWTHandler** - It's ready to use for token issuance
4. **Keep KEMTLS separate initially** - Integrate it last
5. **Mock user authentication** - Simple hardcoded users are fine for demo

## Need Help?

Check these files for examples:
- `src/pq_crypto/test_crypto.py` - How to use crypto functions
- `src/oidc/pq_jwt.py` - How to create and verify JWTs
- `src/kemtls/server.py` - How KEMTLS server works

## Summary

**You have built a solid foundation!** The hard cryptographic work is done. Now you need to:

1. Build standard OIDC server (use existing libraries for OAuth flow)
2. Integrate your PQ-JWT handler
3. Wrap it with your KEMTLS transport
4. Benchmark everything
5. Document and demo

**Estimated time to complete**: 2-3 weeks working steadily.

Good luck! The foundation is excellent - the rest is integration and testing.

# Technical Architecture - Post-Quantum OIDC using KEMTLS

## System Overview

This system implements OpenID Connect (OIDC) authentication with complete post-quantum security by:
1. Replacing TLS with **KEMTLS** (KEM-based Transport Layer Security)
2. Replacing RSA/ECDSA signatures with **ML-DSA** (Dilithium) or **Falcon**
3. Maintaining full OIDC protocol compliance at the application layer

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  OpenID Connect Protocol (Unchanged)                         │
│  - Authorization Flow                                        │
│  - Token Exchange                                            │
│  - UserInfo Retrieval                                        │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                  Cryptographic Layer                         │
│  Post-Quantum JWT with ML-DSA/Falcon Signatures             │
│  - ID Token Signing                                          │
│  - Access Token Signing                                      │
│  - Token Verification                                        │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                    Transport Layer                           │
│  KEMTLS (replaces TLS)                                       │
│  - Kyber KEM for key exchange                                │
│  - ML-DSA signatures for authentication                      │
│  - HKDF for session key derivation                           │
└─────────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────────┐
│                      Network Layer                           │
│  TCP/IP                                                      │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Post-Quantum Cryptography Module

#### 1.1 Key Encapsulation Mechanism (KEM)
**File**: `src/pq_crypto/kem.py`

**Purpose**: Quantum-resistant key exchange

**Algorithm**: Kyber (NIST standardized)

**Variants**:
- Kyber512: NIST Security Level 1, 800-byte public keys
- Kyber768: NIST Security Level 3, 1184-byte public keys
- Kyber1024: NIST Security Level 5, 1568-byte public keys

**Operations**:
```python
# Key generation
kem = KyberKEM("Kyber512")
public_key = kem.generate_keypair()

# Encapsulation (sender side)
ciphertext, shared_secret = kem.encapsulate(recipient_public_key)

# Decapsulation (receiver side)
shared_secret = kem.decapsulate(ciphertext)
```

**Security Properties**:
- IND-CCA2 secure
- Quantum-resistant (based on Module-LWE problem)
- Deterministic key generation
- Fixed-size outputs

#### 1.2 Digital Signatures
**File**: `src/pq_crypto/signature.py`

**Purpose**: Quantum-resistant authentication and non-repudiation

**Algorithms**:
1. **ML-DSA** (Dilithium - NIST standardized)
   - ML-DSA-44: NIST Level 2, 2420-byte signatures
   - ML-DSA-65: NIST Level 3, 3309-byte signatures
   - ML-DSA-87: NIST Level 5, 4627-byte signatures

2. **Falcon** (NIST standardized)
   - Falcon-512: NIST Level 1, 650-byte signatures (compact!)
   - Falcon-1024: NIST Level 5, 1269-byte signatures

**Operations**:
```python
# Key generation
signer = DilithiumSigner("ML-DSA-44")
public_key = signer.generate_keypair()

# Signing
signature = signer.sign(message)

# Verification
is_valid = signer.verify(message, signature, public_key)
```

**Security Properties**:
- EUF-CMA secure (Existentially Unforgeable under Chosen Message Attack)
- Quantum-resistant
- Stateless (unlike hash-based signatures)

#### 1.3 Cryptographic Utilities
**File**: `src/pq_crypto/utils.py`

**Key Functions**:

1. **Key Derivation (HKDF)**:
   ```python
   hkdf(salt, input_key_material, info, length)
   ```
   - Used to derive session keys from KEM shared secret
   - Extracts: encryption key, MAC key, IV

2. **Base64URL Encoding**:
   ```python
   base64url_encode(data) / base64url_decode(data)
   ```
   - URL-safe encoding for JWT

3. **Secure Random**:
   ```python
   generate_random_bytes(length)
   generate_nonce(length)
   ```

---

### 2. KEMTLS Protocol

#### 2.1 Protocol Overview
**Files**: `src/kemtls/protocol.py`, `src/kemtls/server.py`, `src/kemtls/client.py`

**Purpose**: Replace TLS 1.3 handshake with KEM-based handshake

**Key Innovation**: Uses Key Encapsulation Mechanisms instead of Diffie-Hellman for key exchange

#### 2.2 Handshake Flow

```
Client                                                Server
------                                                ------

1. CLIENT_HELLO
   [Client KEM Public Key, Nonce]
                            ────────────────────────>

2. SERVER_HELLO
   [KEM Ciphertext, Server Nonce, Certificate]
                            <────────────────────────

   [Both derive shared secret and session keys]

3. SERVER_FINISHED
   [Handshake MAC]
                            <────────────────────────

4. CLIENT_FINISHED
   [Handshake MAC]
                            ────────────────────────>

[Encrypted communication using derived session keys]
```

#### 2.3 Message Format

All messages follow this structure:
```
┌──────────┬─────────────┬─────────────────┐
│   Type   │   Length    │     Payload     │
│  1 byte  │  4 bytes    │   Variable      │
└──────────┴─────────────┴─────────────────┘
```

**Message Types**:
- `0x01`: CLIENT_HELLO
- `0x02`: SERVER_HELLO
- `0x05`: CLIENT_FINISHED
- `0x06`: SERVER_FINISHED
- `0x10`: ENCRYPTED_DATA
- `0xFF`: ALERT

#### 2.4 Certificate Structure

KEMTLS certificates contain:
```json
{
  "subject": "CN=server.example.com",
  "kem_public_key": "<hex-encoded-kyber-pk>",
  "sig_public_key": "<hex-encoded-mldsa-pk>",
  "signature": "<hex-encoded-signature>"
}
```

**Note**: Self-signed for this implementation (OK for demo/research)

#### 2.5 Session Key Derivation

```python
# Input: KEM shared secret (32 bytes)
# Context: Client nonce || Server nonce

# Derive using HKDF:
encryption_key = HKDF(shared_secret, context, 32)  # For AES-256
mac_key = HKDF(shared_secret, context, 32)         # For HMAC
iv = HKDF(shared_secret, context, 16)              # For AES IV
```

#### 2.6 Security Properties

- ✅ **Forward Secrecy**: Ephemeral KEM keys per session
- ✅ **Mutual Authentication**: Via certificates (optional client cert)
- ✅ **Post-Quantum Security**: Kyber + ML-DSA
- ✅ **No RSA/ECC**: Pure post-quantum stack

---

### 3. Post-Quantum JWT

#### 3.1 JWT Structure
**File**: `src/oidc/pq_jwt.py`

Standard JWT format is preserved:
```
<base64url(header)>.<base64url(payload)>.<base64url(pq-signature)>
```

**Header**:
```json
{
  "alg": "ML-DSA-44",  // or "Falcon-512", etc.
  "typ": "JWT"
}
```

**Payload (ID Token Example)**:
```json
{
  "iss": "https://pq-oidc.example.com",
  "sub": "user123",
  "aud": "client-app-id",
  "iat": 1707316781,
  "exp": 1707320381,
  "nbf": 1707316781,
  "nonce": "random-nonce",
  "auth_time": 1707316781,
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true
}
```

**Signature**:
- Computed over: `base64url(header).base64url(payload)`
- Algorithm: ML-DSA-44 / ML-DSA-65 / ML-DSA-87 / Falcon-512 / Falcon-1024
- Encoded as base64url

#### 3.2 Token Sizes

| Algorithm | Typical JWT Size | Overhead vs RSA |
|-----------|------------------|-----------------|
| ML-DSA-44 | ~3.5 KB | +2.8 KB |
| ML-DSA-65 | ~4.7 KB | +4.0 KB |
| Falcon-512 | ~1.1 KB | +0.4 KB |
| RSA-2048 | ~0.7 KB | Baseline |

**Recommendation**: Use Falcon-512 for best size/performance balance

#### 3.3 API Usage

```python
# Create handler
handler = PQJWTHandler("ML-DSA-44")
handler.generate_keypair()

# Create ID Token
id_token = handler.create_id_token(
    user_id="user123",
    client_id="webapp",
    nonce="abc123",
    additional_claims={
        "name": "John Doe",
        "email": "john@example.com"
    }
)

# Verify token
is_valid, payload = handler.verify_jwt(
    id_token,
    expected_audience="webapp"
)
```

---

### 4. OpenID Connect Layer (To Be Implemented)

#### 4.1 Authorization Server

**Endpoints**:

1. **Authorization Endpoint** (`/authorize`)
   ```
   GET /authorize?
       response_type=code&
       client_id=CLIENT_ID&
       redirect_uri=REDIRECT_URI&
       scope=openid profile email&
       state=STATE&
       nonce=NONCE
   ```
   - Authenticates user
   - Returns authorization code

2. **Token Endpoint** (`/token`)
   ```
   POST /token
   Content-Type: application/x-www-form-urlencoded
   
   grant_type=authorization_code&
   code=AUTH_CODE&
   redirect_uri=REDIRECT_URI&
   client_id=CLIENT_ID&
   client_secret=CLIENT_SECRET
   ```
   - Exchanges code for tokens
   - Returns PQ-signed ID token

3. **UserInfo Endpoint** (`/userinfo`)
   ```
   GET /userinfo
   Authorization: Bearer ACCESS_TOKEN
   ```
   - Returns user claims

4. **Discovery Endpoint** (`/.well-known/openid-configuration`)
   ```json
   {
     "issuer": "https://pq-oidc.example.com",
     "authorization_endpoint": "...",
     "token_endpoint": "...",
     "userinfo_endpoint": "...",
     "jwks_uri": "...",
     "response_types_supported": ["code"],
     "subject_types_supported": ["public"],
     "id_token_signing_alg_values_supported": [
       "ML-DSA-44", "ML-DSA-65", "Falcon-512"
     ],
     "scopes_supported": ["openid", "profile", "email"]
   }
   ```

#### 4.2 Integration with KEMTLS

Instead of running on HTTPS:
```python
# Traditional approach:
app.run(ssl_context=(...))

# PQ approach:
kemtls_server = KEMTLSServer(config)
kemtls_server.wrap_and_serve(app, host='0.0.0.0', port=8443)
```

All communication flows through KEMTLS:
- Client connects via KEMTLS
- KEMTLS handshake establishes session keys
- HTTP requests/responses encrypted with session keys
- OIDC protocol operates normally at application layer

---

## Security Analysis

### Threat Model

**Assumptions**:
1. Adversary has access to network traffic
2. Adversary has large-scale quantum computer
3. Adversary can perform man-in-the-middle attacks
4. Adversary cannot break PQC algorithms

### Security Properties Achieved

| Property | Mechanism | Status |
|----------|-----------|--------|
| Confidentiality | Kyber KEM + AES-256 | ✅ Quantum-safe |
| Authentication | ML-DSA certificates | ✅ Quantum-safe |
| Integrity | HMAC + ML-DSA signatures | ✅ Quantum-safe |
| Forward Secrecy | Ephemeral Kyber keys | ✅ Yes |
| Non-Repudiation | ML-DSA signed tokens | ✅ Quantum-safe |

### Attack Resistance

- ✅ **Quantum attacks**: All algorithms are PQC
- ✅ **Man-in-the-middle**: Certificate verification
- ✅ **Replay attacks**: Nonces + timestamps
- ✅ **Token forgery**: PQ signature verification
- ✅ **Downgrade attacks**: No classical fallback

---

## Performance Considerations

### Computational Cost

**KEMTLS Handshake** (estimated):
- Kyber512 keygen: ~30 μs
- Kyber512 encaps: ~50 μs
- Kyber512 decaps: ~60 μs
- ML-DSA-44 sign: ~500 μs
- ML-DSA-44 verify: ~250 μs
- **Total**: ~1 ms (vs ~50 ms for RSA-2048 TLS)

**JWT Operations**:
- Create ID Token: ~500 μs (ML-DSA-44) or ~9 ms (Falcon-512)
- Verify ID Token: ~250 μs (ML-DSA-44) or ~100 μs (Falcon-512)

### Bandwidth Overhead

**KEMTLS Handshake**:
- CLIENT_HELLO: ~850 bytes (Kyber512 pk + metadata)
- SERVER_HELLO: ~10 KB (ciphertext + cert with ML-DSA-44)
- Finished messages: ~200 bytes each
- **Total**: ~11 KB (vs ~3 KB for RSA/ECDSA TLS)

**Tokens**:
- ID Token: 1.1 KB (Falcon-512) to 4.7 KB (ML-DSA-65)
- Access Token: Similar

### Optimization Strategies

1. **Use Falcon-512** for JWT to reduce token size
2. **Use Kyber512** for KEMTLS (sufficient security, smaller)
3. **Session resumption** (future work)
4. **Token caching** on client side

---

## Future Enhancements

1. **Certificate Authority Integration**: Replace self-signed certs
2. **Session Resumption**: Reduce handshake overhead
3. **Multiple Client Authentication**: Mutual TLS equivalent
4. **Dynamic Algorithm Selection**: Negotiate algorithms
5. **Performance Optimizations**: Parallel signature verification
6. **Hybrid Mode**: PQC + Classical for transition period

---

## References

1. **KEMTLS Paper**: Schwabe et al., "KEMTLS: Post-quantum TLS without signatures"
2. **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography
3. **OpenID Connect Spec**: https://openid.net/specs/openid-connect-core-1_0.html
4. **liboqs**: https://github.com/open-quantum-safe/liboqs

---

## Appendix: Algorithm Parameters

### Kyber Parameters

| Variant | n | k | q | Security |
|---------|---|---|---|----------|
| Kyber512 | 256 | 2 | 3329 | NIST Level 1 |
| Kyber768 | 256 | 3 | 3329 | NIST Level 3 |
| Kyber1024 | 256 | 4 | 3329 | NIST Level 5 |

### ML-DSA Parameters

| Variant | (n,q,d) | Signature Size | Security |
|---------|---------|----------------|----------|
| ML-DSA-44 | (256, 8380417, 13) | 2420 bytes | Level 2 |
| ML-DSA-65 | (256, 8380417, 13) | 3309 bytes | Level 3 |
| ML-DSA-87 | (256, 8380417, 13) | 4627 bytes | Level 5 |

---

**Document Version**: 1.0
**Last Updated**: February 7, 2026
**Status**: Core Implementation Complete

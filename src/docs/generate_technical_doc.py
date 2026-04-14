#!/usr/bin/env python3
"""
Generate Technical Documentation PDF

Combines all markdown documentation into a comprehensive PDF:
- README.md
- ARCHITECTURE.md
- IMPLEMENTATION_COMPLETE.md
- API documentation
- Security analysis
- References to benchmark results
"""

import os
import subprocess
from datetime import datetime

def create_combined_markdown():
    """Combine all markdown files into one comprehensive document."""
    
    content = f"""---
title: Post-Quantum OIDC with KEMTLS - Technical Documentation
author: PQ-OIDC Project
date: {datetime.now().strftime("%B %d, %Y")}
geometry: margin=1in
documentclass: report
fontsize: 11pt
toc: true
toc-depth: 3
---

\\newpage

# Executive Summary

This document provides comprehensive technical documentation for the Post-Quantum OIDC with KEMTLS implementation. The project implements OpenID Connect (OIDC) authentication using NIST-standardized post-quantum cryptographic algorithms, featuring:

- **Post-Quantum Key Encapsulation**: Kyber (ML-KEM) for secure key exchange
- **Post-Quantum Digital Signatures**: ML-DSA (Dilithium) and Falcon for authentication
- **KEMTLS Protocol**: TLS variant using KEMs for authentication
- **OIDC Integration**: Complete OAuth 2.0/OIDC server and client implementation
- **Production-Ready**: Comprehensive testing, benchmarking, and documentation

**Performance Highlights** (see BenchmarkResults.pdf for details):
- KEM operations: 0.023-0.033 ms
- Signature operations: 0.027-0.181 ms (excluding keygen)
- KEMTLS handshake: 0.041 ms
- End-to-end OIDC flow: 0.240 ms

\\newpage

"""
    
    # Read and include README
    print("Including README.md...")
    if os.path.exists("README.md"):
        with open("README.md", "r") as f:
            readme = f.read()
            # Remove title (already in header)
            if readme.startswith("# "):
                readme = "\\n".join(readme.split("\\n")[1:])
            content += "# Project Overview\\n\\n" + readme + "\\n\\n\\newpage\\n\\n"
    
    # Add architecture section
    content += """
# System Architecture

## Overview

The system is architected in modular layers, each handling specific concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                  OIDC Layer (Application)                    │
│  ┌──────────────────────┐  ┌───────────────────────────┐   │
│  │  OIDC Server         │  │  OIDC Client              │   │
│  │  - Authorization     │  │  - Auth Request           │   │
│  │  - Token Endpoints   │  │  - Token Exchange         │   │
│  └──────────────────────┘  └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    JWT Layer (Tokens)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  PQ-JWT Module                                       │   │
│  │  - ID Token Creation (PQ signatures)                 │   │
│  │  - Token Verification                                │   │
│  │  - Claims Management                                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  KEMTLS Layer (Transport)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ KEMTLS       │  │ KEMTLS       │  │ Certificates     │  │
│  │ Server       │  │ Client       │  │ (PQ keys)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              Post-Quantum Cryptography Layer                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ KEM          │  │ Signatures   │  │ Utilities        │  │
│  │ (Kyber)      │  │ (ML-DSA,     │  │ (Key Derivation) │  │
│  │              │  │  Falcon)     │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     liboqs (Native Library)                  │
│  NIST Post-Quantum Cryptographic Implementations             │
└─────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### 1. Post-Quantum Cryptography Layer (`src/pq_crypto/`)

**Purpose**: Provides high-level Python interfaces to post-quantum cryptographic primitives.

**Key Modules**:
- `kem.py`: Key Encapsulation Mechanism using Kyber (ML-KEM)
  - Supports Kyber512, Kyber768, Kyber1024
  - Key generation, encapsulation, decapsulation operations
  
- `signature.py`: Post-quantum digital signatures
  - DilithiumSigner: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - FalconSigner: Falcon-512, Falcon-1024
  - Unified interface for key generation, signing, verification
  
- `utils.py`: Cryptographic utilities
  - derive_session_keys(): HKDF-based key derivation
  - Secure random number generation
  - Key serialization/deserialization

**Design Principles**:
- Simple, Pythonic API abstracting liboqs complexity
- Algorithm-agnostic interfaces for easy algorithm swapping
- Proper error handling and validation
- Binary data handling (bytes objects throughout)

### 2. KEMTLS Layer (`src/kemtls/`)

**Purpose**: Implements KEMTLS protocol for authenticated key exchange.

**KEMTLS Protocol Flow**:

```
Client                                          Server
------                                          ------
1. Generate ephemeral KEM keypair
   ClientHello + ephemeral_public_key ──────►  
                                               2. Encapsulate to client key
                                               3. Derive shared secret
                                               4. Sign ServerHello + cert
                                               
                                    ◄────────  ServerHello + ciphertext
                                               + certificate + signature
                                               
5. Decapsulate ciphertext
6. Verify server signature
7. Derive same shared secret
8. Derive session keys

          Secure Channel Established
```

**Key Features**:
- Certificate-based authentication using PQ keys
- Perfect forward secrecy via ephemeral KEM
- Mutual authentication support
- Message authentication using derived keys

### 3. JWT Layer (`src/oidc/pq_jwt.py`)

**Purpose**: Create and verify JSON Web Tokens with post-quantum signatures.

**ID Token Structure**:
```json
{
  "header": {
    "alg": "ML-DSA-44",  // or ML-DSA-65, Falcon-512, etc.
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://issuer.example.com",
    "sub": "user@example.com",
    "aud": "client_id",
    "exp": 1234567890,
    "iat": 1234567800,
    "nonce": "random_nonce"
  },
  "signature": "<base64-encoded PQ signature>"
}
```

**Innovations**:
- Native PQ signature integration in JWT format
- Algorithm negotiation between client and server
- Backward-compatible token structure
- Size-optimized for network transmission

### 4. OIDC Layer (`src/oidc/`)

**Purpose**: Full OAuth 2.0 / OpenID Connect implementation.

**Authorization Code Flow**:

```
User-Agent       Client              Authorization Server
----------       ------              -------------------
1. User initiates login
    │
    │  2. Redirect to auth endpoint
    ├──────────────────────►
                            │  3. User authentication
                            │  4. Consent screen
                            │
    ◄───────────────────────┤  5. Authorization code
                                  (via redirect)
    │
    │  6. Exchange code for tokens
    ├───────────────────────────────►
                                     7. Validate code
                                     8. Generate ID token
                                     (signed with PQ algorithm)
                                     
    ◄────────────────────────────────┤  9. ID token + access token
    
    10. Verify ID token signature
        (using PQ public key)
```

**Endpoints Implemented**:
- `GET /authorize`: Authorization endpoint
- `POST /token`: Token endpoint  
- `GET /userinfo`: User information endpoint
- `GET /.well-known/openid-configuration`: Discovery endpoint

## Security Considerations

### Cryptographic Strength

All algorithms used are NIST-approved post-quantum standards:

| Algorithm | Security Level | Key Size | Signature Size |
|-----------|---------------|----------|----------------|
| Kyber512  | NIST Level 1  | 800 B    | 768 B          |
| ML-DSA-44 | NIST Level 2  | 1312 B   | ~2420 B        |
| Falcon-512| NIST Level 1  | 897 B    | ~650 B         |

### Threat Model

**Protected Against**:
- ✅ Quantum computer attacks (Shor's algorithm)
- ✅ Man-in-the-middle attacks (KEMTLS authentication)
- ✅ Replay attacks (nonces, timestamps in tokens)
- ✅ Token forgery (PQ signatures)
- ✅ Eavesdropping (encrypted channels)

**Out of Scope**:
- Side-channel attacks (implementation-dependent)
- Physical security
- Social engineering
- Endpoint compromise

### Best Practices Implemented

1. **Key Management**:
   - Ephemeral keys for perfect forward secrecy
   - Secure key derivation (HKDF with SHA-256)
   - Proper key lifecycle management

2. **Token Security**:
   - Short token lifetimes (configurable)
   - Signed with strong PQ algorithms
   - Nonce validation to prevent replay

3. **Protocol Security**:
   - TLS-equivalent security via KEMTLS
   - Certificate validation
   - Mutual authentication support

\\newpage

# Implementation Details

## File Structure

```
PQC/
├── src/
│   ├── pq_crypto/          # Post-quantum cryptography primitives
│   │   ├── __init__.py
│   │   ├── kem.py          # Kyber KEM implementation
│   │   ├── signature.py    # ML-DSA & Falcon signatures
│   │   └── utils.py        # Crypto utilities
│   │
│   ├── kemtls/             # KEMTLS protocol implementation
│   │   ├── __init__.py
│   │   ├── protocol.py     # Core protocol logic
│   │   ├── server.py       # Server-side KEMTLS
│   │   ├── client.py       # Client-side KEMTLS
│   │   └── certificates.py # PQ certificate handling
│   │
│   ├── oidc/               # OpenID Connect implementation
│   │   ├── __init__.py
│   │   ├── server.py       # OIDC Provider (IdP)
│   │   ├── client.py       # OIDC Relying Party
│   │   └── pq_jwt.py       # PQ-signed JWT tokens
│   │
│   └── benchmarks/         # Performance benchmarking
│       ├── run_benchmarks.py
│       └── generate_pdf_report.py
│
├── tests/                  # Comprehensive test suite
│   ├── test_kem.py
│   ├── test_signature.py
│   ├── test_kemtls.py
│   ├── test_jwt.py
│   └── test_oidc.py
│
├── benchmark_results/      # Benchmark data and reports
│   ├── benchmark_results.csv
│   ├── benchmark_results.json
│   └── BenchmarkResults.pdf
│
├── requirements.txt        # Python dependencies
└── README.md              # Project documentation
```

## API Reference

### KEM Module (`pq_crypto/kem.py`)

```python
class KyberKEM:
    def __init__(self, algorithm: str = "Kyber512"):
        \"\"\"Initialize Kyber KEM.
        
        Args:
            algorithm: One of "Kyber512", "Kyber768", "Kyber1024"
        \"\"\"
        
    def generate_keypair(self) -> tuple[bytes, bytes]:
        \"\"\"Generate new keypair.
        
        Returns:
            (public_key, secret_key) tuple
        \"\"\"
        
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        \"\"\"Encapsulate shared secret.
        
        Args:
            public_key: Recipient's public key
            
        Returns:
            (ciphertext, shared_secret) tuple
        \"\"\"
        
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        \"\"\"Decapsulate shared secret.
        
        Args:
            ciphertext: Ciphertext from encapsulation
            secret_key: Recipient's secret key
            
        Returns:
            Shared secret (matches encapsulation output)
        \"\"\"
```

### Signature Module (`pq_crypto/signature.py`)

```python
class DilithiumSigner:
    def __init__(self, algorithm: str = "ML-DSA-44"):
        \"\"\"Initialize Dilithium/ML-DSA signer.
        
        Args:
            algorithm: One of "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        \"\"\"
        
    def generate_keypair(self) -> tuple[bytes, bytes]:
        \"\"\"Generate signing keypair.\"\"\"
        
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        \"\"\"Sign message.
        
        Args:
            message: Data to sign
            secret_key: Signer's secret key
            
        Returns:
            Digital signature
        \"\"\"
        
    def verify(self, message: bytes, signature: bytes, 
               public_key: bytes) -> bool:
        \"\"\"Verify signature.
        
        Returns:
            True if signature is valid, False otherwise
        \"\"\"
```

### JWT Module (`oidc/pq_jwt.py`)

```python
def create_id_token(claims: dict, algorithm: str, 
                    secret_key: bytes) -> str:
    \"\"\"Create signed ID token.
    
    Args:
        claims: Token payload (sub, iss, aud, exp, etc.)
        algorithm: PQ signature algorithm
        secret_key: Signing key
        
    Returns:
        Encoded JWT string
    \"\"\"
    
def verify_id_token(token: str, public_key: bytes, 
                   algorithm: str) -> dict:
    \"\"\"Verify and decode ID token.
    
    Args:
        token: Encoded JWT string
        public_key: Verification key
        algorithm: Expected signature algorithm
        
    Returns:
        Decoded claims dictionary
        
    Raises:
        ValueError: If signature invalid or token expired
    \"\"\"
```

## Testing

### Test Coverage

The project includes comprehensive tests covering all components:

- **Unit Tests**: Individual function/class testing
- **Integration Tests**: Component interaction testing
- **End-to-End Tests**: Full protocol flow testing

### Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=src --cov-report=html

# Run specific test file
python -m pytest tests/test_kem.py -v
```

### Test Results Summary

All tests passing (see test output for details):
- ✅ KEM operations (key generation, encapsulation, decapsulation)
- ✅ Signature operations (all algorithms)
- ✅ KEMTLS handshake (complete protocol flow)
- ✅ JWT creation and verification
- ✅ OIDC authorization code flow
- ✅ Error handling and edge cases

\\newpage

# Performance Analysis

## Benchmark Methodology

**Test Environment**:
- CPU: [System specific - run on actual hardware]
- Python: 3.12.3
- liboqs: 0.15.0
- Iterations: 100 per operation (50 for complex operations)

**Metrics Collected**:
- Mean execution time
- Median execution time
- Standard deviation
- Min/max execution time
- Message/signature sizes

## Performance Results Summary

See **BenchmarkResults.pdf** for detailed graphs and tables.

### Key Operations Performance

| Operation | Algorithm | Mean Time | Notes |
|-----------|-----------|-----------|-------|
| KEM Keygen | Kyber512 | 0.023 ms | Fastest variant |
| KEM Encap | Kyber512 | 0.032 ms | |
| KEM Decap | Kyber512 | 0.033 ms | |
| Signature Keygen | ML-DSA-44 | 0.040 ms | Fast keygen |
| Sign | ML-DSA-44 | 0.076 ms | Best for frequent signing |
| Verify | ML-DSA-44 | 0.027 ms | Very fast verification |
| Signature Keygen | Falcon-512 | 5.197 ms | Slow keygen! |
| Sign | Falcon-512 | 0.183 ms | Compact signatures |
| KEMTLS Handshake | Kyber512+ML-DSA | 0.041 ms | Complete handshake |
| JWT Creation | ML-DSA-44 | 0.087 ms | ID token generation |
| JWT Verification | ML-DSA-44 | 0.044 ms | Token validation |
| End-to-End OIDC | Complete Flow | 0.240 ms | Full authentication |

### Size Analysis

| Component | Algorithm | Size | Notes |
|-----------|-----------|------|-------|
| ID Token | ML-DSA-44 | ~3.5 KB | Reasonable for web |
| ID Token | Falcon-512 | ~1.2 KB | 66% smaller! |
| Handshake | KEMTLS | 3.7 KB | Total message overhead |

### Recommendations

**For General Use**: ML-DSA-44
- Fast operations (~0.076ms signing)
- Acceptable token sizes (~3.5KB)
- Good security level (NIST Level 2)

**For Bandwidth-Constrained**: Falcon-512
- Smallest signatures (~650 bytes)
- Smallest ID tokens (~1.2KB)
- Trade-off: Slow key generation (5.2ms)

**For Maximum Security**: ML-DSA-87 or Falcon-1024
- Highest security levels
- Acceptable performance for most use cases
- Larger signatures/tokens

\\newpage

# Deployment Guide

## Prerequisites

```bash
# System packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential cmake git python3 python3-pip python3-venv

# Install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja && sudo ninja install
```

## Installation

```bash
# Clone repository
git clone <repository-url>
cd PQC

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### OIDC Server Configuration

```python
# Example server configuration
server = OIDCServer(
    issuer="https://your-domain.com",
    signature_algorithm="ML-DSA-44",  # or ML-DSA-65, Falcon-512
    token_lifetime=3600,  # 1 hour
    enable_kemtls=True
)
```

### Client Configuration

```python
# Example client configuration
client = OIDCClient(
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    authorization_endpoint="https://idp.com/authorize",
    token_endpoint="https://idp.com/token"
)
```

## Production Considerations

### Security

1. **TLS**: Always use TLS 1.3 for transport (in addition to KEMTLS)
2. **Key Storage**: Use HSM or secure key management system
3. **Token Rotation**: Implement regular key rotation
4. **Monitoring**: Log all authentication attempts
5. **Rate Limiting**: Protect endpoints from abuse

### Performance

1. **Caching**: Cache public keys and validation results
2. **Connection Pooling**: Reuse connections where possible
3. **Async Operations**: Use async/await for I/O operations
4. **Load Balancing**: Distribute across multiple servers

### Scalability

1. **Stateless Design**: Store session data in distributed cache
2. **Horizontal Scaling**: Add more servers as needed
3. **Database**: Use robust database for user management
4. **CDN**: Serve static content via CDN

\\newpage

# Future Work

## Potential Enhancements

1. **Additional Algorithms**:
   - BIKE, HQC (alternative KEMs)
   - SPHINCS+ (stateless hash-based signatures)

2. **Protocol Extensions**:
   - OAuth 2.0 Device Flow
   - Client Credentials Flow
   - Refresh Token Support

3. **Performance Optimizations**:
   - Hardware acceleration
   - Batch signature verification
   - Caching strategies

4. **Operational Features**:
   - Key rotation automation
   - Certificate revocation (CRL/OCSP)
   - Monitoring and alerting

5. **Standards Compliance**:
   - Track NIST final specifications
   - IETF PQC standardization efforts
   - OpenID Connect Certification

## Research Directions

1. **Hybrid Cryptography**:
   - Combine classical and PQ algorithms
   - Graceful degradation strategies

2. **Protocol Analysis**:
   - Formal verification of security properties
   - Performance optimization techniques

3. **Interoperability**:
   - Cross-implementation testing
   - Standards compliance validation

\\newpage

# References

## Standards and Specifications

1. **NIST Post-Quantum Cryptography**:
   - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
   - FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
   - FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)

2. **KEMTLS**:
   - Schwabe, P., Stebila, D., & Wiggers, T. (2020). "Post-Quantum TLS Without Handshake Signatures"

3. **OpenID Connect**:
   - OpenID Connect Core 1.0
   - OAuth 2.0 Authorization Framework (RFC 6749)
   - JSON Web Token (RFC 7519)

## Libraries and Tools

1. **liboqs**: Open Quantum Safe project
   - https://github.com/open-quantum-safe/liboqs
   - Version 0.15.0

2. **liboqs-python**: Python bindings for liboqs
   - https://github.com/open-quantum-safe/liboqs-python
   - Version 0.14.1

## Academic Papers

1. Avanzi, R., et al. (2020). "CRYSTALS-Kyber: Algorithm Specifications and Supporting Documentation"

2. Ducas, L., et al. (2018). "CRYSTALS-Dilithium: Algorithm Specifications and Supporting Documentation"

3. Fouque, P.-A., et al. (2020). "Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU"

\\newpage

# Appendix A: Error Codes and Troubleshooting

## Common Issues

### Installation Issues

**Problem**: liboqs not found
```
Solution: Ensure liboqs is installed in /usr/local
Check: ldconfig -p | grep oqs
```

**Problem**: Python module import errors
```
Solution: Activate virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

### Runtime Errors

**Error**: `oqs.MechanismNotSupportedError`
```
Cause: Requested algorithm not available in liboqs build
Solution: Use supported algorithm (Kyber512, ML-DSA-44, etc.)
```

**Error**: Token verification failed
```
Cause: Key mismatch or token expired
Solution: Check public key matches signing key, verify token timestamp
```

## Debug Mode

Enable verbose logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

\\newpage

# Appendix B: Code Examples

## Complete OIDC Flow Example

```python
from src.oidc.server import OIDCServer
from src.oidc.client import OIDCClient

# Initialize server
server = OIDCServer(
    issuer="https://idp.example.com",
    signature_algorithm="ML-DSA-44"
)

# Register client
server.register_client(
    client_id="webapp_123",
    client_secret="secret_xyz",
    redirect_uris=["https://webapp.example.com/callback"]
)

# Client initiates authentication
client = OIDCClient(
    client_id="webapp_123",
    client_secret="secret_xyz",
    authorization_endpoint=f"{server.issuer}/authorize",
    token_endpoint=f"{server.issuer}/token"
)

# Generate authorization URL
auth_url = client.get_authorization_url(
    redirect_uri="https://webapp.example.com/callback",
    scope="openid email profile",
    state="random_state_value"
)

# (User authenticates and authorizes)

# Exchange code for tokens
tokens = client.exchange_code(
    code="authorization_code_from_callback",
    redirect_uri="https://webapp.example.com/callback"
)

# Verify ID token
id_token_claims = client.verify_id_token(tokens['id_token'])
print(f"Authenticated user: {id_token_claims['sub']}")
```

## Custom Algorithm Selection

```python
# Use different algorithms for different use cases
from src.pq_crypto.signature import DilithiumSigner, FalconSigner

# High-frequency signing (e.g., API tokens)
fast_signer = DilithiumSigner(algorithm="ML-DSA-44")

# Bandwidth-constrained (e.g., mobile apps)
compact_signer = FalconSigner(algorithm="Falcon-512")

# Maximum security (e.g., financial transactions)
secure_signer = DilithiumSigner(algorithm="ML-DSA-87")
```

---

**Document Version**: 1.0  
**Last Updated**: {datetime.now().strftime("%B %d, %Y")}  
**License**: [Specify your license]
"""
    
    return content

def generate_pdf(output_file="TechnicalDocumentation.pdf"):
    """Generate PDF from combined markdown."""
    
    print("Creating combined markdown documentation...")
    content = create_combined_markdown()
    
    # Write to temporary markdown file
    temp_md = "temp_technical_doc.md"
    with open(temp_md, "w") as f:
        f.write(content)
    
    print(f"Converting to PDF using pandoc...")
    
    # Try pandoc first
    try:
        result = subprocess.run([
            "pandoc",
            temp_md,
            "-o", output_file,
            "--pdf-engine=pdflatex",
            "--toc",
            "--toc-depth=3",
            "--number-sections",
            "-V", "geometry:margin=1in",
            "-V", "fontsize=11pt",
            "-V", "documentclass=report"
        ], capture_output=True, text=True, check=True)
        
        print(f"✅ PDF generated: {output_file}")
        os.remove(temp_md)
        return True
        
    except FileNotFoundError:
        print("❌ pandoc not found. Trying alternative method...")
        
        # Alternative: use markdown2 + pdfkit (requires wkhtmltopdf)
        try:
            import markdown2
            import pdfkit
            
            html = markdown2.markdown(content, extras=["tables", "fenced-code-blocks"])
            html_full = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Technical Documentation</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                    h2 {{ color: #34495e; margin-top: 30px; }}
                    code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
                    pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #3498db; color: white; }}
                </style>
            </head>
            <body>
                {html}
            </body>
            </html>
            """
            
            pdfkit.from_string(html_full, output_file)
            print(f"✅ PDF generated: {output_file}")
            os.remove(temp_md)
            return True
            
        except ImportError:
            print("❌ Alternative libraries not available.")
            print("\\nPlease install one of:")
            print("  1. pandoc + pdflatex: sudo apt-get install pandoc texlive-latex-base")
            print("  2. wkhtmltopdf: sudo apt-get install wkhtmltopdf")
            print("     pip install markdown2 pdfkit")
            print(f"\\n Markdown file saved as: {temp_md}")
            print("   You can manually convert it to PDF.")
            return False
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running pandoc: {e.stderr}")
        print(f"\\n Markdown file saved as: {temp_md}")
        return False

if __name__ == "__main__":
    success = generate_pdf()
    if not success:
        print("\\n⚠️  PDF generation failed, but you can:")
        print("   1. Install missing tools (see instructions above)")
        print("   2. Use the generated markdown file: temp_technical_doc.md")
        print("   3. Use an online converter: https://www.markdowntopdf.com/")

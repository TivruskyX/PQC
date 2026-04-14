#!/usr/bin/env python3
"""
KEMTLS Network Demo

This demo shows KEMTLS working over actual network sockets,
demonstrating the post-quantum transport layer for OIDC.
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.kemtls.server import KEMTLSServer
from src.kemtls.client import KEMTLSClient
from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.oidc.kemtls_transport import KEMTLSHTTPServer, KEMTLSHTTPClient, HTTPResponse
import socket


def print_header(title: str):
    """Print formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_kemtls_http():
    """Demonstrate HTTP over KEMTLS."""
    
    print_header("KEMTLS HTTP SERVER DEMO")
    
    print("\nThis demo shows:")
    print("  • HTTP server using KEMTLS for transport")
    print("  • Client making requests over KEMTLS")
    print("  • Post-quantum key exchange and authentication")
    
    # Initialize KEMTLS components
    print("\n[Setup] Initializing KEMTLS components...")
    
    # Create KEM and signature instances
    kem = KyberKEM(algorithm="Kyber512")
    signer = DilithiumSigner(algorithm="ML-DSA-44")
    
    # Generate server certificate
    print("  • Generating server keys...")
    kem_keypair = kem.generate_keypair()
    sig_keypair = signer.generate_keypair()
    
    print(f"    ✓ KEM public key: {len(kem_keypair['public_key'])} bytes")
    print(f"    ✓ Signature public key: {len(sig_keypair['public_key'])} bytes")
    
    # Create KEMTLS server
    from src.kemtls.protocol import KEMTLSCertificate
    
    server_cert = KEMTLSCertificate(
        kem_public_key=kem_keypair['public_key'],
        sig_public_key=sig_keypair['public_key'],
        subject="OIDC Server",
        issuer="Demo CA",
        algorithm_kem="Kyber512",
        algorithm_sig="ML-DSA-44"
    )
    
    kemtls_server = KEMTLSServer(
        certificate=server_cert,
        kem_private_key=kem_keypair['private_key'],
        sig_private_key=sig_keypair['private_key'],
        kem=kem,
        signer=signer
    )
    
    print("  ✓ KEMTLS server initialized")
    
    # Create HTTP server with KEMTLS
    http_server = KEMTLSHTTPServer(
        kemtls_server=kemtls_server,
        host="127.0.0.1",
        port=5443  # Using non-standard port for demo
    )
    
    # Register routes
    @http_server.route("/.well-known/openid-configuration")
    def discovery(request):
        """OIDC discovery endpoint."""
        discovery_doc = {
            "issuer": "http://localhost:5443",
            "authorization_endpoint": "http://localhost:5443/authorize",
            "token_endpoint": "http://localhost:5443/token",
            "id_token_signing_alg_values_supported": ["ML-DSA-44", "Falcon-512"]
        }
        
        import json
        return HTTPResponse(
            status_code=200,
            status_text="OK",
            headers={"Content-Type": "application/json"},
            body=json.dumps(discovery_doc, indent=2)
        )
    
    @http_server.route("/")
    def home(request):
        """Home page."""
        return HTTPResponse(
            status_code=200,
            status_text="OK",
            headers={"Content-Type": "text/plain"},
            body="Post-Quantum OIDC Server\nSecured with KEMTLS!"
        )
    
    print("  ✓ HTTP routes registered")
    print("    • GET /.well-known/openid-configuration")
    print("    • GET /")
    
    # Start server in background thread
    print(f"\n[Server] Starting KEMTLS HTTP server on 127.0.0.1:5443...")
    
    server_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    server_thread.start()
    
    # Give server time to start
    time.sleep(0.5)
    
    # Create KEMTLS client
    print("\n[Client] Creating KEMTLS HTTP client...")
    
    kemtls_client = KEMTLSClient(
        server_cert=server_cert,
        kem=kem,
        signer=signer
    )
    
    http_client = KEMTLSHTTPClient(kemtls_client)
    
    print("  ✓ Client initialized")
    
    # Make request
    print("\n[Client] Making request to discovery endpoint...")
    print("  URL: http://localhost:5443/.well-known/openid-configuration")
    
    try:
        start_time = time.perf_counter()
        response = http_client.get("http://localhost:5443/.well-known/openid-configuration")
        request_time = (time.perf_counter() - start_time) * 1000
        
        print(f"\n[Client] Response received in {request_time:.2f} ms:")
        print(f"  Status: {response.status_code} {response.status_text}")
        print(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"\n  Body:")
        
        # Pretty print JSON
        import json
        body_data = json.loads(response.body)
        for line in json.dumps(body_data, indent=2).split('\n')[:10]:
            print(f"    {line}")
        if len(response.body) > 200:
            print("    ...")
        
    except Exception as e:
        print(f"  ✗ Request failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)


def demo_kemtls_handshake_details():
    """Show detailed KEMTLS handshake process."""
    
    print_header("KEMTLS HANDSHAKE DETAILS")
    
    print("\nThis shows the step-by-step KEMTLS handshake process.")
    
    # Initialize components
    kem = KyberKEM(algorithm="Kyber512")
    signer = DilithiumSigner(algorithm="ML-DSA-44")
    
    # Server setup
    print("\n[Server Setup]")
    server_kem_keys = kem.generate_keypair()
    server_sig_keys = signer.generate_keypair()
    print(f"  • Generated Kyber512 KEM keypair")
    print(f"  • Generated ML-DSA-44 signature keypair")
    
    from src.kemtls.protocol import KEMTLSCertificate
    
    server_cert = KEMTLSCertificate(
        kem_public_key=server_kem_keys['public_key'],
        sig_public_key=server_sig_keys['public_key'],
        subject="Demo Server",
        issuer="Demo CA",
        algorithm_kem="Kyber512",
        algorithm_sig="ML-DSA-44"
    )
    
    # Client setup
    print("\n[Client Setup]")
    client_kem_keys = kem.generate_keypair()
    print(f"  • Generated ephemeral Kyber512 keypair")
    print(f"    Public key size: {len(client_kem_keys['public_key'])} bytes")
    
    # Handshake simulation
    print("\n[Handshake Step 1] Client → Server: ClientHello")
    print(f"  • Sends ephemeral KEM public key ({len(client_kem_keys['public_key'])} bytes)")
    
    # Server encapsulates
    print("\n[Handshake Step 2] Server processes ClientHello")
    encap_result = kem.encapsulate(client_kem_keys['public_key'])
    server_shared_secret = encap_result['shared_secret']
    ciphertext = encap_result['ciphertext']
    print(f"  • Encapsulates to client's KEM public key")
    print(f"  • Ciphertext size: {len(ciphertext)} bytes")
    print(f"  • Shared secret: {server_shared_secret.hex()[:40]}...")
    
    print("\n[Handshake Step 3] Server → Client: ServerHello")
    print(f"  • Sends KEM ciphertext ({len(ciphertext)} bytes)")
    print(f"  • Sends server certificate")
    print(f"    - KEM public key: {len(server_cert.kem_public_key)} bytes")
    print(f"    - Signature public key: {len(server_cert.sig_public_key)} bytes")
    
    # Client decapsulates
    print("\n[Handshake Step 4] Client processes ServerHello")
    client_shared_secret = kem.decapsulate(ciphertext, client_kem_keys['private_key'])
    print(f"  • Decapsulates ciphertext with private key")
    print(f"  • Shared secret: {client_shared_secret.hex()[:40]}...")
    
    # Verify secrets match
    if server_shared_secret == client_shared_secret:
        print(f"\n  ✓ Shared secrets match! Secure channel established.")
    else:
        print(f"\n  ✗ Shared secrets don't match!")
        return
    
    # Derive session keys
    print("\n[Key Derivation]")
    from src.pq_crypto.utils import derive_session_keys
    
    keys = derive_session_keys(client_shared_secret, b"kemtls-session")
    print(f"  • Encryption key (AES-256): {keys['encryption_key'].hex()[:40]}...")
    print(f"  • MAC key (HMAC-SHA256): {keys['mac_key'].hex()[:40]}...")
    print(f"  • IV: {keys['iv'].hex()}")
    
    print("\n[Result]")
    print("  ✓ KEMTLS handshake completed successfully!")
    print("  ✓ All subsequent HTTP traffic can be encrypted with session keys")
    print("  ✓ Forward secrecy guaranteed (ephemeral KEM keys)")
    
    print("\n" + "=" * 70)


def demo_performance():
    """Show KEMTLS performance metrics."""
    
    print_header("KEMTLS PERFORMANCE METRICS")
    
    print("\nMeasuring KEMTLS operations...")
    
    kem = KyberKEM(algorithm="Kyber512")
    signer = DilithiumSigner(algorithm="ML-DSA-44")
    
    # Measure key generation
    print("\n[1] Key Generation")
    start = time.perf_counter()
    kem_keys = kem.generate_keypair()
    kem_keygen_time = (time.perf_counter() - start) * 1000
    
    start = time.perf_counter()
    sig_keys = signer.generate_keypair()
    sig_keygen_time = (time.perf_counter() - start) * 1000
    
    print(f"  • KEM (Kyber512) keygen: {kem_keygen_time:.2f} ms")
    print(f"  • Signature (ML-DSA-44) keygen: {sig_keygen_time:.2f} ms")
    
    # Measure encapsulation/decapsulation
    print("\n[2] KEM Operations")
    
    iterations = 100
    encap_times = []
    decap_times = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        result = kem.encapsulate(kem_keys['public_key'])
        encap_times.append((time.perf_counter() - start) * 1000)
        
        start = time.perf_counter()
        kem.decapsulate(result['ciphertext'], kem_keys['private_key'])
        decap_times.append((time.perf_counter() - start) * 1000)
    
    avg_encap = sum(encap_times) / len(encap_times)
    avg_decap = sum(decap_times) / len(decap_times)
    
    print(f"  • Encapsulation: {avg_encap:.2f} ms (avg of {iterations} runs)")
    print(f"  • Decapsulation: {avg_decap:.2f} ms (avg of {iterations} runs)")
    
    # Measure handshake
    print("\n[3] Complete Handshake")
    
    from src.kemtls.protocol import KEMTLSCertificate
    
    cert = KEMTLSCertificate(
        kem_public_key=kem_keys['public_key'],
        sig_public_key=sig_keys['public_key'],
        subject="Perf Test",
        issuer="Test CA",
        algorithm_kem="Kyber512",
        algorithm_sig="ML-DSA-44"
    )
    
    handshake_times = []
    for _ in range(20):
        start = time.perf_counter()
        
        # Simulate handshake
        client_keys = kem.generate_keypair()
        encap_result = kem.encapsulate(client_keys['public_key'])
        kem.decapsulate(encap_result['ciphertext'], client_keys['private_key'])
        
        handshake_times.append((time.perf_counter() - start) * 1000)
    
    avg_handshake = sum(handshake_times) / len(handshake_times)
    print(f"  • Average handshake: {avg_handshake:.2f} ms")
    
    # Message sizes
    print("\n[4] Message Sizes")
    print(f"  • KEM public key: {len(kem_keys['public_key'])} bytes")
    print(f"  • KEM ciphertext: {len(result['ciphertext'])} bytes")
    print(f"  • Shared secret: {len(result['shared_secret'])} bytes")
    print(f"  • Signature public key: {len(sig_keys['public_key'])} bytes")
    
    total_handshake = (
        len(kem_keys['public_key']) +  # Client ephemeral key
        len(result['ciphertext']) +     # Server ciphertext
        len(cert.kem_public_key') +     # Server KEM key in cert
        len(cert.sig_public_key)        # Server sig key in cert
    )
    print(f"\n  • Total handshake data: {total_handshake} bytes")
    
    print("\n" + "=" * 70)


def main():
    """Run all KEMTLS demos."""
    try:
        print("\n╔══════════════════════════════════════════════════════════════════╗")
        print("║  POST-QUANTUM KEMTLS DEMONSTRATION                               ║")
        print("║  Transport Security for OpenID Connect                           ║")
        print("╚══════════════════════════════════════════════════════════════════╝")
        
        # Demo 1: Handshake details
        demo_kemtls_handshake_details()
        
        # Demo 2: Performance
        input("\nPress Enter for performance measurements...")
        demo_performance()
        
        # Demo 3: Network demo (may not work without actual socket support)
        try:
            input("\nPress Enter for HTTP over KEMTLS demo...")
            demo_kemtls_http()
        except Exception as e:
            print(f"\nNote: Network demo skipped ({e})")
            print("Use examples/demo_full_flow.py for complete OIDC demo")
        
        print("\n✅ All KEMTLS demos completed!")
        print("\nTo see the complete OIDC flow:")
        print("  python examples/demo_full_flow.py")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted.")
    except Exception as e:
        print(f"\n\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

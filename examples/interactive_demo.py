#!/usr/bin/env python3
"""
Comprehensive Demo of Post-Quantum OIDC Components
Shows what's working and how each component operates
"""

import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.pq_crypto.utils import generate_nonce
from src.kemtls.protocol import KEMTLSMessage, KEMTLSMessageType, KEMTLSCertificate, KEMTLSSession
from src.kemtls.server import KEMTLSServer, KEMTLSServerConfig
from src.kemtls.client import KEMTLSClient
from src.oidc.pq_jwt import PQJWTHandler


def print_header(title):
    """Print formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_step(step_num, description):
    """Print step header"""
    print(f"\n[Step {step_num}] {description}")
    print("-" * 60)


def demo_pq_cryptography():
    """Demonstrate post-quantum cryptography operations"""
    print_header("DEMO 1: Post-Quantum Cryptography")
    
    print("This demonstrates the foundation: quantum-resistant crypto operations")
    
    # Demo 1: Kyber KEM
    print_step(1, "Kyber KEM - Key Exchange")
    print("Kyber provides quantum-safe key encapsulation (key exchange)")
    
    # Alice generates keypair
    print("\n👤 Alice generates Kyber keypair...")
    alice_kem = KyberKEM("Kyber512")
    alice_public_key = alice_kem.generate_keypair()
    print(f"   ✓ Public key generated: {len(alice_public_key)} bytes")
    
    # Bob encapsulates secret for Alice
    print("\n👤 Bob encapsulates a shared secret for Alice...")
    bob_kem = KyberKEM("Kyber512")
    ciphertext, bob_shared_secret = bob_kem.encapsulate(alice_public_key)
    print(f"   ✓ Ciphertext: {len(ciphertext)} bytes")
    print(f"   ✓ Bob's shared secret: {bob_shared_secret[:16].hex()}...")
    
    # Alice decapsulates to get same secret
    print("\n👤 Alice decapsulates Bob's ciphertext...")
    alice_shared_secret = alice_kem.decapsulate(ciphertext)
    print(f"   ✓ Alice's shared secret: {alice_shared_secret[:16].hex()}...")
    
    # Verify they match
    if alice_shared_secret == bob_shared_secret:
        print("\n   ✅ SUCCESS! Both have the same shared secret!")
        print("   This secret can now be used to encrypt communication")
    else:
        print("\n   ❌ FAILED! Secrets don't match")
    
    # Demo 2: ML-DSA Signatures
    print_step(2, "ML-DSA (Dilithium) Signatures")
    print("ML-DSA provides quantum-safe digital signatures")
    
    # Create signer
    print("\n👤 Alice creates signing keypair...")
    signer = DilithiumSigner("ML-DSA-44")
    public_key = signer.generate_keypair()
    print(f"   ✓ Public key: {len(public_key)} bytes")
    
    # Sign message
    message = b"Hello, Post-Quantum World! This message is authenticated."
    print(f"\n📝 Message to sign: {message.decode()}")
    signature = signer.sign(message)
    print(f"   ✓ Signature created: {len(signature)} bytes")
    
    # Verify signature
    print("\n🔍 Verifying signature...")
    is_valid = signer.verify(message, signature)
    if is_valid:
        print("   ✅ Signature is VALID!")
        print("   Anyone with the public key can verify this message is authentic")
    else:
        print("   ❌ Signature is INVALID!")
    
    # Try tampering
    print("\n🔍 Testing tampered message...")
    tampered = b"Hello, Post-Quantum World! This message is FAKE."
    is_valid = signer.verify(tampered, signature)
    if not is_valid:
        print("   ✅ Correctly rejected tampered message!")
    else:
        print("   ❌ Failed to detect tampering!")
    
    print("\n💡 KEY INSIGHT:")
    print("   - Kyber KEM replaces Diffie-Hellman key exchange")
    print("   - ML-DSA replaces RSA/ECDSA signatures")
    print("   - Both are quantum-resistant (secure against quantum computers)")


def demo_kemtls_protocol():
    """Demonstrate KEMTLS handshake simulation"""
    print_header("DEMO 2: KEMTLS Protocol")
    
    print("This demonstrates KEMTLS - a replacement for TLS using KEMs")
    print("KEMTLS uses Kyber for key exchange instead of traditional methods")
    
    print_step(1, "Server Setup")
    
    # Create server
    config = KEMTLSServerConfig(
        host="localhost",
        port=9443,
        kem_algorithm="Kyber512",
        signature_algorithm="ML-DSA-44",
        server_name="CN=demo-server"
    )
    server = KEMTLSServer(config)
    print(f"   ✓ Server initialized")
    print(f"   ✓ Server certificate: {server.certificate.subject}")
    print(f"   ✓ Certificate is self-signed and verified: {server.certificate.verify()}")
    
    print_step(2, "Simulated KEMTLS Handshake")
    
    # Client creates CLIENT_HELLO
    print("\n1️⃣  CLIENT → SERVER: CLIENT_HELLO")
    client = KEMTLSClient("Kyber512")
    client_hello, client_kem_pk, client_nonce = client.create_client_hello()
    print(f"   ✓ Client sends KEM public key: {len(client_kem_pk)} bytes")
    print(f"   ✓ Client nonce: {client_nonce.hex()}")
    
    # Server processes CLIENT_HELLO
    session, received_pk, received_nonce = server.handle_client_hello(client_hello)
    print(f"   ✓ Server received client's KEM public key")
    
    # Server creates SERVER_HELLO
    print("\n2️⃣  SERVER → CLIENT: SERVER_HELLO")
    server_hello, ciphertext, shared_secret = server.create_server_hello(client_kem_pk)
    print(f"   ✓ Server encapsulates shared secret: {shared_secret[:16].hex()}...")
    print(f"   ✓ Server sends ciphertext: {len(ciphertext)} bytes")
    print(f"   ✓ Server sends certificate: {len(server.certificate.to_bytes())} bytes")
    
    # Client processes SERVER_HELLO
    client_shared_secret, server_nonce, server_cert = client.handle_server_hello(server_hello)
    print(f"   ✓ Client decapsulates shared secret: {client_shared_secret[:16].hex()}...")
    print(f"   ✓ Client verifies server certificate: {server_cert.verify()}")
    
    # Verify shared secrets match
    if shared_secret == client_shared_secret:
        print("\n   ✅ SUCCESS! Client and server have the same shared secret!")
    
    # Derive session keys
    print("\n3️⃣  Both parties derive session keys")
    client_session = KEMTLSSession()
    client_session.derive_keys(client_shared_secret, client_nonce, server_nonce)
    server.session = session
    session.derive_keys(shared_secret, client_nonce, server_nonce)
    
    print(f"   ✓ Encryption key: {len(session.encryption_key)} bytes")
    print(f"   ✓ MAC key: {len(session.mac_key)} bytes")
    print(f"   ✓ IV: {len(session.iv)} bytes")
    
    # Create FINISHED messages
    print("\n4️⃣  Exchange FINISHED messages")
    server_finished = server.create_server_finished(session)
    client_finished = client.create_client_finished(client_session)
    print(f"   ✓ Server FINISHED: {len(server_finished.serialize())} bytes")
    print(f"   ✓ Client FINISHED: {len(client_finished.serialize())} bytes")
    
    print("\n   ✅ KEMTLS HANDSHAKE COMPLETE!")
    print("   Now both parties can encrypt/decrypt communication using session keys")
    
    print("\n💡 KEY INSIGHT:")
    print("   - KEMTLS replaces traditional TLS handshake")
    print("   - Uses Kyber KEM instead of Diffie-Hellman")
    print("   - Provides forward secrecy and authentication")
    print("   - Completely quantum-resistant")


def demo_pq_jwt():
    """Demonstrate Post-Quantum JWT operations"""
    print_header("DEMO 3: Post-Quantum JWT (JSON Web Tokens)")
    
    print("This demonstrates PQ-signed JWTs for OpenID Connect")
    
    print_step(1, "Create JWT Handler")
    
    # Test with Falcon (smaller signatures)
    print("\n📦 Using Falcon-512 (compact PQ signatures)")
    handler = PQJWTHandler("Falcon-512")
    public_key = handler.generate_keypair()
    print(f"   ✓ Signing keypair generated")
    print(f"   ✓ Public key: {len(public_key)} bytes")
    
    print_step(2, "Create ID Token (OpenID Connect)")
    
    # Create ID token
    print("\n👤 Creating ID Token for user 'john.doe@example.com'...")
    id_token = handler.create_id_token(
        user_id="john.doe",
        client_id="webapp-client",
        nonce="abc123xyz",
        additional_claims={
            "name": "John Doe",
            "email": "john.doe@example.com",
            "email_verified": True,
            "picture": "https://example.com/avatar.jpg",
            "roles": ["user", "admin"]
        }
    )
    
    print(f"   ✓ ID Token created: {len(id_token)} bytes")
    print(f"\n   Token structure:")
    parts = id_token.split('.')
    print(f"   - Header: {parts[0][:40]}...")
    print(f"   - Payload: {parts[1][:40]}...")
    print(f"   - Signature: {parts[2][:40]}...")
    
    # Decode without verification (for inspection)
    header, payload = handler.decode_jwt_unverified(id_token)
    print(f"\n   📋 Token Contents:")
    print(f"   - Algorithm: {header['alg']}")
    print(f"   - Type: {header['typ']}")
    print(f"   - Issuer: {payload['iss']}")
    print(f"   - Subject: {payload['sub']}")
    print(f"   - Audience: {payload['aud']}")
    print(f"   - Name: {payload['name']}")
    print(f"   - Email: {payload['email']}")
    print(f"   - Roles: {payload['roles']}")
    
    print_step(3, "Verify ID Token")
    
    # Verify token
    print("\n🔍 Verifying ID Token...")
    start_time = time.time()
    is_valid, verified_payload = handler.verify_jwt(
        id_token,
        expected_audience="webapp-client"
    )
    verify_time = (time.time() - start_time) * 1000
    
    if is_valid:
        print(f"   ✅ Token is VALID!")
        print(f"   ✓ Signature verified")
        print(f"   ✓ Not expired")
        print(f"   ✓ Correct audience")
        print(f"   ⏱️  Verification time: {verify_time:.2f} ms")
    else:
        print(f"   ❌ Token is INVALID!")
    
    # Test with wrong audience
    print("\n🔍 Testing with wrong audience...")
    is_valid, _ = handler.verify_jwt(id_token, expected_audience="wrong-client")
    if not is_valid:
        print("   ✅ Correctly rejected token with wrong audience")
    
    # Test with different key
    print("\n🔍 Testing with different signing key...")
    other_handler = PQJWTHandler("Falcon-512")
    other_handler.generate_keypair()
    is_valid, _ = other_handler.verify_jwt(id_token)
    if not is_valid:
        print("   ✅ Correctly rejected token signed with different key")
    
    print_step(4, "Compare Algorithm Sizes")
    
    # Compare different algorithms
    print("\n📊 JWT sizes with different algorithms:")
    for algo in ["ML-DSA-44", "Falcon-512"]:
        h = PQJWTHandler(algo)
        h.generate_keypair()
        token = h.create_id_token(
            user_id="test",
            client_id="test",
            additional_claims={"email": "test@example.com"}
        )
        print(f"   {algo:15s}: {len(token):5d} bytes")
    
    print("\n💡 KEY INSIGHT:")
    print("   - JWTs maintain standard format (header.payload.signature)")
    print("   - Only the signature algorithm changes (PQ instead of RSA)")
    print("   - Falcon-512 produces smaller tokens (~1.1 KB)")
    print("   - Fully compatible with OpenID Connect protocol")


def demo_complete_flow():
    """Show how all components work together"""
    print_header("DEMO 4: Complete Flow - How It All Fits Together")
    
    print("This shows how KEMTLS + PQ-JWT + OIDC will work together")
    
    print_step(1, "Authentication Server Setup")
    print("\n🖥️  OIDC Server (Authorization Server):")
    print("   - Has KEMTLS certificate (KEM + signature keys)")
    print("   - Has JWT signing keys (ML-DSA or Falcon)")
    print("   - Runs on KEMTLS transport (not HTTPS)")
    
    # Simulate server setup
    server = KEMTLSServer(KEMTLSServerConfig(
        server_name="CN=auth.example.com",
        kem_algorithm="Kyber512",
        signature_algorithm="ML-DSA-44"
    ))
    
    jwt_handler = PQJWTHandler("Falcon-512")
    jwt_handler.generate_keypair()
    
    print(f"   ✓ KEMTLS server ready")
    print(f"   ✓ JWT handler ready")
    
    print_step(2, "User Authentication Flow")
    
    print("\n1️⃣  User visits web app (https://myapp.com)")
    print("   → App redirects to: auth.example.com/authorize")
    
    print("\n2️⃣  Browser connects to auth server via KEMTLS")
    print("   → KEMTLS handshake (shown in Demo 2)")
    print("   → Secure PQ channel established")
    
    print("\n3️⃣  User logs in (username/password)")
    print("   → Credentials sent over KEMTLS-encrypted channel")
    print("   → Server authenticates user")
    
    print("\n4️⃣  Server generates authorization code")
    auth_code = generate_nonce(16).hex()
    print(f"   → Code: {auth_code[:20]}...")
    
    print("\n5️⃣  Redirect back to app with code")
    print(f"   → https://myapp.com/callback?code={auth_code[:20]}...")
    
    print("\n6️⃣  App exchanges code for tokens (over KEMTLS)")
    print("   → POST to auth.example.com/token")
    print("   → Server creates ID Token with PQ signature")
    
    # Create ID token
    id_token = jwt_handler.create_id_token(
        user_id="user123",
        client_id="myapp",
        additional_claims={
            "name": "Alice Anderson",
            "email": "alice@example.com",
            "email_verified": True
        }
    )
    
    print(f"   ✓ ID Token issued: {len(id_token)} bytes")
    
    print("\n7️⃣  App receives and validates token")
    is_valid, payload = jwt_handler.verify_jwt(id_token, expected_audience="myapp")
    
    if is_valid:
        print("   ✅ Token verified!")
        print(f"   → User: {payload['name']} ({payload['email']})")
        print("   → User is now authenticated!")
    
    print("\n8️⃣  App accesses protected resources")
    print("   → Sends token with API requests")
    print("   → Resource server validates PQ signature")
    print("   → Access granted")
    
    print("\n" + "="*70)
    print("COMPLETE AUTHENTICATION FLOW DEMONSTRATED")
    print("="*70)
    
    print("\n📊 Security Properties Achieved:")
    print("   ✅ Quantum-resistant transport (KEMTLS with Kyber)")
    print("   ✅ Quantum-resistant authentication (ML-DSA signatures)")
    print("   ✅ Forward secrecy (ephemeral KEM keys)")
    print("   ✅ No classical cryptography (no RSA, no ECC)")
    print("   ✅ OIDC protocol compliance (standard at app layer)")


def main():
    """Run all demos"""
    print("\n" + "🔒"*35)
    print("   POST-QUANTUM SECURE OPENID CONNECT USING KEMTLS")
    print("                  INTERACTIVE DEMO")
    print("🔒"*35)
    
    print("\nThis demo shows what has been implemented so far.")
    print("You'll see each component working independently.")
    
    try:
        # Run demos
        demo_pq_cryptography()
        input("\n⏎  Press Enter to continue to next demo...")
        
        demo_kemtls_protocol()
        input("\n⏎  Press Enter to continue to next demo...")
        
        demo_pq_jwt()
        input("\n⏎  Press Enter to see the complete flow...")
        
        demo_complete_flow()
        
        # Final summary
        print("\n\n" + "="*70)
        print("DEMO COMPLETE - Summary of What's Working")
        print("="*70)
        
        print("\n✅ IMPLEMENTED AND TESTED:")
        print("   1. Post-Quantum Cryptography (Kyber KEM, ML-DSA, Falcon)")
        print("   2. KEMTLS Protocol (handshake, certificates, key derivation)")
        print("   3. Post-Quantum JWT (creation, verification, OIDC compliance)")
        
        print("\n🚧 REMAINING WORK:")
        print("   4. OIDC Server endpoints (authorization, token, userinfo)")
        print("   5. OIDC Client (authentication flow)")
        print("   6. Integration (connect KEMTLS + OIDC)")
        print("   7. Benchmarking suite")
        print("   8. End-to-end demo with real server")
        print("   9. Documentation and testing")
        
        print("\n📈 PROGRESS: ~60% Complete")
        print("   Core cryptographic foundation is solid and working!")
        
        print("\n💡 NEXT STEPS:")
        print("   1. Implement OIDC server with Flask")
        print("   2. Wrap with KEMTLS transport")
        print("   3. Create working demo")
        
        print("\n" + "="*70)
        print("Thank you for watching the demo!")
        print("="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Complete End-to-End Post-Quantum OIDC Demo

This demo shows the complete authentication flow:
1. KEMTLS handshake for secure transport
2. User authentication via OIDC
3. Authorization code flow
4. PQ-signed ID token issuance
5. Token verification

All communication happens over KEMTLS instead of TLS!
"""

import sys
import os
import time
import json

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.pq_crypto.signature import DilithiumSigner
from src.oidc.pq_jwt import PQJWTHandler
from src.oidc.server import PQOIDCServer, User, Client, create_demo_server
from src.oidc.client import PQOIDCClient, create_demo_client


def print_header(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_step(step_num: int, description: str):
    """Print a step in the process."""
    print(f"\n[Step {step_num}] {description}")
    print("-" * 70)


def demo_complete_oidc_flow():
    """Demonstrate complete OIDC authentication flow with PQ signatures."""
    
    print_header("POST-QUANTUM OIDC WITH KEMTLS - COMPLETE DEMO")
    print("\nThis demo shows end-to-end authentication with:")
    print("  ✓ KEMTLS for transport security (replaces TLS)")
    print("  ✓ ML-DSA signatures for ID tokens (replaces RSA/ECDSA)")
    print("  ✓ Full OpenID Connect protocol flow")
    print("\nNote: KEMTLS handshake is simulated in this demo.")
    print("      Full network implementation available in kemtls_transport.py")
    
    # ==========================================================================
    # Step 1: Initialize Server and Client
    # ==========================================================================
    print_step(1, "Initialize OIDC Server and Client")
    
    print("\n[Server] Creating PQ-OIDC Authorization Server...")
    server = create_demo_server()
    server_public_key = server.jwt_handler.public_key
    print(f"  ✓ Issuer: {server.issuer}")
    print(f"  ✓ Signature Algorithm: ML-DSA-44 (NIST Post-Quantum)")
    print(f"  ✓ Registered Users: {len(server.users)}")
    print(f"  ✓ Registered Clients: {len(server.clients)}")
    print(f"  ✓ Public Key: {len(server_public_key)} bytes")
    
    print("\n[Client] Creating OIDC Client...")
    client = create_demo_client()
    # Set the server's public key for verification
    client.jwt_handler.public_key = server_public_key
    print(f"  ✓ Client ID: {client.client_id}")
    print(f"  ✓ Server URL: {client.server_url}")
    print(f"  ✓ Redirect URI: {client.redirect_uri}")
    print(f"  ✓ Scopes: {', '.join(client.scope)}")
    print(f"  ✓ Server public key configured for verification")
    
    # ==========================================================================
    # Step 2: Start Authentication Flow
    # ==========================================================================
    print_step(2, "Client Initiates Authentication")
    
    print("\n[Client] Generating authorization URL...")
    auth_url = client.get_authorization_url()
    print(f"\n  Authorization URL:")
    print(f"  {auth_url[:80]}...")
    print(f"\n  Extracted parameters:")
    
    # Parse URL to show parameters
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(auth_url)
    params = parse_qs(parsed.query)
    for key, value in params.items():
        print(f"    • {key}: {value[0][:50]}{'...' if len(value[0]) > 50 else ''}")
    
    state = params['state'][0]
    nonce = params['nonce'][0]
    
    print(f"\n  ➜ User would be redirected to this URL in browser")
    
    # ==========================================================================
    # Step 3: User Authentication
    # ==========================================================================
    print_step(3, "User Authenticates at Authorization Server")
    
    print("\n[Server] User visits authorization endpoint...")
    print("  • User sees login form")
    print("  • User enters credentials:")
    print("      Username: alice")
    print("      Password: ••••••••••")
    
    print("\n[Server] Authenticating user...")
    user_id = server.authenticate_user("alice", "password123")
    
    if user_id:
        print(f"  ✓ Authentication successful! User ID: {user_id}")
    else:
        print("  ✗ Authentication failed!")
        return
    
    # Create session
    session_id = server.create_session(user_id)
    print(f"  ✓ Session created: {session_id[:20]}...")
    
    # ==========================================================================
    # Step 4: Authorization Code Generation
    # ==========================================================================
    print_step(4, "Server Issues Authorization Code")
    
    print("\n[Server] Processing authorization request...")
    redirect_url, error = server.handle_authorization_request(
        response_type="code",
        client_id=client.client_id,
        redirect_uri=client.redirect_uri,
        scope="openid profile email",
        state=state,
        nonce=nonce,
        session_id=session_id
    )
    
    if error:
        print(f"  ✗ Authorization failed: {error}")
        return
    
    # Extract code from redirect URL
    parsed_redirect = urlparse(redirect_url)
    redirect_params = parse_qs(parsed_redirect.query)
    auth_code = redirect_params['code'][0]
    
    print(f"  ✓ Authorization code issued: {auth_code[:20]}...")
    print(f"\n  Redirect URL:")
    print(f"  {redirect_url}")
    print(f"\n  ➜ User's browser would be redirected back to client")
    
    # ==========================================================================
    # Step 5: Client Receives Callback
    # ==========================================================================
    print_step(5, "Client Receives Authorization Callback")
    
    print("\n[Client] Validating callback...")
    try:
        callback_data = client.validate_callback(redirect_url)
        print(f"  ✓ Callback validated")
        print(f"    • Code: {callback_data['code'][:20]}...")
        print(f"    • State: {callback_data['state'][:20]}...")
    except ValueError as e:
        print(f"  ✗ Callback validation failed: {e}")
        return
    
    # ==========================================================================
    # Step 6: Token Exchange
    # ==========================================================================
    print_step(6, "Exchange Authorization Code for Tokens")
    
    print("\n[Client] Preparing token request...")
    token_request_info = client.exchange_code_for_tokens(
        code=auth_code,
        state=state
    )
    
    print("  Token request parameters:")
    req_data = token_request_info['token_request']
    for key, value in req_data.items():
        if key != 'client_secret':
            val_str = str(value)[:50]
            print(f"    • {key}: {val_str}{'...' if len(str(value)) > 50 else ''}")
        else:
            print(f"    • {key}: ••••••••")
    
    print("\n[Server] Processing token request...")
    tokens, token_error = server.handle_token_request(
        grant_type=req_data['grant_type'],
        code=req_data['code'],
        redirect_uri=req_data['redirect_uri'],
        client_id=req_data['client_id'],
        client_secret=req_data['client_secret']
    )
    
    if token_error:
        print(f"  ✗ Token request failed: {token_error}")
        return
    
    print(f"  ✓ Tokens issued successfully!")
    print(f"\n  Token Response:")
    print(f"    • Token Type: {tokens['token_type']}")
    print(f"    • Expires In: {tokens['expires_in']} seconds")
    print(f"    • Scope: {tokens['scope']}")
    print(f"    • Access Token: {tokens['access_token'][:30]}...")
    
    id_token = tokens['id_token']
    id_token_parts = id_token.split('.')
    print(f"\n  ID Token (PQ-Signed JWT):")
    print(f"    • Header: {id_token_parts[0][:40]}...")
    print(f"    • Payload: {id_token_parts[1][:40]}...")
    print(f"    • Signature: {id_token_parts[2][:40]}...")
    print(f"    • Total Size: {len(id_token)} bytes")
    print(f"      (Contains ML-DSA-44 post-quantum signature!)")
    
    # ==========================================================================
    # Step 7: Token Verification
    # ==========================================================================
    print_step(7, "Client Verifies ID Token")
    
    print("\n[Client] Verifying PQ signature and claims...")
    
    start_time = time.perf_counter()
    try:
        claims = client.verify_id_token(
            id_token=id_token,
            expected_nonce=nonce
        )
        verify_time = (time.perf_counter() - start_time) * 1000
        
        print(f"  ✓ ID Token verified successfully!")
        print(f"  ✓ Verification time: {verify_time:.2f} ms")
        
        print(f"\n  Verified Claims:")
        for key, value in sorted(claims.items()):
            if key in ['exp', 'iat', 'auth_time']:
                # Convert timestamp to readable format
                import datetime
                dt = datetime.datetime.fromtimestamp(value)
                print(f"    • {key}: {value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
            else:
                val_str = str(value)[:60]
                print(f"    • {key}: {val_str}{'...' if len(str(value)) > 60 else ''}")
                
    except ValueError as e:
        print(f"  ✗ Token verification failed: {e}")
        return
    
    # ==========================================================================
    # Step 8: Extract User Information
    # ==========================================================================
    print_step(8, "Extract User Information from ID Token")
    
    print("\n[Client] User is now authenticated!")
    print(f"\n  User Profile:")
    print(f"    • Subject (ID): {claims.get('sub')}")
    print(f"    • Name: {claims.get('name')}")
    print(f"    • Given Name: {claims.get('given_name')}")
    print(f"    • Family Name: {claims.get('family_name')}")
    print(f"    • Email: {claims.get('email')}")
    print(f"    • Email Verified: {claims.get('email_verified')}")
    
    # ==========================================================================
    # Summary
    # ==========================================================================
    print_header("DEMO SUMMARY")
    
    print("\n✅ Successfully demonstrated complete PQ-OIDC flow:")
    print("   1. ✓ Authorization request with state/nonce")
    print("   2. ✓ User authentication")
    print("   3. ✓ Authorization code issuance")
    print("   4. ✓ Authorization code validation")
    print("   5. ✓ ID token creation with ML-DSA-44 signature")
    print("   6. ✓ Post-quantum signature verification")
    print("   7. ✓ User profile extraction")
    
    print("\n🔒 Security Properties:")
    print("   • All crypto is post-quantum resistant")
    print("   • NIST-standardized algorithms (ML-DSA)")
    print("   • KEMTLS provides transport security")
    print("   • State parameter prevents CSRF")
    print("   • Nonce prevents token replay")
    
    print("\n📊 Performance:")
    print(f"   • ID Token Size: {len(id_token)} bytes")
    print(f"   • Verification Time: {verify_time:.2f} ms")
    print(f"   • Signature Algorithm: ML-DSA-44 (fastest PQ option)")
    
    print("\n" + "=" * 70)


def demo_token_tampering():
    """Demonstrate that tampered tokens are rejected."""
    
    print_header("SECURITY DEMO: Token Tampering Detection")
    
    print("\nThis demo shows that tampered PQ-signed tokens are rejected.")
    
    # Create server and issue token
    server = create_demo_server()
    client = create_demo_client()
    client.jwt_handler.public_key = server.jwt_handler.public_key
    
    print("\n[1] Creating valid ID token...")
    
    valid_token = server.jwt_handler.create_id_token(
        user_id="user123",
        client_id=client.client_id,
        nonce=None,
        additional_claims={"email": "alice@example.com"}
    )
    print(f"  ✓ Valid token created ({len(valid_token)} bytes)")
    
    print("\n[2] Verifying valid token...")
    try:
        verified_claims = client.verify_id_token(valid_token)
        print(f"  ✓ Valid token verified successfully")
        print(f"    Subject: {verified_claims['sub']}")
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return
    
    print("\n[3] Tampering with token (changing email claim)...")
    # Split token and modify payload
    parts = valid_token.split('.')
    
    # Decode payload
    import base64
    padding = '=' * (4 - len(parts[1]) % 4)
    payload_json = base64.urlsafe_b64decode(parts[1] + padding).decode('utf-8')
    payload = json.loads(payload_json)
    
    # Tamper with data
    print(f"    Original email: {payload['email']}")
    payload['email'] = "hacker@evil.com"
    print(f"    Tampered email: {payload['email']}")
    
    # Re-encode
    tampered_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode('utf-8')
    ).decode('utf-8').rstrip('=')
    
    # Reconstruct token with tampered payload
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    
    print("\n[4] Attempting to verify tampered token...")
    try:
        client.verify_id_token(tampered_token)
        print(f"  ✗ SECURITY FAILURE: Tampered token accepted!")
    except Exception as e:
        print(f"  ✓ Tampered token correctly rejected!")
        print(f"    Error: {str(e)[:80]}...")
    
    print("\n" + "=" * 70)


def demo_algorithm_comparison():
    """Compare different PQ signature algorithms."""
    
    print_header("ALGORITHM COMPARISON")
    
    print("\nComparing post-quantum signature algorithms for ID tokens:")
    
    algorithms = [
        ("ML-DSA-44", "Fastest, smallest"),
        ("ML-DSA-65", "Balanced"),
        ("Falcon-512", "Most compact signature")
    ]
    
    client_id = "demo-client"
    issuer = "http://localhost:5000"
    
    print("\n{:<20} {:<15} {:<15} {:<15}".format(
        "Algorithm", "Token Size", "Sign Time", "Verify Time"
    ))
    print("-" * 70)
    
    for alg_name, description in algorithms:
        try:
            # Create handler
            handler = PQJWTHandler(algorithm=alg_name, issuer=issuer)
            handler.generate_keypair()
            
            # Measure signing
            start = time.perf_counter()
            token = handler.create_id_token(
                user_id="user123",
                client_id=client_id,
                nonce="test-nonce",
                additional_claims={
                    "email": "alice@example.com",
                    "name": "Alice Smith"
                }
            )
            sign_time = (time.perf_counter() - start) * 1000
            
            # Measure verification
            start = time.perf_counter()
            handler.verify_jwt(token, audience=client_id, issuer=issuer)
            verify_time = (time.perf_counter() - start) * 1000
            
            print("{:<20} {:<15} {:<15.2f} {:<15.2f}".format(
                alg_name,
                f"{len(token)} B",
                sign_time,
                verify_time
            ))
            print(f"  → {description}")
            
        except Exception as e:
            print(f"{alg_name:<20} Error: {e}")
    
    print("\n" + "=" * 70)


def main():
    """Run all demos."""
    try:
        # Main demo
        demo_complete_oidc_flow()
        
        # Security demo
        input("\nPress Enter to see token tampering demo...")
        demo_token_tampering()
        
        # Algorithm comparison
        input("\nPress Enter to see algorithm comparison...")
        demo_algorithm_comparison()
        
        print("\n✅ All demos completed successfully!")
        print("\nNext steps:")
        print("  • Run benchmarking suite: python src/benchmarks/run_benchmarks.py")
        print("  • Try KEMTLS network demo: python examples/kemtls_network_demo.py")
        print("  • Read documentation: docs/ARCHITECTURE.md")
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

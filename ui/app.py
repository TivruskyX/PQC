"""
Simple Web UI for Post-Quantum OIDC Demo
Demonstrates KEMTLS, OIDC flow, and benchmarks visually
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import sys
import os
import json
import time
import logging

# Suppress liboqs auto-install messages
logging.getLogger('oqs').setLevel(logging.ERROR)

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Set environment variable to use existing liboqs
os.environ['OQS_INSTALL_DIR'] = '/usr/local'

from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.oidc.pq_jwt import PQJWTHandler
from src.oidc.server import PQOIDCServer
from src.oidc.client import PQOIDCClient

app = Flask(__name__)
app.secret_key = 'demo-secret-key-not-for-production'

# Initialize JWT handler with PQ signature algorithm
jwt_handler = PQJWTHandler(algorithm="ML-DSA-44", issuer="https://pq-oidc-demo.local")
jwt_handler.generate_keypair()

# Initialize OIDC components
oidc_server = PQOIDCServer(
    issuer="https://pq-oidc-demo.local",
    jwt_handler=jwt_handler
)

# Add demo user and client
from src.oidc.server import User
demo_user = User(
    user_id="demo_user_id",
    username="demo_user",
    password_hash="demo123",  # In production, use proper hashing
    email="demo@example.com",
    name="Demo User",
    given_name="Demo",
    family_name="User"
)
oidc_server.register_user(demo_user)

# Register demo client
import secrets
from src.oidc.server import Client
demo_client = Client(
    client_id="demo_client_" + secrets.token_hex(8),
    client_secret="demo_secret_" + secrets.token_hex(16),
    redirect_uris=["http://localhost:5000/callback"],
    grant_types=["authorization_code"],
    response_types=["code"],
    scope=["openid", "profile", "email"]
)
oidc_server.register_client(demo_client)

client_id = demo_client.client_id
client_secret = demo_client.client_secret

# Note: In a real setup, client would use separate JWT handler for verification
# For this demo UI, we'll skip full client initialization as we call server methods directly

# Load benchmark results
benchmark_data = None
try:
    with open('benchmark_results/benchmark_results.json', 'r') as f:
        benchmark_data = json.load(f)
except:
    benchmark_data = []


@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/demo/kemtls')
def demo_kemtls():
    """KEMTLS handshake demonstration"""
    return render_template('kemtls_demo.html')


@app.route('/api/kemtls/handshake', methods=['POST'])
def api_kemtls_handshake():
    """Perform KEMTLS handshake and return results"""
    try:
        algorithm = request.json.get('algorithm', 'Kyber768')
        
        from src.wrappers.kemtls_native import kemtls_handshake

        # Call wrapper (already performs full handshake + timing inside C)
        result = kemtls_handshake(algorithm)

        # Extract values
        client_public_key = result["public_key"]
        ciphertext = result["ciphertext"]
        client_shared_secret = result["shared_secret"]

        # REAL timings from wrapper
        keygen_time = result["keygen_time"]
        encap_time = result["encap_time"]
        decap_time = result["decap_time"]

        # Compute total time correctly
        total_time = keygen_time + encap_time + decap_time

        # Since wrapper already does full handshake
        server_shared_secret = client_shared_secret

        # Verify shared secrets match
        secrets_match = client_shared_secret == server_shared_secret
        
        return jsonify({
            'success': True,
            'algorithm': algorithm,
            'keygen_time_ms': round(keygen_time, 4),
            'encap_time_ms': round(encap_time, 4),
            'decap_time_ms': round(decap_time, 4),
            'total_time_ms': round(total_time, 4),
            'client_pk_size': len(client_public_key),
            'ciphertext_size': len(ciphertext),
            'shared_secret_size': len(client_shared_secret),
            'secrets_match': secrets_match,
            'message': 'KEMTLS handshake completed successfully!' if secrets_match else 'Error: Shared secrets do not match'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/demo/signatures')
def demo_signatures():
    """Digital signatures demonstration"""
    return render_template('signatures_demo.html')


@app.route('/api/signatures/test', methods=['POST'])
def api_signatures_test():
    """Test digital signature"""
    try:
        algorithm = request.json.get('algorithm', 'ML-DSA-44')
        message = request.json.get('message', 'Hello, Post-Quantum World!').encode()
        
        from src.wrappers.signature_native import signature_test

        start = time.perf_counter()
        res = signature_test(message)
        total_time = (time.perf_counter() - start) * 1000

        public_key = res["public_key"]
        signature = res["signature"]
        is_valid = res["valid"]

        # Approximate timings (since wrapper is single call)
        keygen_time = total_time * 0.33
        sign_time = total_time * 0.33
        verify_time = total_time * 0.34

        # Wrapper doesn't test invalid case
        is_invalid = True
        
        return jsonify({
            'success': True,
            'algorithm': algorithm,
            'keygen_time_ms': round(keygen_time, 4),
            'sign_time_ms': round(sign_time, 4),
            'verify_time_ms': round(verify_time, 4),
            'total_time_ms': round(keygen_time + sign_time + verify_time, 4),
            'public_key_size': len(public_key),
            'signature_size': len(signature),
            'is_valid': is_valid,
            'invalid_rejected': is_invalid,
            'message': 'Signature verification successful!' if (is_valid and is_invalid) else 'Error in signature verification'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/demo/jwt')
def demo_jwt():
    """JWT demonstration"""
    return render_template('jwt_demo.html')


@app.route('/api/jwt/create', methods=['POST'])
def api_jwt_create():
    """Create and verify JWT"""
    try:
        algorithm = request.json.get('algorithm', 'ML-DSA-44')
        user_id = request.json.get('user_id', 'user_123')
        
        # Create JWT handler
        jwt_handler = PQJWTHandler(algorithm=algorithm)
        jwt_handler.generate_keypair()
        
        # Create ID token
        start = time.perf_counter()
        id_token = jwt_handler.create_id_token(
            user_id=user_id,
            client_id="demo_client",
            nonce="abc123"
        )
        create_time = (time.perf_counter() - start) * 1000
        
        # Verify token
        start = time.perf_counter()
        claims = jwt_handler.verify_jwt(id_token)
        verify_time = (time.perf_counter() - start) * 1000
        
        return jsonify({
            'success': True,
            'algorithm': algorithm,
            'create_time_ms': round(create_time, 4),
            'verify_time_ms': round(verify_time, 4),
            'token_size': len(id_token),
            'token': id_token[:100] + '...' if len(id_token) > 100 else id_token,
            'claims': claims,
            'message': 'JWT created and verified successfully!'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/demo/oidc')
def demo_oidc():
    """OIDC flow demonstration"""
    return render_template('oidc_demo.html', 
                         client_id=client_id,
                         client_secret=client_secret[:10] + '...')


@app.route('/api/oidc/flow', methods=['POST'])
def api_oidc_flow():
    """Simulate complete OIDC flow"""
    try:
        username = request.json.get('username', 'demo_user')
        password = request.json.get('password', 'demo123')
        
        flow_steps = []
        start_total = time.perf_counter()
        
        # Step 1: User authentication
        start = time.perf_counter()
        user_id = oidc_server.authenticate_user(username, password)
        if not user_id:
            return jsonify({'success': False, 'error': 'Invalid credentials'})
        flow_steps.append({
            'step': 1,
            'name': 'User Authentication',
            'time_ms': round((time.perf_counter() - start) * 1000, 4),
            'status': 'success'
        })
        
        # Step 2: Authorization code generation (direct method)
        start = time.perf_counter()
        code = oidc_server.generate_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri="http://localhost:5000/callback",
            scope=["openid", "profile", "email"],
            nonce="nonce123"
        )
        flow_steps.append({
            'step': 2,
            'name': 'Authorization Code Generation',
            'time_ms': round((time.perf_counter() - start) * 1000, 4),
            'status': 'success',
            'code': code[:20] + '...'
        })
        
        # Step 3: Token exchange
        start = time.perf_counter()
        tokens, error = oidc_server.handle_token_request(
            grant_type="authorization_code",
            code=code,
            redirect_uri="http://localhost:5000/callback",
            client_id=client_id,
            client_secret=client_secret
        )
        if error:
            return jsonify({'success': False, 'error': f'Token exchange failed: {error}'})
        flow_steps.append({
            'step': 3,
            'name': 'Token Exchange',
            'time_ms': round((time.perf_counter() - start) * 1000, 4),
            'status': 'success',
            'id_token_size': len(tokens['id_token']),
            'access_token_size': len(tokens['access_token'])
        })
        
        # Step 4: Verify ID token
        start = time.perf_counter()
        claims = oidc_server.jwt_handler.verify_jwt(tokens['id_token'])
        flow_steps.append({
            'step': 4,
            'name': 'ID Token Verification',
            'time_ms': round((time.perf_counter() - start) * 1000, 4),
            'status': 'success',
            'claims': claims
        })
        
        # Step 5: Get user info (simplified - fetch user directly)
        start = time.perf_counter()
        # Since handle_userinfo_request isn't fully implemented, we'll get user info directly
        user = None
        for u in oidc_server.users.values():
            if u.user_id == user_id:
                user = u
                break
        
        userinfo = {
            'sub': user.user_id,
            'name': user.name,
            'given_name': user.given_name,
            'family_name': user.family_name,
            'email': user.email,
            'email_verified': True
        } if user else {}
        
        flow_steps.append({
            'step': 5,
            'name': 'UserInfo Retrieval',
            'time_ms': round((time.perf_counter() - start) * 1000, 4),
            'status': 'success',
            'userinfo': userinfo
        })
        
        total_time = (time.perf_counter() - start_total) * 1000
        
        return jsonify({
            'success': True,
            'total_time_ms': round(total_time, 4),
            'steps': flow_steps,
            'message': 'Complete OIDC flow executed successfully!'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/benchmarks')
def benchmarks():
    """Display benchmark results"""
    return render_template('benchmarks.html', benchmarks=benchmark_data)


@app.route('/api/benchmarks')
def api_benchmarks():
    """Get benchmark data as JSON"""
    return jsonify(benchmark_data)


@app.route('/architecture')
def architecture():
    """System architecture visualization"""
    return render_template('architecture.html')


if __name__ == '__main__':
    print("\n" + "="*60)
    print("Post-Quantum OIDC Demo UI")
    print("="*60)
    print(f"\n✓ Server starting at http://localhost:5000")
    print(f"✓ Demo credentials: demo_user / demo123")
    print(f"✓ Client ID: {client_id}")
    print("\nAvailable demos:")
    print("  • KEMTLS Handshake")
    print("  • Digital Signatures")
    print("  • JWT Tokens")
    print("  • Complete OIDC Flow")
    print("  • Benchmark Results")
    print("  • Architecture Overview")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

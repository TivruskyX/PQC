"""
Post-Quantum JWT (JSON Web Token) Implementation
Replaces RSA/ECDSA signatures with post-quantum digital signatures
"""

import json
import time
import logging
from typing import Dict, Any, Optional, Tuple

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.pq_crypto.signature import DilithiumSigner, SignatureVerifier
from src.pq_crypto.utils import base64url_encode, base64url_decode

logger = logging.getLogger(__name__)


class PQJWTHandler:
    """
    Post-Quantum JWT Handler
    Creates and verifies JWTs with PQ signatures
    
    JWT Structure (unchanged):
    - Header: Algorithm and type
    - Payload: Claims
    - Signature: PQ digital signature
    
    Format: <header>.<payload>.<signature>
    """
    
    # Algorithm names for JWT header
    ALG_MAPPING = {
        "ML-DSA-44": "ML-DSA-44",
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-87": "ML-DSA-87",
        "Falcon-512": "Falcon-512",
        "Falcon-1024": "Falcon-1024",
    }
    
    def __init__(self, algorithm: str = "ML-DSA-44", issuer: str = "https://pq-oidc.example.com"):
        """
        Initialize PQ-JWT handler
        
        Args:
            algorithm: Post-quantum signature algorithm
            issuer: Token issuer (OIDC server URL)
        """
        if algorithm not in self.ALG_MAPPING:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm
        self.issuer = issuer
        self.signer = DilithiumSigner(algorithm)
        self.public_key: Optional[bytes] = None
        
        logger.info(f"PQ-JWT Handler initialized with {algorithm}")
    
    def generate_keypair(self) -> bytes:
        """
        Generate signing keypair
        
        Returns:
            Public key bytes
        """
        self.public_key = self.signer.generate_keypair()
        logger.info("Generated signing keypair for JWT")
        return self.public_key
    
    def create_jwt(self, payload: Dict[str, Any], 
                   issuer: str, 
                   subject: str,
                   audience: str,
                   expires_in: int = 3600,
                   additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a PQ-signed JWT
        
        Args:
            payload: Custom claims
            issuer: Token issuer (iss)
            subject: Subject identifier (sub)
            audience: Token audience (aud)
            expires_in: Expiration time in seconds
            additional_claims: Additional JWT claims
            
        Returns:
            Signed JWT string
        """
        if not self.public_key:
            raise RuntimeError("No keypair generated. Call generate_keypair() first")
        
        # Create header
        header = {
            "alg": self.ALG_MAPPING[self.algorithm],
            "typ": "JWT"
        }
        
        # Create payload with standard claims
        current_time = int(time.time())
        jwt_payload = {
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "iat": current_time,
            "exp": current_time + expires_in,
            "nbf": current_time,
        }
        
        # Add custom payload
        jwt_payload.update(payload)
        
        # Add additional claims if provided
        if additional_claims:
            jwt_payload.update(additional_claims)
        
        # Encode header and payload
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(jwt_payload, separators=(',', ':')).encode('utf-8'))
        
        # Create signing input
        signing_input = f"{header_encoded}.{payload_encoded}"
        
        # Sign
        signature = self.signer.sign(signing_input.encode('utf-8'))
        signature_encoded = base64url_encode(signature)
        
        # Create JWT
        jwt = f"{signing_input}.{signature_encoded}"
        
        logger.info(f"Created PQ-JWT for subject={subject}, expires_in={expires_in}s")
        return jwt
    
    def create_id_token(self, user_id: str, 
                       client_id: str,
                       nonce: Optional[str] = None,
                       auth_time: Optional[int] = None,
                       additional_claims: Optional[Dict[str, Any]] = None) -> str:
        """
        Create an OpenID Connect ID Token (PQ-signed)
        
        Args:
            user_id: User identifier
            client_id: Client application ID
            nonce: Nonce from authentication request
            auth_time: Time of authentication
            additional_claims: Additional user claims
            
        Returns:
            Signed ID Token (JWT)
        """
        payload = {}
        
        if nonce:
            payload["nonce"] = nonce
        
        if auth_time:
            payload["auth_time"] = auth_time
        else:
            payload["auth_time"] = int(time.time())
        
        return self.create_jwt(
            payload=payload,
            issuer=self.issuer,
            subject=user_id,
            audience=client_id,
            additional_claims=additional_claims
        )
    
    def verify_jwt(self, jwt: str, 
                   public_key: Optional[bytes] = None,
                   verify_expiration: bool = True,
                   audience: Optional[str] = None,
                   issuer: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify a PQ-signed JWT
        
        Args:
            jwt: JWT string
            public_key: Public key to verify with (uses own if None)
            verify_expiration: Check if token is expired
            audience: Expected audience value
            issuer: Expected issuer value
            
        Returns:
            Decoded payload dictionary
            
        Raises:
            ValueError: If verification fails
        """
        try:
            # Split JWT
            parts = jwt.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Decode header
            header_bytes = base64url_decode(header_encoded)
            header = json.loads(header_bytes.decode('utf-8'))
            
            # Check algorithm
            if header.get('alg') not in self.ALG_MAPPING.values():
                raise ValueError(f"Unsupported algorithm: {header.get('alg')}")
            
            # Decode payload
            payload_bytes = base64url_decode(payload_encoded)
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            # Decode signature
            signature = base64url_decode(signature_encoded)
            
            # Verify signature
            signing_input = f"{header_encoded}.{payload_encoded}"
            verify_key = public_key if public_key else self.public_key
            
            if not verify_key:
                raise ValueError("No public key available for verification")
            
            verifier = SignatureVerifier(
                algorithm=header['alg'],
                public_key=verify_key
            )
            
            is_valid = verifier.verify(signing_input.encode('utf-8'), signature)
            
            if not is_valid:
                raise ValueError("Signature verification failed")
            
            # Verify expiration
            if verify_expiration:
                current_time = int(time.time())
                if payload.get('exp', 0) < current_time:
                    raise ValueError("Token expired")
                
                if payload.get('nbf', 0) > current_time:
                    raise ValueError("Token not yet valid")
            
            # Verify audience
            if audience and payload.get('aud') != audience:
                raise ValueError(f"Audience mismatch: expected {audience}, got {payload.get('aud')}")
            
            # Verify issuer
            if issuer and payload.get('iss') != issuer:
                raise ValueError(f"Issuer mismatch: expected {issuer}, got {payload.get('iss')}")
            
            logger.info("JWT verification successful")
            return payload
            
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"JWT verification error: {e}")
    
    def decode_jwt_unverified(self, jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Decode JWT without verification (for inspection only)
        
        Args:
            jwt: JWT string
            
        Returns:
            Tuple of (header, payload)
        """
        parts = jwt.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header_encoded, payload_encoded, _ = parts
        
        header_bytes = base64url_decode(header_encoded)
        header = json.loads(header_bytes.decode('utf-8'))
        
        payload_bytes = base64url_decode(payload_encoded)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        return header, payload


def test_pq_jwt():
    """Test Post-Quantum JWT creation and verification"""
    print("Testing Post-Quantum JWT...")
    
    # Test each supported algorithm
    for algo in ["ML-DSA-44", "ML-DSA-65", "Falcon-512"]:
        print(f"\nTesting JWT with {algo}:")
        
        # Create handler and generate keypair
        handler = PQJWTHandler(algo)
        public_key = handler.generate_keypair()
        print(f"  ✓ Generated keypair, public key: {len(public_key)} bytes")
        
        # Create JWT
        jwt = handler.create_jwt(
            payload={"email": "user@example.com", "role": "admin"},
            issuer="https://pq-oidc.example.com",
            subject="user123",
            audience="client-app",
            expires_in=3600
        )
        print(f"  ✓ Created JWT: {len(jwt)} bytes")
        print(f"    JWT preview: {jwt[:50]}...{jwt[-50:]}")
        
        # Verify JWT
        try:
            payload = handler.verify_jwt(jwt)
            assert payload['sub'] == "user123"
            assert payload['email'] == "user@example.com"
            print(f"  ✓ JWT verified successfully")
            print(f"    Subject: {payload['sub']}")
            print(f"    Email: {payload['email']}")
            print(f"    Expires: {payload['exp']}")
        except Exception as e:
            print(f"  ✗ JWT verification failed: {e}")
            raise
        
        # Test verification with different key (should fail)
        other_handler = PQJWTHandler(algo)
        other_handler.generate_keypair()
        try:
            other_handler.verify_jwt(jwt)
            assert False, "JWT verified with wrong key!"
        except ValueError:
            print(f"  ✓ Correctly rejected JWT with wrong key")
        
        # Test ID Token
        id_token = handler.create_id_token(
            user_id="user456",
            client_id="webapp",
            nonce="abc123",
            additional_claims={
                "name": "John Doe",
                "email": "john@example.com",
                "email_verified": True
            }
        )
        print(f"  ✓ Created ID Token: {len(id_token)} bytes")
        
        # Verify ID Token
        try:
            id_payload = handler.verify_jwt(id_token, audience="webapp")
            assert id_payload['sub'] == "user456"
            assert id_payload['nonce'] == "abc123"
            print(f"  ✓ ID Token verified successfully")
            print(f"    Name: {id_payload.get('name')}")
            print(f"    Email: {id_payload.get('email')}")
        except Exception as e:
            print(f"  ✗ ID Token verification failed: {e}")
            raise
    
    print("\n" + "="*70)
    print("✓ ALL PQ-JWT TESTS PASSED!")
    print("="*70)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_pq_jwt()

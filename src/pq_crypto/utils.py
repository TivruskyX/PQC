"""
Utility functions for post-quantum cryptography
Includes key derivation, encoding, and helper functions
"""

import hashlib
import hmac
import base64
from typing import Tuple


def base64url_encode(data: bytes) -> str:
    """
    Base64url encode data (URL-safe, no padding)
    Used for JWT encoding
    
    Args:
        data: Bytes to encode
        
    Returns:
        Base64url encoded string
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """
    Base64url decode data
    
    Args:
        data: Base64url encoded string
        
    Returns:
        Decoded bytes
    """
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
    """
    HKDF Extract step
    
    Args:
        salt: Salt value
        input_key_material: Input keying material
        
    Returns:
        Pseudorandom key
    """
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF Expand step
    
    Args:
        prk: Pseudorandom key from extract
        info: Context and application specific information
        length: Length of output keying material in bytes
        
    Returns:
        Output keying material
    """
    hash_len = 32  # SHA256 output length
    n = (length + hash_len - 1) // hash_len
    
    okm = b""
    previous = b""
    
    for i in range(1, n + 1):
        previous = hmac.new(
            prk,
            previous + info + bytes([i]),
            hashlib.sha256
        ).digest()
        okm += previous
    
    return okm[:length]


def hkdf(salt: bytes, input_key_material: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF (HMAC-based Key Derivation Function) - RFC 5869
    Used to derive session keys from KEMTLS shared secret
    
    Args:
        salt: Salt value
        input_key_material: Input keying material (e.g., KEM shared secret)
        info: Context and application specific information
        length: Length of output keying material in bytes
        
    Returns:
        Derived key material
    """
    prk = hkdf_extract(salt, input_key_material)
    return hkdf_expand(prk, info, length)


def derive_session_keys(shared_secret: bytes, session_context: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Derive session keys from KEM shared secret
    
    Args:
        shared_secret: Shared secret from KEM
        session_context: Session-specific context (e.g., random nonces)
        
    Returns:
        Tuple of (encryption_key, mac_key, iv)
    """
    # Derive 80 bytes total: 32 for encryption, 32 for MAC, 16 for IV
    salt = b"KEMTLS-Session-Keys"
    info = b"PQ-OIDC-v1|" + session_context
    
    key_material = hkdf(salt, shared_secret, info, 80)
    
    encryption_key = key_material[:32]
    mac_key = key_material[32:64]
    iv = key_material[64:80]
    
    return encryption_key, mac_key, iv


def compute_sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 hash
    
    Args:
        data: Data to hash
        
    Returns:
        Hash digest
    """
    return hashlib.sha256(data).digest()


def compute_sha256_hex(data: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string
    
    Args:
        data: Data to hash
        
    Returns:
        Hex encoded hash
    """
    return hashlib.sha256(data).hexdigest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks
    
    Args:
        a: First bytes sequence
        b: Second bytes sequence
        
    Returns:
        True if equal
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes
    
    Args:
        length: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    import os
    return os.urandom(length)


def generate_nonce(length: int = 16) -> bytes:
    """
    Generate a random nonce
    
    Args:
        length: Nonce length in bytes (default 16)
        
    Returns:
        Random nonce
    """
    return generate_random_bytes(length)


if __name__ == "__main__":
    # Test utilities
    print("Testing PQ Crypto Utilities...")
    
    # Test base64url encoding
    data = b"Hello, Post-Quantum World!"
    encoded = base64url_encode(data)
    decoded = base64url_decode(encoded)
    assert data == decoded
    print(f"✓ Base64url encoding/decoding: {encoded}")
    
    # Test HKDF
    ikm = generate_random_bytes(32)
    salt = b"test-salt"
    info = b"test-context"
    derived = hkdf(salt, ikm, info, 32)
    print(f"✓ HKDF derived {len(derived)} bytes")
    
    # Test session key derivation
    shared_secret = generate_random_bytes(32)
    context = generate_random_bytes(16)
    enc_key, mac_key, iv = derive_session_keys(shared_secret, context)
    print(f"✓ Session keys derived - enc: {len(enc_key)}, mac: {len(mac_key)}, iv: {len(iv)}")
    
    # Test constant time compare
    assert constant_time_compare(b"test", b"test")
    assert not constant_time_compare(b"test", b"fail")
    print("✓ Constant-time comparison working")
    
    print("\nAll utility tests passed!")

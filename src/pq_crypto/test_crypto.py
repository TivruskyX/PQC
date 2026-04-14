"""
Test suite for post-quantum cryptography components
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.pq_crypto.kem import test_kyber_kem
from src.pq_crypto.signature import test_dilithium_signatures
from src.pq_crypto import utils

def main():
    """Run all PQ crypto tests"""
    print("="*70)
    print("POST-QUANTUM CRYPTOGRAPHY TEST SUITE")
    print("="*70)
    print()
    
    # Test KEM
    print("=" * 70)
    test_kyber_kem()
    print()
    
    # Test Signatures
    print("=" * 70)
    test_dilithium_signatures()
    print()
    
    # Test utilities
    print("=" * 70)
    print("Testing Utilities...")
    
    # Test base64url
    data = b"Test data for encoding"
    encoded = utils.base64url_encode(data)
    decoded = utils.base64url_decode(encoded)
    assert data == decoded, "Base64url encoding failed"
    print(f"✓ Base64url encoding/decoding works")
    
    # Test key derivation
    shared_secret = utils.generate_random_bytes(32)
    context = utils.generate_random_bytes(16)
    enc_key, mac_key, iv = utils.derive_session_keys(shared_secret, context)
    assert len(enc_key) == 32
    assert len(mac_key) == 32
    assert len(iv) == 16
    print(f"✓ Session key derivation works")
    
    print()
    print("=" * 70)
    print("✓ ALL POST-QUANTUM CRYPTOGRAPHY TESTS PASSED!")
    print("=" * 70)


if __name__ == "__main__":
    main()

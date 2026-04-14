"""
Post-Quantum Digital Signature Wrapper
Uses Dilithium from liboqs for quantum-resistant signatures
"""

from typing import Optional
import logging

try:
    from oqs import Signature
except ImportError:
    raise ImportError(
        "liboqs-python not installed. "
        "Install with: pip install liboqs-python"
    )

logger = logging.getLogger(__name__)


class DilithiumSigner:
    """
    Wrapper for ML-DSA (Dilithium) digital signature scheme
    Provides post-quantum secure signatures
    
    Note: Dilithium was renamed to ML-DSA in NIST standardization
    ML-DSA-44 = Dilithium2, ML-DSA-65 = Dilithium3, ML-DSA-87 = Dilithium5
    """
    
    SUPPORTED_ALGORITHMS = [
        "ML-DSA-44",    # Dilithium2 (NIST Level 2)
        "ML-DSA-65",    # Dilithium3 (NIST Level 3)
        "ML-DSA-87",    # Dilithium5 (NIST Level 5)
        "Falcon-512",
        "Falcon-1024",
    ]
    
    def __init__(self, algorithm: str = "ML-DSA-44"):
        """
        Initialize ML-DSA (Dilithium) signer
        
        Args:
            algorithm: Signature algorithm (ML-DSA-44, ML-DSA-65, ML-DSA-87, Falcon-512, Falcon-1024)
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported: {self.SUPPORTED_ALGORITHMS}"
            )
        
        self.algorithm = algorithm
        self.signer = Signature(algorithm)
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None
        
        logger.info(f"Initialized DilithiumSigner with {algorithm}")
    
    def generate_keypair(self) -> bytes:
        """
        Generate a new signing keypair
        
        Returns:
            Public key bytes
        """
        self.public_key = self.signer.generate_keypair()
        logger.debug(f"Generated signing keypair, public key size: {len(self.public_key)} bytes")
        return self.public_key
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message
        
        Args:
            message: Message bytes to sign
            
        Returns:
            Signature bytes
        """
        if not self.public_key:
            raise RuntimeError("No keypair generated. Call generate_keypair() first")
        
        signature = self.signer.sign(message)
        logger.debug(f"Signed message of {len(message)} bytes, signature: {len(signature)} bytes")
        return signature
    
    def verify(self, message: bytes, signature: bytes, public_key: Optional[bytes] = None) -> bool:
        """
        Verify a signature
        
        Args:
            message: Original message bytes
            signature: Signature bytes
            public_key: Public key to verify with (uses own if None)
            
        Returns:
            True if signature is valid
        """
        verify_key = public_key if public_key else self.public_key
        
        if not verify_key:
            raise RuntimeError("No public key available for verification")
        
        try:
            is_valid = self.signer.verify(message, signature, verify_key)
            logger.debug(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
            return is_valid
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def get_public_key(self) -> bytes:
        """Get the current public key"""
        if not self.public_key:
            raise RuntimeError("No keypair generated")
        return self.public_key
    
    @classmethod
    def get_algorithm_info(cls, algorithm: str) -> dict:
        """
        Get information about a specific signature algorithm
        
        Returns:
            Dictionary with algorithm parameters
        """
        info = {
            "ML-DSA-44": {  # Dilithium2
                "security_level": 2,
                "public_key_size": 1312,
                "secret_key_size": 2528,
                "signature_size": 2420,
                "nist_level": 2,
            },
            "ML-DSA-65": {  # Dilithium3
                "security_level": 3,
                "public_key_size": 1952,
                "secret_key_size": 4000,
                "signature_size": 3293,
                "nist_level": 3,
            },
            "ML-DSA-87": {  # Dilithium5
                "security_level": 5,
                "public_key_size": 2592,
                "secret_key_size": 4864,
                "signature_size": 4595,
                "nist_level": 5,
            },
            "Falcon-512": {
                "security_level": 1,
                "public_key_size": 897,
                "secret_key_size": 1281,
                "signature_size": 666,
                "nist_level": 1,
            },
            "Falcon-1024": {
                "security_level": 5,
                "public_key_size": 1793,
                "secret_key_size": 2305,
                "signature_size": 1280,
                "nist_level": 5,
            },
        }
        return info.get(algorithm, {})


class SignatureVerifier:
    """
    Standalone verifier for post-quantum signatures
    Used when you only have a public key and need to verify
    """
    
    def __init__(self, algorithm: str, public_key: bytes):
        """
        Initialize verifier with public key
        
        Args:
            algorithm: Signature algorithm
            public_key: Public key bytes
        """
        self.algorithm = algorithm
        self.public_key = public_key
        self.verifier = Signature(algorithm)
        logger.info(f"Initialized SignatureVerifier with {algorithm}")
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature"""
        try:
            is_valid = self.verifier.verify(message, signature, self.public_key)
            return is_valid
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False


def test_dilithium_signatures():
    """Test basic ML-DSA (Dilithium) signature functionality"""
    print("Testing ML-DSA (Dilithium) Signatures...")
    
    # Test all supported algorithms
    for algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024"]:
        print(f"\nTesting {algo}:")
        
        # Generate keypair
        signer = DilithiumSigner(algo)
        public_key = signer.generate_keypair()
        print(f"  ✓ Generated keypair")
        print(f"    Public key size: {len(public_key)} bytes")
        
        # Sign a message
        message = b"Post-Quantum OpenID Connect using KEMTLS"
        signature = signer.sign(message)
        print(f"  ✓ Signed message")
        print(f"    Message size: {len(message)} bytes")
        print(f"    Signature size: {len(signature)} bytes")
        
        # Verify with signer's own key
        is_valid = signer.verify(message, signature)
        assert is_valid, "Signature verification failed!"
        print(f"  ✓ Verified signature with signer's key")
        
        # Verify with standalone verifier
        verifier = SignatureVerifier(algo, public_key)
        is_valid = verifier.verify(message, signature)
        assert is_valid, "Standalone verification failed!"
        print(f"  ✓ Verified signature with standalone verifier")
        
        # Test invalid signature
        invalid_message = b"Modified message"
        is_valid = signer.verify(invalid_message, signature)
        assert not is_valid, "Invalid signature verified as valid!"
        print(f"  ✓ Correctly rejected invalid signature")
        
        # Print algorithm info
        info = DilithiumSigner.get_algorithm_info(algo)
        print(f"  Security level: NIST Level {info['nist_level']}")


if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(level=logging.INFO)
    test_dilithium_signatures()

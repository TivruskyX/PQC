"""
Post-Quantum Key Encapsulation Mechanism (KEM) Wrapper
Uses Kyber from liboqs for quantum-resistant key exchange
"""

from typing import Tuple, Optional
import logging

try:
    from oqs import KeyEncapsulation
except ImportError:
    raise ImportError(
        "liboqs-python not installed. "
        "Install with: pip install liboqs-python"
    )

logger = logging.getLogger(__name__)


class KyberKEM:
    """
    Wrapper for Kyber KEM (Key Encapsulation Mechanism)
    Provides post-quantum secure key exchange
    """
    
    SUPPORTED_ALGORITHMS = ["Kyber512", "Kyber768", "Kyber1024"]
    
    def __init__(self, algorithm: str = "Kyber512"):
        """
        Initialize Kyber KEM
        
        Args:
            algorithm: Kyber variant (Kyber512, Kyber768, Kyber1024)
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm: {algorithm}. "
                f"Supported: {self.SUPPORTED_ALGORITHMS}"
            )
        
        self.algorithm = algorithm
        self.kem = KeyEncapsulation(algorithm)
        self.public_key: Optional[bytes] = None
        self.secret_key: Optional[bytes] = None
        
        logger.info(f"Initialized KyberKEM with {algorithm}")
    
    def generate_keypair(self) -> bytes:
        """
        Generate a new KEM keypair
        
        Returns:
            Public key bytes
        """
        self.public_key = self.kem.generate_keypair()
        logger.debug(f"Generated keypair, public key size: {len(self.public_key)} bytes")
        return self.public_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using recipient's public key
        
        Args:
            public_key: Recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        logger.debug(
            f"Encapsulated secret - ciphertext: {len(ciphertext)} bytes, "
            f"shared secret: {len(shared_secret)} bytes"
        )
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate ciphertext to recover shared secret
        
        Args:
            ciphertext: Encapsulated secret
            
        Returns:
            Shared secret bytes
        """
        if not self.public_key:
            raise RuntimeError("No keypair generated. Call generate_keypair() first")
        
        shared_secret = self.kem.decap_secret(ciphertext)
        logger.debug(f"Decapsulated secret: {len(shared_secret)} bytes")
        return shared_secret
    
    def get_public_key(self) -> bytes:
        """Get the current public key"""
        if not self.public_key:
            raise RuntimeError("No keypair generated")
        return self.public_key
    
    @classmethod
    def get_algorithm_info(cls, algorithm: str) -> dict:
        """
        Get information about a specific Kyber algorithm
        
        Returns:
            Dictionary with algorithm parameters
        """
        info = {
            "Kyber512": {
                "security_level": 1,
                "public_key_size": 800,
                "secret_key_size": 1632,
                "ciphertext_size": 768,
                "shared_secret_size": 32,
            },
            "Kyber768": {
                "security_level": 3,
                "public_key_size": 1184,
                "secret_key_size": 2400,
                "ciphertext_size": 1088,
                "shared_secret_size": 32,
            },
            "Kyber1024": {
                "security_level": 5,
                "public_key_size": 1568,
                "secret_key_size": 3168,
                "ciphertext_size": 1568,
                "shared_secret_size": 32,
            },
        }
        return info.get(algorithm, {})


def test_kyber_kem():
    """Test basic Kyber KEM functionality"""
    print("Testing Kyber KEM...")
    
    # Test Kyber512
    for algo in ["Kyber512", "Kyber768", "Kyber1024"]:
        print(f"\nTesting {algo}:")
        
        # Sender generates keypair
        sender = KyberKEM(algo)
        sender_public_key = sender.generate_keypair()
        print(f"  ✓ Generated keypair")
        print(f"    Public key size: {len(sender_public_key)} bytes")
        
        # Recipient encapsulates secret
        recipient = KyberKEM(algo)
        ciphertext, shared_secret_recipient = recipient.encapsulate(sender_public_key)
        print(f"  ✓ Encapsulated shared secret")
        print(f"    Ciphertext size: {len(ciphertext)} bytes")
        print(f"    Shared secret size: {len(shared_secret_recipient)} bytes")
        
        # Sender decapsulates to recover secret
        shared_secret_sender = sender.decapsulate(ciphertext)
        print(f"  ✓ Decapsulated shared secret")
        
        # Verify shared secrets match
        assert shared_secret_sender == shared_secret_recipient, "Shared secrets don't match!"
        print(f"  ✓ Shared secrets match!")
        
        # Print algorithm info
        info = KyberKEM.get_algorithm_info(algo)
        print(f"  Security level: NIST Level {info['security_level']}")


if __name__ == "__main__":
    # Configure logging for testing
    logging.basicConfig(level=logging.INFO)
    test_kyber_kem()

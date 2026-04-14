"""
KEMTLS Protocol Implementation
Replaces TLS handshake with KEM-based key exchange

KEMTLS Protocol Overview:
1. Client Hello: Client sends its ephemeral KEM public key
2. Server Hello: Server encapsulates shared secret using client's public key,
                  sends ciphertext and server's certificate (with KEM public key)
3. Server Auth: Server proves possession of certificate private key
4. Finished: Both parties derive session keys and complete handshake

This implementation provides:
- Forward secrecy
- Mutual authentication (optional)
- Post-quantum security
"""

import json
import struct
import logging
from typing import Tuple, Optional, Dict
from enum import Enum

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.pq_crypto.utils import (
    derive_session_keys,
    generate_nonce,
    compute_sha256,
    constant_time_compare
)

logger = logging.getLogger(__name__)


class KEMTLSMessageType(Enum):
    """KEMTLS message types"""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    SERVER_CERTIFICATE = 0x03
    SERVER_KEMTLS_AUTH = 0x04
    CLIENT_FINISHED = 0x05
    SERVER_FINISHED = 0x06
    ENCRYPTED_DATA = 0x10
    ALERT = 0xFF


class KEMTLSState(Enum):
    """KEMTLS connection state"""
    START = 0
    CLIENT_HELLO_SENT = 1
    SERVER_HELLO_RECEIVED = 2
    HANDSHAKE_COMPLETE = 3
    ENCRYPTED = 4
    CLOSED = 5


class KEMTLSMessage:
    """
    KEMTLS Protocol Message
    
    Format:
    - Type (1 byte)
    - Length (4 bytes, big-endian)
    - Payload (variable)
    """
    
    def __init__(self, msg_type: KEMTLSMessageType, payload: bytes):
        self.msg_type = msg_type
        self.payload = payload
    
    def serialize(self) -> bytes:
        """Serialize message to bytes"""
        msg_type_byte = struct.pack('B', self.msg_type.value)
        length = struct.pack('>I', len(self.payload))
        return msg_type_byte + length + self.payload
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'KEMTLSMessage':
        """Deserialize message from bytes"""
        if len(data) < 5:
            raise ValueError("Message too short")
        
        msg_type_val = struct.unpack('B', data[0:1])[0]
        msg_type = KEMTLSMessageType(msg_type_val)
        length = struct.unpack('>I', data[1:5])[0]
        
        if len(data) < 5 + length:
            raise ValueError("Incomplete message")
        
        payload = data[5:5+length]
        return cls(msg_type, payload)


class KEMTLSCertificate:
    """
    Simplified KEMTLS Certificate
    Contains:
    - Subject name
    - KEM public key
    - Signature public key
    - Signature over the above (self-signed for now)
    """
    
    def __init__(self, subject: str, kem_public_key: bytes, 
                 sig_public_key: bytes, signature: Optional[bytes] = None):
        self.subject = subject
        self.kem_public_key = kem_public_key
        self.sig_public_key = sig_public_key
        self.signature = signature
    
    def to_bytes(self) -> bytes:
        """Serialize certificate"""
        cert_dict = {
            "subject": self.subject,
            "kem_pk": self.kem_public_key.hex(),
            "sig_pk": self.sig_public_key.hex(),
        }
        if self.signature:
            cert_dict["signature"] = self.signature.hex()
        return json.dumps(cert_dict).encode('utf-8')
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'KEMTLSCertificate':
        """Deserialize certificate"""
        cert_dict = json.loads(data.decode('utf-8'))
        signature = bytes.fromhex(cert_dict["signature"]) if "signature" in cert_dict else None
        return cls(
            subject=cert_dict["subject"],
            kem_public_key=bytes.fromhex(cert_dict["kem_pk"]),
            sig_public_key=bytes.fromhex(cert_dict["sig_pk"]),
            signature=signature
        )
    
    def get_tbs_data(self) -> bytes:
        """Get 'to be signed' data"""
        return f"{self.subject}|{self.kem_public_key.hex()}|{self.sig_public_key.hex()}".encode()
    
    def sign(self, signer: DilithiumSigner):
        """Sign the certificate"""
        tbs = self.get_tbs_data()
        self.signature = signer.sign(tbs)
    
    def verify(self) -> bool:
        """Verify certificate signature"""
        if not self.signature:
            return False
        tbs = self.get_tbs_data()
        from src.pq_crypto.signature import SignatureVerifier
        verifier = SignatureVerifier(
            algorithm="ML-DSA-44",  # TODO: Extract from cert
            public_key=self.sig_public_key
        )
        return verifier.verify(tbs, self.signature)


class KEMTLSSession:
    """
    KEMTLS Session State
    Manages session keys and encryption
    """
    
    def __init__(self):
        self.encryption_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        self.iv: Optional[bytes] = None
        self.client_nonce: Optional[bytes] = None
        self.server_nonce: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
    
    def derive_keys(self, shared_secret: bytes, client_nonce: bytes, server_nonce: bytes):
        """Derive session keys from shared secret"""
        self.shared_secret = shared_secret
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce
        
        context = client_nonce + server_nonce
        self.encryption_key, self.mac_key, self.iv = derive_session_keys(
            shared_secret, context
        )
        logger.info("Session keys derived successfully")
    
    def is_ready(self) -> bool:
        """Check if session is ready for encryption"""
        return all([
            self.encryption_key,
            self.mac_key,
            self.iv,
            self.shared_secret
        ])


def test_kemtls_messages():
    """Test KEMTLS message serialization"""
    print("Testing KEMTLS Message Format...")
    
    # Test message serialization
    payload = b"Test payload data"
    msg = KEMTLSMessage(KEMTLSMessageType.CLIENT_HELLO, payload)
    serialized = msg.serialize()
    print(f"✓ Serialized message: {len(serialized)} bytes")
    
    # Test deserialization
    deserialized = KEMTLSMessage.deserialize(serialized)
    assert deserialized.msg_type == KEMTLSMessageType.CLIENT_HELLO
    assert deserialized.payload == payload
    print(f"✓ Deserialized message correctly")
    
    print("\nTesting KEMTLS Certificate...")
    
    # Create certificate
    kem = KyberKEM("Kyber512")
    kem_pk = kem.generate_keypair()
    
    signer = DilithiumSigner("ML-DSA-44")
    sig_pk = signer.generate_keypair()
    
    cert = KEMTLSCertificate(
        subject="CN=localhost",
        kem_public_key=kem_pk,
        sig_public_key=sig_pk
    )
    
    # Sign certificate
    cert.sign(signer)
    print(f"✓ Created and signed certificate")
    print(f"  Subject: {cert.subject}")
    print(f"  KEM public key: {len(cert.kem_public_key)} bytes")
    print(f"  Signature public key: {len(cert.sig_public_key)} bytes")
    print(f"  Signature: {len(cert.signature)} bytes")
    
    # Serialize and deserialize
    cert_bytes = cert.to_bytes()
    cert_restored = KEMTLSCertificate.from_bytes(cert_bytes)
    print(f"✓ Serialized certificate: {len(cert_bytes)} bytes")
    
    # Verify signature
    is_valid = cert_restored.verify()
    assert is_valid
    print(f"✓ Certificate signature verified")
    
    print("\nTesting KEMTLS Session...")
    
    # Test session key derivation
    session = KEMTLSSession()
    shared_secret = generate_nonce(32)
    client_nonce = generate_nonce(16)
    server_nonce = generate_nonce(16)
    
    session.derive_keys(shared_secret, client_nonce, server_nonce)
    assert session.is_ready()
    print(f"✓ Session keys derived")
    print(f"  Encryption key: {len(session.encryption_key)} bytes")
    print(f"  MAC key: {len(session.mac_key)} bytes")
    print(f"  IV: {len(session.iv)} bytes")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_kemtls_messages()

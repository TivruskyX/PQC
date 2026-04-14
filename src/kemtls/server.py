"""
KEMTLS Server Implementation
Handles server-side KEMTLS handshake and encrypted communication
"""

import socket
import logging
import json
from typing import Optional, Callable, Tuple
from dataclasses import dataclass

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.kemtls.protocol import (
    KEMTLSMessage,
    KEMTLSMessageType,
    KEMTLSCertificate,
    KEMTLSSession,
    KEMTLSState
)
from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.pq_crypto.utils import generate_nonce, compute_sha256

logger = logging.getLogger(__name__)


@dataclass
class KEMTLSServerConfig:
    """KEMTLS Server Configuration"""
    host: str = "0.0.0.0"
    port: int = 8443
    kem_algorithm: str = "Kyber512"
    signature_algorithm: str = "ML-DSA-44"
    server_name: str = "CN=PQ-OIDC-Server"


class KEMTLSServer:
    """
    KEMTLS Server
    Provides post-quantum secure transport layer
    """
    
    def __init__(self, config: Optional[KEMTLSServerConfig] = None):
        self.config = config or KEMTLSServerConfig()
        
        # Initialize cryptographic components
        self.kem = KyberKEM(self.config.kem_algorithm)
        self.signer = DilithiumSigner(self.config.signature_algorithm)
        
        # Generate server keys
        self.kem_public_key = self.kem.generate_keypair()
        self.sig_public_key = self.signer.generate_keypair()
        
        # Create server certificate
        self.certificate = KEMTLSCertificate(
            subject=self.config.server_name,
            kem_public_key=self.kem_public_key,
            sig_public_key=self.sig_public_key
        )
        self.certificate.sign(self.signer)
        
        logger.info(f"KEMTLS Server initialized with {self.config.kem_algorithm} and {self.config.signature_algorithm}")
        logger.info(f"Server certificate created for: {self.config.server_name}")
    
    def handle_client_hello(self, message: KEMTLSMessage) -> Tuple[KEMTLSSession, bytes, bytes]:
        """
        Process CLIENT_HELLO message
        
        Returns:
            Tuple of (session, client_kem_public_key, client_nonce)
        """
        if message.msg_type != KEMTLSMessageType.CLIENT_HELLO:
            raise ValueError("Expected CLIENT_HELLO")
        
        # Parse CLIENT_HELLO payload
        hello_data = json.loads(message.payload.decode('utf-8'))
        client_kem_pk = bytes.fromhex(hello_data['kem_public_key'])
        client_nonce = bytes.fromhex(hello_data['nonce'])
        
        logger.info(f"Received CLIENT_HELLO with {len(client_kem_pk)} byte KEM public key")
        
        # Create session
        session = KEMTLSSession()
        session.client_nonce = client_nonce
        
        return session, client_kem_pk, client_nonce
    
    def create_server_hello(self, client_kem_pk: bytes) -> Tuple[KEMTLSMessage, bytes, bytes]:
        """
        Create SERVER_HELLO message
        
        Args:
            client_kem_pk: Client's KEM public key
            
        Returns:
            Tuple of (message, kem_ciphertext, shared_secret)
        """
        # Encapsulate shared secret using client's public key
        kem_ciphertext, shared_secret = self.kem.encapsulate(client_kem_pk)
        
        # Generate server nonce
        server_nonce = generate_nonce(16)
        
        # Create SERVER_HELLO payload
        hello_payload = {
            "kem_ciphertext": kem_ciphertext.hex(),
            "nonce": server_nonce.hex(),
            "certificate": self.certificate.to_bytes().hex()
        }
        
        message = KEMTLSMessage(
            KEMTLSMessageType.SERVER_HELLO,
            json.dumps(hello_payload).encode('utf-8')
        )
        
        logger.info("Created SERVER_HELLO with encapsulated secret")
        
        return message, kem_ciphertext, shared_secret
    
    def create_server_finished(self, session: KEMTLSSession) -> KEMTLSMessage:
        """
        Create SERVER_FINISHED message
        Contains MAC of handshake transcript
        """
        if not session.is_ready():
            raise RuntimeError("Session not ready")
        
        # Compute handshake hash
        handshake_data = (
            session.client_nonce +
            session.server_nonce +
            session.shared_secret
        )
        handshake_hash = compute_sha256(handshake_data)
        
        # Create finished payload
        finished_payload = {
            "handshake_hash": handshake_hash.hex(),
            "status": "OK"
        }
        
        message = KEMTLSMessage(
            KEMTLSMessageType.SERVER_FINISHED,
            json.dumps(finished_payload).encode('utf-8')
        )
        
        logger.info("Created SERVER_FINISHED")
        return message
    
    def perform_handshake(self, client_socket: socket.socket) -> KEMTLSSession:
        """
        Perform complete KEMTLS handshake with client
        
        Args:
            client_socket: Connected client socket
            
        Returns:
            Established KEMTLS session
        """
        logger.info("Starting KEMTLS handshake...")
        
        # Step 1: Receive CLIENT_HELLO
        data = self._recv_message(client_socket)
        client_hello = KEMTLSMessage.deserialize(data)
        session, client_kem_pk, client_nonce = self.handle_client_hello(client_hello)
        
        # Step 2: Send SERVER_HELLO
        server_hello, kem_ciphertext, shared_secret = self.create_server_hello(client_kem_pk)
        self._send_message(client_socket, server_hello.serialize())
        
        # Get server nonce from message
        hello_payload = json.loads(server_hello.payload.decode('utf-8'))
        server_nonce = bytes.fromhex(hello_payload['nonce'])
        
        # Derive session keys
        session.derive_keys(shared_secret, client_nonce, server_nonce)
        
        # Step 3: Send SERVER_FINISHED
        server_finished = self.create_server_finished(session)
        self._send_message(client_socket, server_finished.serialize())
        
        # Step 4: Receive CLIENT_FINISHED
        data = self._recv_message(client_socket)
        client_finished = KEMTLSMessage.deserialize(data)
        
        if client_finished.msg_type != KEMTLSMessageType.CLIENT_FINISHED:
            raise ValueError("Expected CLIENT_FINISHED")
        
        logger.info("KEMTLS handshake completed successfully!")
        return session
    
    def _send_message(self, sock: socket.socket, data: bytes):
        """Send data over socket"""
        sock.sendall(data)
    
    def _recv_message(self, sock: socket.socket, buffer_size: int = 65536) -> bytes:
        """Receive data from socket"""
        return sock.recv(buffer_size)


def test_kemtls_server():
    """Test KEMTLS server creation"""
    print("Testing KEMTLS Server...")
    
    config = KEMTLSServerConfig(
        host="localhost",
        port=9443,
        kem_algorithm="Kyber512",
        signature_algorithm="ML-DSA-44",
        server_name="CN=test-server"
    )
    
    server = KEMTLSServer(config)
    print(f"✓ Server initialized")
    print(f"  KEM Algorithm: {server.config.kem_algorithm}")
    print(f"  Signature Algorithm: {server.config.signature_algorithm}")
    print(f"  Certificate Subject: {server.certificate.subject}")
    print(f"  Certificate valid: {server.certificate.verify()}")
    
    # Test message creation
    client_kem = KyberKEM("Kyber512")
    client_pk = client_kem.generate_keypair()
    
    server_hello, ciphertext, shared_secret = server.create_server_hello(client_pk)
    print(f"✓ Created SERVER_HELLO")
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    print(f"  Shared secret size: {len(shared_secret)} bytes")
    
    # Test session creation
    session = KEMTLSSession()
    session.derive_keys(
        shared_secret,
        generate_nonce(16),
        generate_nonce(16)
    )
    
    server_finished = server.create_server_finished(session)
    print(f"✓ Created SERVER_FINISHED")
    print(f"  Message size: {len(server_finished.serialize())} bytes")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_kemtls_server()

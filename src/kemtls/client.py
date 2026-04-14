"""
KEMTLS Client Implementation
Handles client-side KEMTLS handshake and encrypted communication
"""

import socket
import logging
import json
from typing import Optional, Tuple

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
from src.pq_crypto.utils import generate_nonce, compute_sha256

logger = logging.getLogger(__name__)


class KEMTLSClient:
    """
    KEMTLS Client
    Initiates connection and performs handshake with server
    """
    
    def __init__(self, kem_algorithm: str = "Kyber512"):
        self.kem_algorithm = kem_algorithm
        self.kem = KyberKEM(kem_algorithm)
        self.session: Optional[KEMTLSSession] = None
        self.server_certificate: Optional[KEMTLSCertificate] = None
        
        logger.info(f"KEMTLS Client initialized with {kem_algorithm}")
    
    def create_client_hello(self) -> Tuple[KEMTLSMessage, bytes, bytes]:
        """
        Create CLIENT_HELLO message
        
        Returns:
            Tuple of (message, kem_public_key, client_nonce)
        """
        # Generate ephemeral KEM keypair
        kem_public_key = self.kem.generate_keypair()
        
        # Generate client nonce
        client_nonce = generate_nonce(16)
        
        # Create CLIENT_HELLO payload
        hello_payload = {
            "kem_public_key": kem_public_key.hex(),
            "nonce": client_nonce.hex(),
            "supported_kem": self.kem_algorithm
        }
        
        message = KEMTLSMessage(
            KEMTLSMessageType.CLIENT_HELLO,
            json.dumps(hello_payload).encode('utf-8')
        )
        
        logger.info("Created CLIENT_HELLO")
        return message, kem_public_key, client_nonce
    
    def handle_server_hello(self, message: KEMTLSMessage) -> Tuple[bytes, bytes, KEMTLSCertificate]:
        """
        Process SERVER_HELLO message
        
        Returns:
            Tuple of (shared_secret, server_nonce, server_certificate)
        """
        if message.msg_type != KEMTLSMessageType.SERVER_HELLO:
            raise ValueError("Expected SERVER_HELLO")
        
        # Parse SERVER_HELLO payload
        hello_data = json.loads(message.payload.decode('utf-8'))
        kem_ciphertext = bytes.fromhex(hello_data['kem_ciphertext'])
        server_nonce = bytes.fromhex(hello_data['nonce'])
        cert_bytes = bytes.fromhex(hello_data['certificate'])
        
        # Decrypt shared secret
        shared_secret = self.kem.decapsulate(kem_ciphertext)
        
        # Parse server certificate
        server_cert = KEMTLSCertificate.from_bytes(cert_bytes)
        
        # Verify certificate
        if not server_cert.verify():
            raise ValueError("Invalid server certificate")
        
        logger.info("Received and verified SERVER_HELLO")
        logger.info(f"Server certificate: {server_cert.subject}")
        
        self.server_certificate = server_cert
        return shared_secret, server_nonce, server_cert
    
    def create_client_finished(self, session: KEMTLSSession) -> KEMTLSMessage:
        """
        Create CLIENT_FINISHED message
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
        
        finished_payload = {
            "handshake_hash": handshake_hash.hex(),
            "status": "OK"
        }
        
        message = KEMTLSMessage(
            KEMTLSMessageType.CLIENT_FINISHED,
            json.dumps(finished_payload).encode('utf-8')
        )
        
        logger.info("Created CLIENT_FINISHED")
        return message
    
    def connect_and_handshake(self, host: str, port: int) -> Tuple[socket.socket, KEMTLSSession]:
        """
        Connect to server and perform KEMTLS handshake
        
        Args:
            host: Server hostname
            port: Server port
            
        Returns:
            Tuple of (connected_socket, established_session)
        """
        logger.info(f"Connecting to {host}:{port}...")
        
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        logger.info("TCP connection established")
        
        # Step 1: Send CLIENT_HELLO
        client_hello, kem_pk, client_nonce = self.create_client_hello()
        self._send_message(sock, client_hello.serialize())
        
        # Step 2: Receive SERVER_HELLO
        data = self._recv_message(sock)
        server_hello = KEMTLSMessage.deserialize(data)
        shared_secret, server_nonce, server_cert = self.handle_server_hello(server_hello)
        
        # Create session and derive keys
        session = KEMTLSSession()
        session.derive_keys(shared_secret, client_nonce, server_nonce)
        
        # Step 3: Receive SERVER_FINISHED
        data = self._recv_message(sock)
        server_finished = KEMTLSMessage.deserialize(data)
        
        if server_finished.msg_type != KEMTLSMessageType.SERVER_FINISHED:
            raise ValueError("Expected SERVER_FINISHED")
        
        # Step 4: Send CLIENT_FINISHED
        client_finished = self.create_client_finished(session)
        self._send_message(sock, client_finished.serialize())
        
        logger.info("KEMTLS handshake completed successfully!")
        self.session = session
        
        return sock, session
    
    def _send_message(self, sock: socket.socket, data: bytes):
        """Send data over socket"""
        sock.sendall(data)
    
    def _recv_message(self, sock: socket.socket, buffer_size: int = 65536) -> bytes:
        """Receive data from socket"""
        return sock.recv(buffer_size)


def test_kemtls_client():
    """Test KEMTLS client creation"""
    print("Testing KEMTLS Client...")
    
    client = KEMTLSClient("Kyber512")
    print(f"✓ Client initialized with {client.kem_algorithm}")
    
    # Test message creation
    client_hello, kem_pk, nonce = client.create_client_hello()
    print(f"✓ Created CLIENT_HELLO")
    print(f"  KEM public key size: {len(kem_pk)} bytes")
    print(f"  Nonce size: {len(nonce)} bytes")
    print(f"  Message size: {len(client_hello.serialize())} bytes")
    
    # Test session
    session = KEMTLSSession()
    session.derive_keys(
        generate_nonce(32),
        nonce,
        generate_nonce(16)
    )
    
    client_finished = client.create_client_finished(session)
    print(f"✓ Created CLIENT_FINISHED")
    print(f"  Message size: {len(client_finished.serialize())} bytes")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_kemtls_client()

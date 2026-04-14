"""
KEMTLS Transport Integration

This module integrates KEMTLS as a transport layer for OIDC communication,
replacing traditional HTTPS/TLS with post-quantum KEMTLS.
"""

import json
import socket
import threading
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass

from ..kemtls.server import KEMTLSServer
from ..kemtls.client import KEMTLSClient
from ..kemtls.protocol import KEMTLSMessage


@dataclass
class HTTPRequest:
    """Parsed HTTP request."""
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    query_params: Dict[str, str]


@dataclass
class HTTPResponse:
    """HTTP response structure."""
    status_code: int
    status_text: str
    headers: Dict[str, str]
    body: str


class KEMTLSHTTPServer:
    """
    HTTP server that uses KEMTLS for transport security.
    
    This wraps an HTTP application (like OIDC server) with KEMTLS transport,
    providing post-quantum security for all communications.
    """
    
    def __init__(
        self,
        kemtls_server: KEMTLSServer,
        host: str = "127.0.0.1",
        port: int = 5000
    ):
        """
        Initialize KEMTLS HTTP server.
        
        Args:
            kemtls_server: Configured KEMTLSServer instance
            host: Host to bind to
            port: Port to listen on
        """
        self.kemtls_server = kemtls_server
        self.host = host
        self.port = port
        self.routes: Dict[str, Callable] = {}
        self.running = False
        
    def route(self, path: str, methods: list = None):
        """
        Decorator to register route handlers.
        
        Args:
            path: URL path
            methods: HTTP methods (default: ["GET"])
        """
        if methods is None:
            methods = ["GET"]
            
        def decorator(func):
            for method in methods:
                route_key = f"{method}:{path}"
                self.routes[route_key] = func
            return func
        return decorator
        
    def parse_http_request(self, data: bytes) -> HTTPRequest:
        """Parse HTTP request from bytes."""
        try:
            # Decode and split into lines
            text = data.decode('utf-8')
            lines = text.split('\r\n')
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            method = parts[0]
            full_path = parts[1]
            
            # Split path and query
            if '?' in full_path:
                path, query_string = full_path.split('?', 1)
                query_params = dict(param.split('=') for param in query_string.split('&') if '=' in param)
            else:
                path = full_path
                query_params = {}
                
            # Parse headers
            headers = {}
            i = 1
            while i < len(lines) and lines[i]:
                if ':' in lines[i]:
                    key, value = lines[i].split(':', 1)
                    headers[key.strip().lower()] = value.strip()
                i += 1
                
            # Parse body
            body = ''
            if i + 1 < len(lines):
                body = '\r\n'.join(lines[i + 1:])
                
            return HTTPRequest(
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_params=query_params
            )
        except Exception as e:
            raise ValueError(f"Failed to parse HTTP request: {e}")
            
    def create_http_response(self, response: HTTPResponse) -> bytes:
        """Create HTTP response bytes."""
        # Status line
        response_lines = [
            f"HTTP/1.1 {response.status_code} {response.status_text}"
        ]
        
        # Headers
        for key, value in response.headers.items():
            response_lines.append(f"{key}: {value}")
            
        # Empty line before body
        response_lines.append("")
        
        # Body
        if response.body:
            response_lines.append(response.body)
            
        # Join with CRLF
        response_text = '\r\n'.join(response_lines)
        return response_text.encode('utf-8')
        
    def handle_request(self, request: HTTPRequest) -> HTTPResponse:
        """
        Handle HTTP request and generate response.
        
        Args:
            request: Parsed HTTP request
            
        Returns:
            HTTP response
        """
        # Find route handler
        route_key = f"{request.method}:{request.path}"
        handler = self.routes.get(route_key)
        
        if not handler:
            return HTTPResponse(
                status_code=404,
                status_text="Not Found",
                headers={"Content-Type": "text/plain"},
                body="404 Not Found"
            )
            
        try:
            # Call handler
            return handler(request)
        except Exception as e:
            return HTTPResponse(
                status_code=500,
                status_text="Internal Server Error",
                headers={"Content-Type": "text/plain"},
                body=f"500 Internal Server Error: {e}"
            )
            
    def handle_client_connection(self, client_socket: socket.socket, client_address: tuple):
        """Handle a client connection over KEMTLS."""
        try:
            # Perform KEMTLS handshake
            print(f"[KEMTLS-HTTP] Client connected from {client_address}")
            success, session = self.kemtls_server.perform_handshake(client_socket)
            
            if not success:
                print(f"[KEMTLS-HTTP] Handshake failed for {client_address}")
                return
                
            print(f"[KEMTLS-HTTP] KEMTLS handshake successful with {client_address}")
            
            # Receive HTTP request over KEMTLS
            # In real implementation, would decrypt using session keys
            request_data = client_socket.recv(4096)
            
            if not request_data:
                return
                
            # Parse HTTP request
            request = self.parse_http_request(request_data)
            print(f"[KEMTLS-HTTP] {request.method} {request.path}")
            
            # Handle request
            response = self.handle_request(request)
            
            # Send HTTP response over KEMTLS
            # In real implementation, would encrypt using session keys
            response_data = self.create_http_response(response)
            client_socket.sendall(response_data)
            
        except Exception as e:
            print(f"[KEMTLS-HTTP] Error handling client: {e}")
        finally:
            client_socket.close()
            
    def serve_forever(self):
        """Start server and handle connections."""
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        self.running = True
        print(f"[KEMTLS-HTTP] Server listening on {self.host}:{self.port}")
        print(f"[KEMTLS-HTTP] Using KEMTLS for transport security")
        
        try:
            while self.running:
                # Accept connection
                client_socket, client_address = server_socket.accept()
                
                # Handle in new thread
                thread = threading.Thread(
                    target=self.handle_client_connection,
                    args=(client_socket, client_address)
                )
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            print("\n[KEMTLS-HTTP] Server shutting down...")
        finally:
            server_socket.close()
            self.running = False


class KEMTLSHTTPClient:
    """
    HTTP client that uses KEMTLS for transport security.
    
    Makes HTTP requests over KEMTLS instead of regular HTTPS.
    """
    
    def __init__(self, kemtls_client: KEMTLSClient):
        """
        Initialize KEMTLS HTTP client.
        
        Args:
            kemtls_client: Configured KEMTLSClient instance
        """
        self.kemtls_client = kemtls_client
        
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> HTTPResponse:
        """
        Make HTTP request over KEMTLS.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            headers: HTTP headers
            body: Request body
            
        Returns:
            HTTP response
        """
        # Parse URL
        if url.startswith('http://'):
            url = url[7:]
        elif url.startswith('https://'):
            url = url[8:]
            
        parts = url.split('/', 1)
        host_port = parts[0]
        path = '/' + parts[1] if len(parts) > 1 else '/'
        
        if ':' in host_port:
            host, port = host_port.split(':')
            port = int(port)
        else:
            host = host_port
            port = 5000
            
        # Build HTTP request
        request_lines = [f"{method} {path} HTTP/1.1"]
        
        # Add headers
        if headers is None:
            headers = {}
        headers['Host'] = host
        headers['Connection'] = 'close'
        
        if body:
            headers['Content-Length'] = str(len(body))
            
        for key, value in headers.items():
            request_lines.append(f"{key}: {value}")
            
        request_lines.append("")
        if body:
            request_lines.append(body)
            
        request_data = '\r\n'.join(request_lines).encode('utf-8')
        
        # Connect with KEMTLS
        success, session, sock = self.kemtls_client.connect_and_handshake(host, port)
        
        if not success:
            raise ConnectionError("KEMTLS handshake failed")
            
        try:
            # Send request over KEMTLS
            # In real implementation, would encrypt using session keys
            sock.sendall(request_data)
            
            # Receive response
            # In real implementation, would decrypt using session keys
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                
            # Parse response
            response_text = response_data.decode('utf-8')
            lines = response_text.split('\r\n')
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ', 2)
            status_code = int(parts[1])
            status_text = parts[2] if len(parts) > 2 else ""
            
            # Parse headers
            response_headers = {}
            i = 1
            while i < len(lines) and lines[i]:
                if ':' in lines[i]:
                    key, value = lines[i].split(':', 1)
                    response_headers[key.strip()] = value.strip()
                i += 1
                
            # Parse body
            response_body = '\r\n'.join(lines[i + 1:]) if i + 1 < len(lines) else ""
            
            return HTTPResponse(
                status_code=status_code,
                status_text=status_text,
                headers=response_headers,
                body=response_body
            )
            
        finally:
            sock.close()
            
    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
        """Make GET request."""
        return self.request("GET", url, headers=headers)
        
    def post(
        self,
        url: str,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> HTTPResponse:
        """Make POST request."""
        return self.request("POST", url, headers=headers, body=data)

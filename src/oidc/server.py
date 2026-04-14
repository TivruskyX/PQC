"""
Post-Quantum OpenID Connect Authorization Server

This module implements an OpenID Connect authorization server with
post-quantum cryptographic signatures for ID tokens. It provides
standard OIDC endpoints while using PQ signatures instead of RSA/ECDSA.
"""

import json
import secrets
import time
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlencode, parse_qs, urlparse

from .pq_jwt import PQJWTHandler


@dataclass
class User:
    """User account information."""
    user_id: str
    username: str
    password_hash: str  # In production, use proper password hashing
    email: str
    name: str
    given_name: str
    family_name: str


@dataclass
class Client:
    """Registered OIDC client application."""
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    grant_types: List[str]
    response_types: List[str]
    scope: List[str]


@dataclass
class AuthorizationCode:
    """Temporary authorization code issued during authorization flow."""
    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scope: List[str]
    nonce: Optional[str]
    expires_at: float
    used: bool = False


class PQOIDCServer:
    """
    Post-Quantum OpenID Connect Authorization Server.
    
    Implements OIDC endpoints with PQ-signed ID tokens:
    - /authorize - Authorization endpoint
    - /token - Token endpoint
    - /userinfo - UserInfo endpoint
    - /.well-known/openid-configuration - Discovery endpoint
    """
    
    def __init__(
        self,
        issuer: str,
        jwt_handler: PQJWTHandler,
        code_lifetime: int = 600,  # 10 minutes
        token_lifetime: int = 3600  # 1 hour
    ):
        """
        Initialize OIDC server.
        
        Args:
            issuer: Issuer identifier (e.g., https://auth.example.com)
            jwt_handler: PQ-JWT handler for token signing/verification
            code_lifetime: Authorization code lifetime in seconds
            token_lifetime: ID token lifetime in seconds
        """
        self.issuer = issuer
        self.jwt_handler = jwt_handler
        self.code_lifetime = code_lifetime
        self.token_lifetime = token_lifetime
        
        # In-memory storage (for demo - use DB in production)
        self.users: Dict[str, User] = {}
        self.clients: Dict[str, Client] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.sessions: Dict[str, str] = {}  # session_id -> user_id
        
        # Supported values
        self.supported_scopes = ["openid", "profile", "email"]
        self.supported_response_types = ["code"]
        self.supported_grant_types = ["authorization_code"]
        self.supported_signing_algs = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", 
                                       "Falcon-512", "Falcon-1024"]
        
    def register_user(self, user: User) -> None:
        """Register a user account."""
        self.users[user.username] = user
        
    def register_client(self, client: Client) -> None:
        """Register an OIDC client application."""
        self.clients[client.client_id] = client
        
    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate user credentials.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            User ID if authentication succeeds, None otherwise
        """
        user = self.users.get(username)
        if not user:
            return None
            
        # Simple password check (use proper hashing in production!)
        if user.password_hash == password:  # Demo only!
            return user.user_id
            
        return None
        
    def create_session(self, user_id: str) -> str:
        """Create an authenticated session."""
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = user_id
        return session_id
        
    def get_user_from_session(self, session_id: str) -> Optional[User]:
        """Get user from session ID."""
        user_id = self.sessions.get(session_id)
        if not user_id:
            return None
            
        for user in self.users.values():
            if user.user_id == user_id:
                return user
        return None
        
    def handle_authorization_request(
        self,
        response_type: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """
        Handle authorization endpoint request.
        
        Args:
            response_type: OAuth response type (must be "code")
            client_id: Client identifier
            redirect_uri: Redirect URI
            scope: Space-separated scopes
            state: Client state value
            nonce: Nonce for ID token
            session_id: User session ID (if already authenticated)
            
        Returns:
            Tuple of (redirect_url, error_message)
            If error_message is None, user needs to authenticate
        """
        # Validate client
        client = self.clients.get(client_id)
        if not client:
            return "", "invalid_client"
            
        # Validate response type
        if response_type not in client.response_types:
            error_params = {
                "error": "unsupported_response_type",
                "error_description": f"Response type {response_type} not supported",
                "state": state
            }
            return f"{redirect_uri}?{urlencode(error_params)}", None
            
        # Validate redirect URI
        if redirect_uri not in client.redirect_uris:
            return "", "invalid_redirect_uri"
            
        # Validate scope
        scopes = scope.split()
        if "openid" not in scopes:
            error_params = {
                "error": "invalid_scope",
                "error_description": "Scope must include 'openid'",
                "state": state
            }
            return f"{redirect_uri}?{urlencode(error_params)}", None
            
        # Check if user is authenticated
        user = self.get_user_from_session(session_id) if session_id else None
        if not user:
            # Need to show login form
            return "", None
            
        # Generate authorization code
        code = self.generate_authorization_code(
            client_id=client_id,
            user_id=user.user_id,
            redirect_uri=redirect_uri,
            scope=scopes,
            nonce=nonce
        )
        
        # Build redirect URL with code
        params = {"code": code}
        if state:
            params["state"] = state
            
        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return redirect_url, None
        
    def generate_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: List[str],
        nonce: Optional[str]
    ) -> str:
        """Generate an authorization code."""
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            expires_at=time.time() + self.code_lifetime
        )
        self.authorization_codes[code] = auth_code
        return code
        
    def handle_token_request(
        self,
        grant_type: str,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Handle token endpoint request.
        
        Args:
            grant_type: OAuth grant type (must be "authorization_code")
            code: Authorization code
            redirect_uri: Redirect URI (must match authorization request)
            client_id: Client identifier
            client_secret: Client secret
            
        Returns:
            Tuple of (token_response, error)
        """
        # Validate client credentials
        client = self.clients.get(client_id)
        if not client or client.client_secret != client_secret:
            return None, "invalid_client"
            
        # Validate grant type
        if grant_type not in client.grant_types:
            return None, "unsupported_grant_type"
            
        # Validate authorization code
        auth_code = self.authorization_codes.get(code)
        if not auth_code:
            return None, "invalid_grant"
            
        if auth_code.used:
            return None, "invalid_grant"
            
        if time.time() > auth_code.expires_at:
            return None, "invalid_grant"
            
        if auth_code.client_id != client_id:
            return None, "invalid_grant"
            
        if auth_code.redirect_uri != redirect_uri:
            return None, "invalid_grant"
            
        # Mark code as used
        auth_code.used = True
        
        # Get user
        user = None
        for u in self.users.values():
            if u.user_id == auth_code.user_id:
                user = u
                break
                
        if not user:
            return None, "invalid_grant"
            
        # Generate tokens
        now = time.time()
        expires_in = self.token_lifetime
        
        # Prepare additional claims based on scope
        additional_claims = {}
        
        # Add profile claims if requested
        if "profile" in auth_code.scope:
            additional_claims["name"] = user.name
            additional_claims["given_name"] = user.given_name
            additional_claims["family_name"] = user.family_name
            
        # Add email claim if requested
        if "email" in auth_code.scope:
            additional_claims["email"] = user.email
            additional_claims["email_verified"] = True
            
        # Sign ID token with PQ signature
        id_token = self.jwt_handler.create_id_token(
            user_id=user.user_id,
            client_id=client_id,
            nonce=auth_code.nonce,
            auth_time=int(now),
            additional_claims=additional_claims
        )
        
        # Generate access token (simplified - just a random token)
        access_token = secrets.token_urlsafe(32)
        
        # Build response
        token_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "id_token": id_token,
            "scope": " ".join(auth_code.scope)
        }
        
        return token_response, None
        
    def handle_userinfo_request(self, access_token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Handle userinfo endpoint request.
        
        Args:
            access_token: Access token from authorization
            
        Returns:
            Tuple of (userinfo, error)
        """
        # In a real implementation, validate access token and get associated user
        # For demo purposes, we'll just return an error
        return None, "invalid_token"
        
    def get_discovery_document(self) -> Dict:
        """
        Get OpenID Connect discovery document.
        
        Returns:
            Discovery document with server metadata
        """
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks",
            "registration_endpoint": f"{self.issuer}/register",
            "scopes_supported": self.supported_scopes,
            "response_types_supported": self.supported_response_types,
            "grant_types_supported": self.supported_grant_types,
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": self.supported_signing_algs,
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "name", "given_name", "family_name", "email", "email_verified"
            ],
            "code_challenge_methods_supported": ["S256"],
            "ui_locales_supported": ["en-US"]
        }


def create_demo_server() -> PQOIDCServer:
    """
    Create a demo OIDC server with sample users and clients.
    
    Returns:
        Configured PQOIDCServer instance
    """
    issuer = "http://localhost:5000"
    
    # Create JWT handler with ML-DSA-44 (fastest PQ signature)
    jwt_handler = PQJWTHandler(algorithm="ML-DSA-44", issuer=issuer)
    jwt_handler.generate_keypair()
    
    # Create server
    server = PQOIDCServer(
        issuer=issuer,
        jwt_handler=jwt_handler
    )
    
    # Register demo user
    demo_user = User(
        user_id="user123",
        username="alice",
        password_hash="password123",  # WARNING: Demo only! Use proper hashing!
        email="alice@example.com",
        name="Alice Smith",
        given_name="Alice",
        family_name="Smith"
    )
    server.register_user(demo_user)
    
    # Register demo client
    demo_client = Client(
        client_id="demo-client",
        client_secret="demo-secret",
        redirect_uris=["http://localhost:8080/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
        scope=["openid", "profile", "email"]
    )
    server.register_client(demo_client)
    
    return server

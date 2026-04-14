"""
Post-Quantum OpenID Connect Client

This module implements an OpenID Connect client that can authenticate
users with a PQ-OIDC server and verify PQ-signed ID tokens.
"""

import secrets
import json
from typing import Dict, Optional, List
from urllib.parse import urlencode, parse_qs, urlparse

from .pq_jwt import PQJWTHandler


class PQOIDCClient:
    """
    Post-Quantum OpenID Connect Client.
    
    Handles authentication flows and PQ-signed token verification.
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        server_url: str,
        redirect_uri: str,
        jwt_handler: PQJWTHandler,
        scope: Optional[List[str]] = None
    ):
        """
        Initialize OIDC client.
        
        Args:
            client_id: Client identifier
            client_secret: Client secret
            server_url: OIDC server base URL
            redirect_uri: Redirect URI for callbacks
            jwt_handler: PQ-JWT handler for token verification
            scope: List of scopes to request
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.server_url = server_url.rstrip('/')
        self.redirect_uri = redirect_uri
        self.jwt_handler = jwt_handler
        self.scope = scope or ["openid", "profile", "email"]
        
        # Endpoints (can be discovered via .well-known)
        self.authorization_endpoint = f"{server_url}/authorize"
        self.token_endpoint = f"{server_url}/token"
        self.userinfo_endpoint = f"{server_url}/userinfo"
        
        # State management for CSRF protection
        self.pending_states: Dict[str, Dict] = {}
        
    def get_authorization_url(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        additional_params: Optional[Dict] = None
    ) -> str:
        """
        Generate authorization URL for user authentication.
        
        Args:
            state: State value for CSRF protection (generated if not provided)
            nonce: Nonce for ID token validation (generated if not provided)
            additional_params: Additional query parameters
            
        Returns:
            Authorization URL to redirect user to
        """
        # Generate state and nonce if not provided
        if not state:
            state = secrets.token_urlsafe(32)
        if not nonce:
            nonce = secrets.token_urlsafe(32)
            
        # Store state for validation
        self.pending_states[state] = {
            "nonce": nonce,
            "redirect_uri": self.redirect_uri
        }
        
        # Build parameters
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scope),
            "state": state,
            "nonce": nonce
        }
        
        # Add additional parameters
        if additional_params:
            params.update(additional_params)
            
        # Build URL
        auth_url = f"{self.authorization_endpoint}?{urlencode(params)}"
        return auth_url
        
    def validate_callback(
        self,
        callback_url: str
    ) -> Dict[str, str]:
        """
        Validate callback from authorization server.
        
        Args:
            callback_url: Full callback URL with query parameters
            
        Returns:
            Dictionary with 'code' and 'state'
            
        Raises:
            ValueError: If callback is invalid
        """
        # Parse callback URL
        parsed = urlparse(callback_url)
        params = parse_qs(parsed.query)
        
        # Extract parameters
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        error = params.get('error', [None])[0]
        
        # Check for errors
        if error:
            error_description = params.get('error_description', [''])[0]
            raise ValueError(f"Authorization error: {error} - {error_description}")
            
        # Validate code and state
        if not code:
            raise ValueError("Authorization code missing from callback")
        if not state:
            raise ValueError("State missing from callback")
            
        # Validate state (CSRF protection)
        if state not in self.pending_states:
            raise ValueError("Invalid state - possible CSRF attack")
            
        return {"code": code, "state": state}
        
    def exchange_code_for_tokens(
        self,
        code: str,
        state: str
    ) -> Dict[str, str]:
        """
        Exchange authorization code for tokens.
        
        Args:
            code: Authorization code
            state: State value from callback
            
        Returns:
            Dictionary with tokens:
            - access_token: Access token
            - token_type: Token type (usually "Bearer")
            - expires_in: Token lifetime in seconds
            - id_token: PQ-signed ID token
            - scope: Granted scopes
            
        Raises:
            ValueError: If token exchange fails
        """
        # Validate state
        if state not in self.pending_states:
            raise ValueError("Invalid state")
            
        state_data = self.pending_states[state]
        
        # Prepare token request
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": state_data["redirect_uri"],
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        # Note: In a real implementation, this would make an HTTP POST request
        # For our demo, we'll return a mock structure that the server will populate
        return {
            "token_request": token_data,
            "expected_nonce": state_data["nonce"]
        }
        
    def verify_id_token(
        self,
        id_token: str,
        expected_nonce: Optional[str] = None
    ) -> Dict:
        """
        Verify and decode PQ-signed ID token.
        
        Args:
            id_token: ID token JWT string
            expected_nonce: Expected nonce value
            
        Returns:
            Decoded token claims
            
        Raises:
            ValueError: If token verification fails
        """
        # Verify token signature and decode
        try:
            claims = self.jwt_handler.verify_jwt(
                id_token,
                audience=self.client_id,
                issuer=self.server_url
            )
        except Exception as e:
            raise ValueError(f"Token verification failed: {e}")
            
        # Verify nonce if provided
        if expected_nonce:
            token_nonce = claims.get("nonce")
            if token_nonce != expected_nonce:
                raise ValueError("Nonce mismatch - possible replay attack")
                
        return claims
        
    def get_user_info(self, access_token: str) -> Dict:
        """
        Get user information from userinfo endpoint.
        
        Args:
            access_token: Access token
            
        Returns:
            User information claims
        """
        # Note: In a real implementation, this would make an HTTP GET request
        # with Authorization: Bearer {access_token} header
        raise NotImplementedError("UserInfo endpoint not implemented in demo")
        
    def logout_url(
        self,
        post_logout_redirect_uri: Optional[str] = None,
        state: Optional[str] = None
    ) -> str:
        """
        Generate logout URL.
        
        Args:
            post_logout_redirect_uri: Where to redirect after logout
            state: State value
            
        Returns:
            Logout URL
        """
        params = {}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
            
        logout_url = f"{self.server_url}/logout"
        if params:
            logout_url += f"?{urlencode(params)}"
            
        return logout_url


def create_demo_client() -> PQOIDCClient:
    """
    Create a demo OIDC client configured for local testing.
    
    Returns:
        Configured PQOIDCClient instance
    """
    server_url = "http://localhost:5000"
    
    # Create JWT handler with ML-DSA-44 (must match server)
    jwt_handler = PQJWTHandler(algorithm="ML-DSA-44", issuer=server_url)
    
    # Create client
    client = PQOIDCClient(
        client_id="demo-client",
        client_secret="demo-secret",
        server_url=server_url,
        redirect_uri="http://localhost:8080/callback",
        jwt_handler=jwt_handler,
        scope=["openid", "profile", "email"]
    )
    
    return client

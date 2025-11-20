"""
PAuth Exception Hierarchy

This module contains all custom exceptions used by the PAuth library.
"""

from typing import Optional


class PAuthError(Exception):
    """Base exception for all PAuth errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        """
        Initialize PAuthError.

        Args:
            message (str): Error message
            details (dict, optional): Additional error details
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)


class AuthorizationError(PAuthError):
    """
    Raised when authorization fails.

    This includes cases like:
    - User denies access
    - Invalid authorization request
    - Authorization code is invalid or expired
    """

    pass


class TokenError(PAuthError):
    """
    Raised when token operations fail.

    This includes cases like:
    - Token exchange fails
    - Token refresh fails
    - Token is invalid or malformed
    """

    pass


class InvalidStateError(PAuthError):
    """
    Raised when state validation fails.

    This is a security-critical error that indicates a potential CSRF attack
    or session tampering.
    """

    pass


class ProviderError(PAuthError):
    """
    Raised when a provider-specific error occurs.

    This includes cases like:
    - Provider API is down
    - Provider returns an unexpected response
    - Provider-specific validation fails
    """

    def __init__(self, provider: str, message: str, details: Optional[dict] = None):
        """
        Initialize ProviderError.

        Args:
            provider (str): Name of the OAuth provider
            message (str): Error message
            details (dict, optional): Additional error details
        """
        self.provider = provider
        super().__init__(message, details)


class ConfigurationError(PAuthError):
    """
    Raised when configuration is invalid or missing.

    This includes cases like:
    - Missing client_id or client_secret
    - Invalid redirect_uri
    - Missing required configuration parameters
    """

    pass


class TokenStorageError(PAuthError):
    """
    Raised when token storage operations fail.

    This includes cases like:
    - Storage backend is unavailable
    - Storage operations fail (save, retrieve, delete)
    - Storage corruption
    """

    pass


class PKCEError(PAuthError):
    """
    Raised when PKCE (Proof Key for Code Exchange) operations fail.

    This includes cases like:
    - Code verifier generation fails
    - Code challenge generation fails
    - PKCE validation fails
    """

    pass


class ScopeError(PAuthError):
    """
    Raised when scope validation or operations fail.

    This includes cases like:
    - Invalid scope requested
    - Insufficient scopes granted
    - Scope format is invalid
    """

    pass


class UserInfoError(PAuthError):
    """
    Raised when fetching user information fails.

    This includes cases like:
    - User info endpoint is unavailable
    - Invalid access token for user info
    - User info response is malformed
    """

    pass

"""
PKCE (Proof Key for Code Exchange) utilities for OAuth 2.0.

This module provides utilities for implementing PKCE as defined in RFC 7636.
PKCE is an extension to the OAuth 2.0 Authorization Code flow to prevent
authorization code interception attacks.
"""

import base64
import hashlib
import secrets
from typing import Tuple


def generate_code_verifier(length: int = 64) -> str:
    """
    Generate a cryptographically random code verifier.

    The code verifier is a high-entropy cryptographic random string used to
    correlate the authorization request to the token request.

    Args:
        length (int): Length of the code verifier. Must be between 43 and 128.
                     Defaults to 64 for optimal security.

    Returns:
        str: A URL-safe random string to be used as the code verifier.

    Raises:
        ValueError: If length is not between 43 and 128.

    Note:
        Per RFC 7636, the code verifier must be between 43 and 128 characters long.
    """
    if not 43 <= length <= 128:
        raise ValueError("Code verifier length must be between 43 and 128 characters")

    return secrets.token_urlsafe(length)


def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """
    Generate a code challenge from a code verifier.

    Args:
        code_verifier (str): The code verifier string.
        method (str): The transformation method. Either "S256" (SHA-256) or "plain".
                     Defaults to "S256" which is recommended for security.

    Returns:
        str: The code challenge derived from the code verifier.

    Raises:
        ValueError: If an unsupported method is provided.

    Note:
        - S256 method: BASE64URL(SHA256(ASCII(code_verifier)))
        - plain method: code_verifier (not recommended for production)
    """
    if method == "S256":
        verifier_bytes = code_verifier.encode('ascii')
        sha256_hash = hashlib.sha256(verifier_bytes).digest()
        base64_encoded = base64.urlsafe_b64encode(sha256_hash).decode('utf-8')
        # Remove padding as per RFC 7636
        code_challenge = base64_encoded.rstrip('=')
        return code_challenge
    elif method == "plain":
        return code_verifier
    else:
        raise ValueError(f"Unsupported code challenge method: {method}. Use 'S256' or 'plain'.")


def generate_pkce_pair(length: int = 64, method: str = "S256") -> Tuple[str, str]:
    """
    Generate both code verifier and code challenge in one call.

    This is a convenience function that combines generate_code_verifier()
    and generate_code_challenge().

    Args:
        length (int): Length of the code verifier. Must be between 43 and 128.
                     Defaults to 64.
        method (str): The transformation method for the challenge.
                     Either "S256" or "plain". Defaults to "S256".

    Returns:
        Tuple[str, str]: A tuple containing (code_verifier, code_challenge).

    Raises:
        ValueError: If length is invalid or method is unsupported.

    Example:
        ```python
        from src.utils.pkce import generate_pkce_pair

        verifier, challenge = generate_pkce_pair()
        # Use challenge in authorization URL
        # Store verifier for token exchange
        ```
    """
    code_verifier = generate_code_verifier(length)
    code_challenge = generate_code_challenge(code_verifier, method)
    return code_verifier, code_challenge


def validate_code_verifier(code_verifier: str) -> bool:
    """
    Validate that a code verifier meets RFC 7636 requirements.

    Args:
        code_verifier (str): The code verifier to validate.

    Returns:
        bool: True if the code verifier is valid, False otherwise.

    Note:
        A valid code verifier must:
        - Be between 43 and 128 characters long
        - Contain only unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    """
    if not 43 <= len(code_verifier) <= 128:
        return False

    # Check for valid unreserved characters
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    return all(c in valid_chars for c in code_verifier)

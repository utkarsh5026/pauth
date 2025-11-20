"""
OAuth session models for managing temporary flow state.
"""

import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional


@dataclass
class OAuthSession:
    """
    Represents an OAuth authorization session.

    This dataclass contains all temporary data needed for an OAuth flow.
    The user stores this object (in session, cookie, Redis, etc.) and passes
    it back during the callback phase.

    Attributes:
        url (str): The authorization URL to redirect the user to
        state (str): CSRF protection token
        code_verifier (Optional[str]): PKCE code verifier (for PKCE flows)
        code_challenge (Optional[str]): PKCE code challenge (for reference)
        nonce (Optional[str]): OpenID Connect nonce (for ID token validation)
        scopes (Optional[list[str]]): Requested OAuth scopes
        created_at (datetime): When this session was created
        expires_at (datetime): When this session expires
        metadata (dict[str, Any]): Custom metadata (user IP, device info, etc.)
    """

    url: str
    state: str
    code_verifier: Optional[str] = None
    code_challenge: Optional[str] = None
    nonce: Optional[str] = None
    scopes: Optional[list[str]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.utcnow() + timedelta(minutes=10)
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert session to dictionary for storage.

        Returns:
            dict: Serializable dictionary representation

        Example:
            ```python
            oauth_session = client.get_authorization_url()
            session['oauth'] = oauth_session.to_dict()
            ```
        """
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        return {k: v for k, v in data.items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OAuthSession":
        """
        Restore session from dictionary.

        Args:
            data: Dictionary representation from to_dict()

        Returns:
            OAuthSession: Restored session object

        Example:
            ```python
            oauth_data = session.get('oauth')
            oauth_session = OAuthSession.from_dict(oauth_data)
            ```
        """
        # Convert ISO format strings back to datetime
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if isinstance(data.get("expires_at"), str):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])

        return cls(**data)

    def is_expired(self) -> bool:
        """
        Check if the session has expired.

        Returns:
            bool: True if expired, False otherwise

        Example:
            ```python
            if oauth_session.is_expired():
                raise AuthorizationError("OAuth session expired")
            ```
        """
        return datetime.utcnow() > self.expires_at

    def validate_state(self, received_state: str) -> bool:
        """
        Validate the received state against the stored state.

        Args:
            received_state: State parameter from OAuth callback

        Returns:
            bool: True if states match

        Raises:
            ValueError: If state doesn't match (CSRF protection)

        Example:
            ```python
            oauth_session.validate_state(request.args['state'])
            ```
        """
        if not secrets.compare_digest(self.state, received_state):
            raise ValueError("State mismatch - possible CSRF attack detected")
        return True

    def __repr__(self) -> str:
        """String representation (hides sensitive data)."""
        return (
            f"OAuthSession(url='{self.url[:50]}...', "
            f"state='***', scopes={self.scopes}, "
            f"expires_at={self.expires_at.isoformat()})"
        )

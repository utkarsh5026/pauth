from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional


@dataclass
class TokenResponse:
    """
    Represents an OAuth 2.0 token response.

    Attributes:
        access_token (str): The access token issued by the authorization server
        token_type (str): The type of token (usually "Bearer")
        expires_in (int, optional): Lifetime in seconds of the access token
        refresh_token (str, optional): Token used to obtain new access tokens
        scope (str, optional): Space-separated list of granted scopes
        id_token (str, optional): OpenID Connect ID token
        raw_response (dict): Raw response from the token endpoint
        issued_at (datetime): Timestamp when the token was issued
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None
    raw_response: Dict[str, Any] = field(default_factory=dict)
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def expires_at(self) -> Optional[datetime]:
        """
        Calculate when the token expires.

        Returns:
            datetime: Expiration timestamp, or None if no expiry information
        """
        if self.expires_in is not None:
            return self.issued_at + timedelta(seconds=self.expires_in)
        return None

    @property
    def is_expired(self) -> bool:
        """
        Check if the token has expired.

        Returns:
            bool: True if expired, False otherwise
        """
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def scopes(self) -> list[str]:
        """
        Get list of scopes from the scope string.

        Returns:
            list[str]: List of scopes
        """
        if self.scope:
            return self.scope.split()
        return []

    def to_dict(self) -> dict:
        """
        Convert token response to dictionary.

        Returns:
            dict: Dictionary representation of the token
        """
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
            "id_token": self.id_token,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenResponse":
        """
        Create TokenResponse from dictionary.

        Args:
            data (dict): Dictionary containing token data

        Returns:
            TokenResponse: Token response object
        """
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
            raw_response=data,
        )

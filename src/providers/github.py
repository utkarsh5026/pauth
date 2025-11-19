"""
GitHub OAuth 2.0 provider with unified sync/async support.
"""

import base64
from typing import Optional, Any
from .base import BaseProvider
from src.http import HTTPClient, AsyncHTTPClient


class GitHubProviderMixin:
    """
    Mixin class containing GitHub-specific payload preparation methods.

    This class contains pure data preparation logic that's shared between
    sync and async GitHub provider implementations.

    Requires the following attributes from implementing class:
        - client_id: str
        - client_secret: str
        - redirect_uri: str
    """

    client_id: str
    client_secret: str
    redirect_uri: str

    def _build_token_exchange_headers(self) -> dict[str, str]:
        """
        Build headers for token exchange request.

        Returns:
            dict: Headers with Accept header for JSON response
        """
        return {"Accept": "application/json"}

    def _build_token_exchange_payload(self, code: str) -> dict[str, str]:
        """
        Build payload for exchanging authorization code for access token.

        Args:
            code: Authorization code from OAuth callback

        Returns:
            dict: Payload for token exchange request
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

    def _build_auth_headers(self, access_token: str) -> dict[str, str]:
        """
        Build authorization headers with Bearer token.

        Args:
            access_token: OAuth access token

        Returns:
            dict: Headers with Authorization Bearer token
        """
        return {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def _build_revoke_headers(self) -> dict[str, str]:
        """
        Build headers for token revocation request with Basic auth.

        Returns:
            dict: Headers with Basic Authorization
        """
        auth_header = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()

        return {
            "Authorization": f"Basic {auth_header}",
            "Accept": "application/vnd.github.v3+json",
        }

    def _build_revoke_payload(self, token: str) -> dict[str, str]:
        """
        Build payload for token revocation.

        Args:
            token: Token to revoke (access token)

        Returns:
            dict: Payload for revocation request
        """
        return {"access_token": token}


class GitHubProvider(GitHubProviderMixin, BaseProvider):
    """
    GitHub OAuth 2.0 provider with both sync and async methods.

    Note: GitHub does not support token refresh for OAuth apps.
    """

    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = True
    SUPPORTS_PKCE = False

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[list[str]] = None,
        http_client: Optional[HTTPClient] = None,
        async_http_client: Optional[AsyncHTTPClient] = None,
    ):
        """
        Initialize GitHub OAuth provider.

        Args:
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: OAuth scopes (defaults to read:user, user:email)
            http_client: Custom sync HTTP client (optional)
            async_http_client: Custom async HTTP client (optional)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
            http_client=http_client,
            async_http_client=async_http_client,
        )

        self.authorization_endpoint = "https://github.com/login/oauth/authorize"
        self.token_endpoint = "https://github.com/login/oauth/access_token"
        self.revocation_endpoint = (
            f"https://api.github.com/applications/{client_id}/token"
        )
        self.user_info_endpoint = "https://api.github.com/user"

    def _get_default_scopes(self) -> list[str]:
        """Get GitHub's default scopes."""
        return ["read:user", "user:email"]

    # =========================================================================
    # SYNC METHODS
    # =========================================================================

    def exchange_code_for_access_token(self, code: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token (SYNC).

        Args:
            code: Authorization code from GitHub

        Returns:
            dict: Token response with access_token, token_type, etc.
        """
        headers = self._build_token_exchange_headers()
        data = self._build_token_exchange_payload(code)

        return self._make_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to exchange code for access token",
        )

    def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from GitHub (SYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (login, id, email, name, etc.)
        """
        headers = self._build_auth_headers(access_token)

        return self._make_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            headers=headers,
            error_message="Failed to fetch user info",
        )

    def revoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access token (SYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response (usually empty on success)
        """
        headers = self._build_revoke_headers()
        data = self._build_revoke_payload(token)

        result = self._make_request(
            method="DELETE",
            url=self._ensure(self.revocation_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to revoke token",
        )

        # GitHub returns empty response on success
        return {"success": True, **result}

    async def aexchange_code_for_access_token(self, code: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token (ASYNC).

        Args:
            code: Authorization code from GitHub

        Returns:
            dict: Token response with access_token, token_type, etc.
        """
        headers = self._build_token_exchange_headers()
        data = self._build_token_exchange_payload(code)

        return await self._amake_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to exchange code for access token",
        )

    async def aget_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from GitHub (ASYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (login, id, email, name, etc.)
        """
        headers = self._build_auth_headers(access_token)

        return await self._amake_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            headers=headers,
            error_message="Failed to fetch user info",
        )

    async def arevoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access token (ASYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response (usually empty on success)
        """
        headers = self._build_revoke_headers()
        data = self._build_revoke_payload(token)

        result = await self._amake_request(
            method="DELETE",
            url=self._ensure(self.revocation_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to revoke token",
        )

        # GitHub returns empty response on success
        return {"success": True, **result}

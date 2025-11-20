"""
Discord OAuth 2.0 provider with unified sync/async support.
"""

from typing import Any, Optional

from src.http import AsyncHTTPClient, HTTPClient

from .base import BaseProvider


class DiscordProviderMixin:
    """
    Mixin class containing Discord-specific payload preparation methods.

    This class contains pure data preparation logic that's shared between
    sync and async Discord provider implementations.

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
            dict: Headers with Content-Type
        """
        return {"Content-Type": "application/x-www-form-urlencoded"}

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
            "grant_type": "authorization_code",
        }

    def _build_auth_headers(self, access_token: str) -> dict[str, str]:
        """
        Build authorization headers with Bearer token.

        Args:
            access_token: OAuth access token

        Returns:
            dict: Headers with Authorization Bearer token
        """
        return {"Authorization": f"Bearer {access_token}"}

    def _build_refresh_token_headers(self) -> dict[str, str]:
        """
        Build headers for token refresh request.

        Returns:
            dict: Headers with Content-Type
        """
        return {"Content-Type": "application/x-www-form-urlencoded"}

    def _build_refresh_token_payload(self, refresh_token: str) -> dict[str, str]:
        """
        Build payload for refreshing access token.

        Args:
            refresh_token: Refresh token from previous token response

        Returns:
            dict: Payload for token refresh request
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

    def _build_revoke_headers(self) -> dict[str, str]:
        """
        Build headers for token revocation request.

        Returns:
            dict: Headers with Content-Type
        """
        return {"Content-Type": "application/x-www-form-urlencoded"}

    def _build_revoke_payload(self, token: str) -> dict[str, str]:
        """
        Build payload for token revocation.

        Args:
            token: Token to revoke (access or refresh token)

        Returns:
            dict: Payload for revocation request
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "token": token,
        }


class DiscordProvider(DiscordProviderMixin, BaseProvider):
    """
    Discord OAuth 2.0 provider with both sync and async methods.
    """

    SUPPORTS_REFRESH = True
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
        Initialize Discord OAuth provider.

        Args:
            client_id: Discord OAuth client ID
            client_secret: Discord OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: OAuth scopes (defaults to identify, email)
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

        # Set Discord OAuth endpoints
        self.authorization_endpoint = "https://discord.com/api/oauth2/authorize"
        self.token_endpoint = "https://discord.com/api/oauth2/token"
        self.revocation_endpoint = "https://discord.com/api/oauth2/token/revoke"
        self.user_info_endpoint = "https://discord.com/api/users/@me"

    def _get_default_scopes(self) -> list[str]:
        """Get Discord's default scopes."""
        return ["identify", "email"]

    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (SYNC).

        Args:
            code: Authorization code from Discord
            code_verifier: Not used (Discord doesn't support PKCE)

        Returns:
            dict: Token response with access_token, refresh_token, etc.
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
        Fetch user information from Discord (SYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, username, email, avatar, etc.)
        """
        headers = self._build_auth_headers(access_token)

        return self._make_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            headers=headers,
            error_message="Failed to fetch user info",
        )

    def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh an access token (SYNC).

        Args:
            refresh_token: Refresh token from previous token response

        Returns:
            dict: New token response
        """
        headers = self._build_refresh_token_headers()
        data = self._build_refresh_token_payload(refresh_token)

        return self._make_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to refresh token",
        )

    def revoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access or refresh token (SYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response (usually empty on success)
        """
        headers = self._build_revoke_headers()
        data = self._build_revoke_payload(token)

        result = self._make_request(
            method="POST",
            url=self._ensure(self.revocation_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to revoke token",
        )

        # Discord returns empty response on success
        return {"success": True, **result}

    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (ASYNC).

        Args:
            code: Authorization code from Discord
            code_verifier: Not used (Discord doesn't support PKCE)

        Returns:
            dict: Token response with access_token, refresh_token, etc.
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
        Fetch user information from Discord (ASYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, username, email, avatar, etc.)
        """
        headers = self._build_auth_headers(access_token)

        return await self._amake_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            headers=headers,
            error_message="Failed to fetch user info",
        )

    async def arefresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh an access token (ASYNC).

        Args:
            refresh_token: Refresh token from previous token response

        Returns:
            dict: New token response
        """
        headers = self._build_refresh_token_headers()
        data = self._build_refresh_token_payload(refresh_token)

        return await self._amake_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to refresh token",
        )

    async def arevoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access or refresh token (ASYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response (usually empty on success)
        """
        headers = self._build_revoke_headers()
        data = self._build_revoke_payload(token)

        result = await self._amake_request(
            method="POST",
            url=self._ensure(self.revocation_endpoint),
            headers=headers,
            data=data,
            error_message="Failed to revoke token",
        )

        # Discord returns empty response on success
        return {"success": True, **result}

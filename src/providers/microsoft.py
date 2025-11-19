"""
Microsoft OAuth 2.0 provider with unified sync/async support.
"""

from typing import Optional, Any
from .base import BaseProvider
from src.http import HTTPClient, AsyncHTTPClient


class MicrosoftProviderMixin:
    """
    Mixin class containing Microsoft-specific payload preparation methods.

    This class contains pure data preparation logic that's shared between
    sync and async Microsoft provider implementations.

    Requires the following attributes from implementing class:
        - client_id: str
        - client_secret: str
        - redirect_uri: str
    """

    # Type hints for required attributes
    client_id: str
    client_secret: str
    redirect_uri: str

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


class MicrosoftProvider(MicrosoftProviderMixin, BaseProvider):
    """
    Unified Microsoft OAuth 2.0 provider with both sync and async methods.

    Supports both synchronous and asynchronous usage:
    - Sync methods: exchange_code_for_access_token(), get_user_info(), etc.
    - Async methods: aexchange_code_for_access_token(), aget_user_info(), etc.

    Example (Sync):
        ```python
        from pauth.providers.microsoft_v2 import MicrosoftProviderStateless

        provider = MicrosoftProviderStateless(
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="http://localhost:5000/callback",
            tenant="common"  # or specific tenant ID
        )

        # Sync usage
        tokens = provider.exchange_code_for_access_token(code)
        user_info = provider.get_user_info(tokens['access_token'])
        ```

    Example (Async):
        ```python
        from pauth.providers.microsoft_v2 import MicrosoftProviderStateless

        provider = MicrosoftProviderStateless(
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="http://localhost:5000/callback",
            tenant="common"
        )

        # Async usage
        tokens = await provider.aexchange_code_for_access_token(code)
        user_info = await provider.aget_user_info(tokens['access_token'])
        ```
    """

    SUPPORTS_REFRESH = True
    SUPPORTS_REVOCATION = False
    SUPPORTS_PKCE = False

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[list[str]] = None,
        tenant: str = "common",
        http_client: Optional[HTTPClient] = None,
        async_http_client: Optional[AsyncHTTPClient] = None,
    ):
        """
        Initialize Microsoft OAuth provider.

        Args:
            client_id: Microsoft OAuth client ID
            client_secret: Microsoft OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: OAuth scopes (defaults to openid, email, profile)
            tenant: Azure AD tenant ID (defaults to 'common' for multi-tenant)
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

        # Set Microsoft OAuth endpoints with tenant
        self.tenant = tenant
        self.authorization_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        )
        self.token_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )
        self.revocation_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout"
        )
        self.user_info_endpoint = "https://graph.microsoft.com/v1.0/me"

    def _get_default_scopes(self) -> list[str]:
        """Get Microsoft's default scopes."""
        return ["openid", "email", "profile"]

    # =========================================================================
    # SYNC METHODS
    # =========================================================================

    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (SYNC).

        Args:
            code: Authorization code from Microsoft
            code_verifier: Not used (Microsoft doesn't require PKCE for web apps)

        Returns:
            dict: Token response with access_token, refresh_token, etc.
        """
        data = self._build_token_exchange_payload(code)

        return self._make_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            data=data,
            error_message="Failed to exchange code for access token",
        )

    def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from Microsoft Graph (SYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, displayName, mail, etc.)
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
        data = self._build_refresh_token_payload(refresh_token)

        return self._make_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            data=data,
            error_message="Failed to refresh token",
        )

    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (ASYNC).

        Args:
            code: Authorization code from Microsoft
            code_verifier: Not used (Microsoft doesn't require PKCE for web apps)

        Returns:
            dict: Token response with access_token, refresh_token, etc.
        """
        data = self._build_token_exchange_payload(code)

        return await self._amake_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            data=data,
            error_message="Failed to exchange code for access token",
        )

    async def aget_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from Microsoft Graph (ASYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, displayName, mail, etc.)
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
        data = self._build_refresh_token_payload(refresh_token)

        return await self._amake_request(
            method="POST",
            url=self._ensure(self.token_endpoint),
            data=data,
            error_message="Failed to refresh token",
        )

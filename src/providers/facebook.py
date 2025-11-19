"""
Facebook OAuth 2.0 provider with unified sync/async support.
"""

from typing import Optional, Any
from .base import BaseProvider
from src.http import HTTPClient, AsyncHTTPClient


class FacebookProviderMixin:
    """
    Mixin class containing Facebook-specific payload preparation methods.

    This class contains pure data preparation logic that's shared between
    sync and async Facebook provider implementations.

    Requires the following attributes from implementing class:
        - client_id: str
        - client_secret: str
        - redirect_uri: str
    """

    client_id: str
    client_secret: str
    redirect_uri: str

    def _build_token_exchange_params(self, code: str) -> dict[str, str]:
        """
        Build query parameters for exchanging authorization code for access token.

        Args:
            code: Authorization code from OAuth callback

        Returns:
            dict: Query parameters for token exchange request
        """
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

    def _build_user_info_params(self, access_token: str) -> dict[str, str]:
        """
        Build query parameters for fetching user info.

        Args:
            access_token: OAuth access token

        Returns:
            dict: Query parameters with access token and fields
        """
        return {
            "access_token": access_token,
            "fields": "id,name,email,picture,first_name,last_name",
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


class FacebookProvider(FacebookProviderMixin, BaseProvider):
    """
    Facebook OAuth 2.0 provider with both sync and async methods

    Note: Facebook does not support token refresh for standard OAuth.
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
        Initialize Facebook OAuth provider.

        Args:
            client_id: Facebook OAuth client ID
            client_secret: Facebook OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: OAuth scopes (defaults to email, public_profile)
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

        # Set Facebook OAuth endpoints
        self.authorization_endpoint = "https://www.facebook.com/v20.0/dialog/oauth"
        self.token_endpoint = "https://graph.facebook.com/v20.0/oauth/access_token"
        self.revocation_endpoint = "https://graph.facebook.com/me/permissions"
        self.user_info_endpoint = "https://graph.facebook.com/me"

    def _get_default_scopes(self) -> list[str]:
        """Get Facebook's default scopes."""
        return ["email", "public_profile"]

    # =========================================================================
    # SYNC METHODS
    # =========================================================================

    def exchange_code_for_access_token(self, code: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token (SYNC).

        Args:
            code: Authorization code from Facebook

        Returns:
            dict: Token response with access_token, token_type, expires_in, etc.
        """
        params = self._build_token_exchange_params(code)

        return self._make_request(
            method="GET",
            url=self._ensure(self.token_endpoint),
            params=params,
            error_message="Unable to exchange code for access token",
        )

    def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from Facebook (SYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, name, email, picture, etc.)
        """
        params = self._build_user_info_params(access_token)

        return self._make_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            params=params,
            error_message="Failed to fetch user info",
        )

    def revoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access token (SYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response
        """
        data = self._build_revoke_payload(token)

        result = self._make_request(
            method="DELETE",
            url=self._ensure(self.revocation_endpoint),
            data=data,
            error_message="Failed to revoke token",
        )

        return {"success": True, **result}

    async def aexchange_code_for_access_token(self, code: str) -> dict[str, Any]:
        """
        Exchange authorization code for access token (ASYNC).

        Args:
            code: Authorization code from Facebook

        Returns:
            dict: Token response with access_token, token_type, expires_in, etc.
        """
        params = self._build_token_exchange_params(code)

        return await self._amake_request(
            method="GET",
            url=self._ensure(self.token_endpoint),
            params=params,
            error_message="Unable to exchange code for access token",
        )

    async def aget_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information from Facebook (ASYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information (id, name, email, picture, etc.)
        """
        params = self._build_user_info_params(access_token)

        return await self._amake_request(
            method="GET",
            url=self._ensure(self.user_info_endpoint),
            params=params,
            error_message="Failed to fetch user info",
        )

    async def arevoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access token (ASYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response
        """
        data = self._build_revoke_payload(token)

        result = await self._amake_request(
            method="DELETE",
            url=self._ensure(self.revocation_endpoint),
            data=data,
            error_message="Failed to revoke token",
        )

        return {"success": True, **result}

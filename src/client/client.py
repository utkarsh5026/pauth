"""
Main OAuth2 client implementation.
"""

from typing import Optional, Union
from src.models import Providers, TokenResponse, UserInfo
from src.providers import BaseProvider
from src.storage import BaseTokenStorage, MemoryTokenStorage
from exceptions import ConfigurationError, TokenError, AuthorizationError


class OAuth2Client:
    """
    Main OAuth 2.0 client for handling authentication flows.

    This client provides a high-level interface for OAuth 2.0 authentication
    with support for multiple providers, PKCE, and token management.

    Example:
        ```python
        from pauth import OAuth2Client, Providers

        client = OAuth2Client(
            provider=Providers.GOOGLE,
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="https://your-app.com/callback"
        )

        # Get authorization URL
        auth_url = client.get_authorization_url(scope=["openid", "email"])

        # Exchange code for tokens
        tokens = client.exchange_code(code="auth_code", state="state_value")

        # Get user info
        user_info = client.get_user_info(tokens.access_token)
        ```
    """

    def __init__(
        self,
        provider: Union[Providers, BaseProvider, str],
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[list] = None,
        tok_store: Optional[BaseTokenStorage] = None,
    ) -> None:

        if not client_id:
            raise ConfigurationError("client_id is required")

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or []

        self.tok_store = tok_store or MemoryTokenStorage()
        self.provider = self.__resolve_provider(provider)

    def __resolve_provider(
        self, provider: Union[Providers, BaseProvider, str]
    ) -> BaseProvider:
        if isinstance(provider, BaseProvider):
            return provider

        if isinstance(provider, Providers):
            provider_class = provider.get_provider_class()
            return provider_class(
                client_id=self.client_id,
                client_secret=self.client_secret,
                redirect_uri=self.redirect_uri,
                scopes=self.scopes,
            )

        if isinstance(provider, str):
            try:
                provider_enum = Providers(provider.lower())
                return self.__resolve_provider(provider_enum)
            except ValueError:
                raise ConfigurationError(f"Unsupported provider: {provider}")

        raise ConfigurationError("Invalid provider type")

    def get_authorization_url(self, scope: Optional[list] = None, **kwargs) -> str:
        if scope:
            self.provider.scopes = scope
        return self.provider.prepare_auth_url(additional_params=kwargs)

    def exchange_code(self, code: str) -> TokenResponse:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code (str): The authorization code received from the OAuth provider.

        Returns:
            TokenResponse: An object containing access and refresh tokens.
        """
        try:
            tok = self.provider.exchange_code_for_access_token(code)
            if not tok:
                raise TokenError("Failed to obtain tokens from provider")
            return TokenResponse.from_dict(tok)
        except Exception as e:
            if isinstance(e, TokenError):
                raise
            raise AuthorizationError("Error exchanging code for tokens") from e

    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Retrieve user information using the access token.

        Args:
            access_token (str): The access token.

        Returns:
            dict: A dictionary containing user information.
        """
        try:
            uif = self.provider.get_user_info(access_token)
            if not uif:
                raise AuthorizationError("Failed to retrieve user information")
            return UserInfo.from_dict(uif)
        except Exception as e:
            raise AuthorizationError("Error retrieving user information") from e

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh the access token using the refresh token.

        Args:
            refresh_token (str): The refresh token.

        Returns:
            TokenResponse: An object containing new access and refresh tokens.

        Raises:
            ConfigurationError: If the provider does not support token refresh.
            TokenError: If token refresh fails.
            AuthorizationError: If an error occurs during refresh.
        """
        if not self.provider.SUPPORTS_REFRESH:
            raise ConfigurationError(
                f"{self.provider.__class__.__name__} does not support token refresh"
            )

        try:
            tok = self.provider.refresh_token(refresh_token)
            if not tok:
                raise TokenError("Failed to refresh tokens from provider")
            return TokenResponse.from_dict(tok)
        except Exception as e:
            if isinstance(e, TokenError):
                raise
            raise AuthorizationError("Error refreshing tokens") from e

    def revoke_token(self, token: str) -> bool:
        """
        Revoke the given access or refresh token.

        Args:
            token (str): The token to be revoked.

        Returns:
            bool: True if revocation was successful, False otherwise.

        Raises:
            ConfigurationError: If the provider does not support token revocation.
            AuthorizationError: If an error occurs during revocation.
        """
        if not self.provider.SUPPORTS_REVOCATION:
            raise ConfigurationError(
                f"{self.provider.__class__.__name__} does not support token revocation"
            )

        try:
            resp = self.provider.revoke_token(token)
            return resp.get("success", False)
        except Exception as e:
            raise AuthorizationError("Error revoking token") from e

"""
Main OAuth2 client implementation.
"""

from typing import Optional, Union
from src.models import Providers, TokenResponse
from src.providers import BaseProvider
from src.storage import BaseTokenStorage, MemoryTokenStorage
from exceptions import ConfigurationError


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
        self.provider = self._resolve_provider(provider)

    def _resolve_provider(
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
                return self._resolve_provider(provider_enum)
            except ValueError:
                raise ConfigurationError(f"Unsupported provider: {provider}")

        raise ConfigurationError("Invalid provider type")

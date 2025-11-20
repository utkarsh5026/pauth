"""
Main OAuth2 client implementation.
"""

from typing import Optional, Union

from src.exceptions import AuthorizationError, ConfigurationError, TokenError
from src.http import AsyncHTTPClient, HTTPClient
from src.models import OAuthSession, Providers, TokenResponse, UserInfo
from src.providers import BaseProvider


class OAuth2Client:
    """
    Main OAuth 2.0 client for handling authentication flows.

    This client provides a high-level interface for OAuth 2.0 authentication
    with support for multiple providers, PKCE, and token management.

    Example:
        ```python
        from pauth import OAuth2Client, Providers

        # Standard OAuth flow (Google, GitHub, etc.)
        client = OAuth2Client(
            provider=Providers.GOOGLE,
            client_id="your_client_id",
            client_secret="your_client_secret",
            redirect_uri="https://your-app.com/callback"
        )

        # Get authorization URL
        auth_url = client.get_authorization_url(scope=["openid", "email"])

        # Exchange code for tokens
        tokens = client.exchange_code(code="auth_code")

        # Get user info
        user_info = client.get_user_info(tokens.access_token)

        # Check provider capabilities before using optional features
        if client.supports_refresh():
            new_tokens = client.refresh_token(tokens.refresh_token)

        if client.supports_revocation():
            client.revoke_token(tokens.access_token)

        # PKCE flow (Twitter) - code_verifier is automatically managed
        twitter_client = OAuth2Client(provider=Providers.TWITTER, ...)
        auth_url = twitter_client.get_authorization_url()  # PKCE params added automatically
        tokens = twitter_client.exchange_code(code="auth_code")  # Uses stored code_verifier
        ```
    """

    def __init__(
        self,
        provider: Union[Providers, BaseProvider, str],
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[list] = None,
        http_client: Optional[HTTPClient] = None,
        async_http_client: Optional[AsyncHTTPClient] = None,
    ) -> None:

        if not client_id:
            raise ConfigurationError("client_id is required")

        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or []
        self.http_client = http_client
        self.async_http_client = async_http_client
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
                http_client=self.http_client,
                async_http_client=self.async_http_client,
            )

        if isinstance(provider, str):
            try:
                provider_enum = Providers(provider.lower())
                return self.__resolve_provider(provider_enum)
            except ValueError:
                raise ConfigurationError(f"Unsupported provider: {provider}")

    def supports_refresh(self) -> bool:
        """
        Check if the current provider supports token refresh.

        Returns:
            bool: True if token refresh is supported, False otherwise.
        """
        return self.provider.SUPPORTS_REFRESH

    def supports_revocation(self) -> bool:
        """
        Check if the current provider supports token revocation.

        Returns:
            bool: True if token revocation is supported, False otherwise.
        """
        return self.provider.SUPPORTS_REVOCATION

    def supports_pkce(self) -> bool:
        """
        Check if the current provider supports PKCE flow.

        Returns:
            bool: True if PKCE is supported, False otherwise.
        """
        return self.provider.SUPPORTS_PKCE

    def get_authorization_session(
        self,
        scopes: Optional[list] = None,
        nonce: Optional[str] = None,
        metadata: Optional[dict] = None,
        **additional_params,
    ) -> OAuthSession:
        """
        Get an OAuth authorization session with all required parameters.

        This is the recommended method for generating authorization URLs as it
        properly manages state, PKCE parameters, and session data.

        Args:
            scopes: Scopes to request (uses default if None)
            nonce: Optional nonce for OpenID Connect
            metadata: Optional custom metadata to store in session
            **additional_params: Additional query parameters for authorization URL

        Returns:
            OAuthSession: Session object with url, state, PKCE params, etc.

        Example:
            ```python
            # Get authorization session
            session = client.get_authorization_session(
                scopes=["email", "profile"],
                metadata={"user_ip": request.remote_addr}
            )

            # Store in HTTP session, Redis, database, etc.
            http_session['oauth'] = session.to_dict()

            # Redirect user
            return redirect(session.url)
            ```
        """
        return self.provider.get_authorization_session(
            scopes=scopes or self.scopes,
            additional_params=additional_params or None,
            nonce=nonce,
            metadata=metadata,
        )

    def exchange_code(
        self,
        code: str,
        session: Optional[OAuthSession] = None,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            code: Authorization code from OAuth callback
            session: OAuthSession object (provides code_verifier for PKCE)
            code_verifier: Explicit PKCE code verifier (overrides session)

        Returns:
            TokenResponse: Object containing access_token, refresh_token, etc.

        Raises:
            ConfigurationError: If PKCE is required but code_verifier not provided
            TokenError: If token exchange fails
            AuthorizationError: If an error occurs during exchange
        """
        try:
            final_code_verifier = code_verifier
            if final_code_verifier is None and session is not None:
                final_code_verifier = session.code_verifier

            if self.provider.SUPPORTS_PKCE:
                if final_code_verifier is None:
                    raise ConfigurationError(
                        f"{self.provider.__class__.__name__} requires PKCE. "
                        f"Please provide code_verifier or session with code_verifier."
                    )

                tok = self.provider.exchange_code_for_access_token(
                    code=code, code_verifier=final_code_verifier
                )
            else:
                tok = self.provider.exchange_code_for_access_token(code)

            if not tok:
                raise TokenError("Failed to obtain tokens from provider")

            return TokenResponse.from_dict(tok)

        except Exception as e:
            if isinstance(e, (TokenError, ConfigurationError)):
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

    async def aexchange_code(
        self,
        code: str,
        session: Optional[OAuthSession] = None,
        code_verifier: Optional[str] = None,
    ) -> TokenResponse:
        """
        Exchange authorization code for access and refresh tokens (ASYNC).

        Args:
            code: Authorization code from OAuth callback
            session: OAuthSession object (provides code_verifier for PKCE)
            code_verifier: Explicit PKCE code verifier (overrides session)

        Returns:
            TokenResponse: Object containing access_token, refresh_token, etc.

        Raises:
            ConfigurationError: If PKCE is required but code_verifier not provided
            TokenError: If token exchange fails
            AuthorizationError: If an error occurs during exchange
        """
        try:
            final_code_verifier = code_verifier
            if final_code_verifier is None and session is not None:
                final_code_verifier = session.code_verifier

            if self.provider.SUPPORTS_PKCE:
                if final_code_verifier is None:
                    raise ConfigurationError(
                        f"{self.provider.__class__.__name__} requires PKCE. "
                        f"Please provide code_verifier or session with code_verifier."
                    )

                tok = await self.provider.aexchange_code_for_access_token(
                    code=code, code_verifier=final_code_verifier
                )
            else:
                tok = await self.provider.aexchange_code_for_access_token(code)

            if not tok:
                raise TokenError("Failed to obtain tokens from provider")

            return TokenResponse.from_dict(tok)

        except Exception as e:
            if isinstance(e, (TokenError, ConfigurationError)):
                raise
            raise AuthorizationError("Error exchanging code for tokens") from e

    async def aget_user_info(self, access_token: str) -> UserInfo:
        """
        Retrieve user information using the access token (ASYNC).

        Args:
            access_token (str): The access token.

        Returns:
            UserInfo: An object containing user information.

        Raises:
            AuthorizationError: If user info retrieval fails.
        """
        try:
            uif = await self.provider.aget_user_info(access_token)
            if not uif:
                raise AuthorizationError("Failed to retrieve user information")
            return UserInfo.from_dict(uif)
        except Exception as e:
            raise AuthorizationError("Error retrieving user information") from e

    async def arefresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh the access token using the refresh token (ASYNC).

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
            tok = await self.provider.arefresh_token(refresh_token)
            if not tok:
                raise TokenError("Failed to refresh tokens from provider")
            return TokenResponse.from_dict(tok)
        except Exception as e:
            if isinstance(e, TokenError):
                raise
            raise AuthorizationError("Error refreshing tokens") from e

    async def arevoke_token(self, token: str) -> bool:
        """
        Revoke the given access or refresh token (ASYNC).

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
            resp = await self.provider.arevoke_token(token)
            return resp.get("success", False)
        except Exception as e:
            raise AuthorizationError("Error revoking token") from e

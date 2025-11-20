"""
Comprehensive tests for OAuth2Client with mock providers.
"""

from typing import Any, Optional
from unittest.mock import AsyncMock, Mock

import pytest

from src.client import OAuth2Client
from src.exceptions import AuthorizationError, ConfigurationError, TokenError
from src.http import AsyncHTTPClient, HTTPClient, HTTPResponse
from src.models import OAuthSession, TokenResponse, UserInfo
from src.providers.base import BaseProvider


# Mock Provider Classes for Testing
class MockProvider(BaseProvider):
    """A basic mock provider without refresh/revocation/PKCE support."""

    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = False
    SUPPORTS_PKCE = False

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes=None,
        http_client: Optional[HTTPClient] = None,
        async_http_client: Optional[AsyncHTTPClient] = None,
    ):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            http_client,
            async_http_client,
        )
        self.authorization_endpoint = "https://mock.provider.com/oauth/authorize"
        self.token_endpoint = "https://mock.provider.com/oauth/token"
        self.user_info_endpoint = "https://mock.provider.com/oauth/userinfo"

    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Mock token exchange (SYNC)."""
        return {
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "read write",
        }

    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Mock token exchange (ASYNC)."""
        return {
            "access_token": "async_mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "async_mock_refresh_token",
            "scope": "read write",
        }

    def get_user_info(self, access_token: str) -> dict:
        """Mock user info retrieval (SYNC)."""
        return {
            "id": "12345",
            "email": "user@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }

    async def aget_user_info(self, access_token: str) -> dict:
        """Mock user info retrieval (ASYNC)."""
        return {
            "id": "async_12345",
            "email": "async_user@example.com",
            "name": "Async Test User",
            "given_name": "Async Test",
            "family_name": "User",
            "picture": "https://example.com/async_photo.jpg",
            "verified_email": True,
        }


class MockProviderWithRefresh(MockProvider):
    """Mock provider with refresh token support."""

    SUPPORTS_REFRESH = True

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes=None,
        http_client: Optional[HTTPClient] = None,
        async_http_client: Optional[AsyncHTTPClient] = None,
    ):
        super().__init__(
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            http_client,
            async_http_client,
        )
        self.revocation_endpoint = "https://mock.provider.com/oauth/revoke"

    def refresh_token(self, refresh_token: str) -> dict:
        """Mock token refresh (SYNC)."""
        return {
            "access_token": "new_mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_mock_refresh_token",
        }

    async def arefresh_token(self, refresh_token: str) -> dict:
        """Mock token refresh (ASYNC)."""
        return {
            "access_token": "async_new_mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "async_new_mock_refresh_token",
        }


class MockProviderWithRevocation(MockProviderWithRefresh):
    """Mock provider with revocation support."""

    SUPPORTS_REVOCATION = True

    def revoke_token(self, token: str) -> dict:
        """Mock token revocation (SYNC)."""
        return {"success": True}

    async def arevoke_token(self, token: str) -> dict:
        """Mock token revocation (ASYNC)."""
        return {"success": True}


class MockProviderWithPKCE(MockProvider):
    """Mock provider with PKCE support."""

    SUPPORTS_PKCE = True

    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Mock token exchange with PKCE (SYNC)."""
        if code_verifier is None:
            raise ConfigurationError("code_verifier required for PKCE")
        return {
            "access_token": "pkce_access_token",
            "token_type": "Bearer",
            "expires_in": 7200,
            "refresh_token": "pkce_refresh_token",
        }

    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Mock token exchange with PKCE (ASYNC)."""
        if code_verifier is None:
            raise ConfigurationError("code_verifier required for PKCE")
        return {
            "access_token": "async_pkce_access_token",
            "token_type": "Bearer",
            "expires_in": 7200,
            "refresh_token": "async_pkce_refresh_token",
        }


class MockProviderWithErrors(MockProvider):
    """Mock provider that simulates various error scenarios."""

    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Simulate token exchange failure (SYNC)."""
        if code == "invalid_code":
            raise Exception("Invalid authorization code")
        if code == "empty_response":
            return {}
        return super().exchange_code_for_access_token(code, code_verifier)

    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
        """Simulate token exchange failure (ASYNC)."""
        if code == "invalid_code":
            raise Exception("Invalid authorization code")
        if code == "empty_response":
            return {}
        return await super().aexchange_code_for_access_token(code, code_verifier)

    def get_user_info(self, access_token: str) -> dict:
        """Simulate user info retrieval failure (SYNC)."""
        if access_token == "invalid_token":
            raise Exception("Invalid access token")
        if access_token == "empty_response":
            return {}
        return super().get_user_info(access_token)

    async def aget_user_info(self, access_token: str) -> dict:
        """Simulate user info retrieval failure (ASYNC)."""
        if access_token == "invalid_token":
            raise Exception("Invalid access token")
        if access_token == "empty_response":
            return {}
        return await super().aget_user_info(access_token)


# Mock HTTP Clients
class MockHTTPClient(HTTPClient):
    """Mock sync HTTP client."""

    def request(
        self,
        method: str,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        """Mock request method."""
        response = Mock(spec=HTTPResponse)
        response.status_code = 200
        response.json.return_value = {"mock": "response"}
        return response

    def close(self):
        """Mock close method."""
        pass


class MockAsyncHTTPClient(AsyncHTTPClient):
    """Mock async HTTP client."""

    async def request(
        self,
        method: str,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        """Mock async request method."""
        response = Mock(spec=HTTPResponse)
        response.status_code = 200
        response.json.return_value = {"mock": "async_response"}
        return response

    async def close(self):
        """Mock close method."""
        pass


# Fixtures
@pytest.fixture
def mock_http_client():
    """Create a mock sync HTTP client."""
    return MockHTTPClient()


@pytest.fixture
def mock_async_http_client():
    """Create a mock async HTTP client."""
    return MockAsyncHTTPClient()


@pytest.fixture
def mock_provider():
    """Create a basic mock provider instance."""
    return MockProvider(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
        scopes=["read", "write"],
    )


@pytest.fixture
def mock_provider_with_refresh():
    """Create a mock provider with refresh support."""
    return MockProviderWithRefresh(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def mock_provider_with_revocation():
    """Create a mock provider with revocation support."""
    return MockProviderWithRevocation(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def mock_provider_with_pkce():
    """Create a mock provider with PKCE support."""
    return MockProviderWithPKCE(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def oauth_client(mock_provider):
    """Create an OAuth2Client with basic mock provider."""
    return OAuth2Client(
        provider=mock_provider,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def oauth_client_with_refresh(mock_provider_with_refresh):
    """Create an OAuth2Client with refresh support."""
    return OAuth2Client(
        provider=mock_provider_with_refresh,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def oauth_client_with_revocation(mock_provider_with_revocation):
    """Create an OAuth2Client with revocation support."""
    return OAuth2Client(
        provider=mock_provider_with_revocation,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


@pytest.fixture
def oauth_client_with_pkce(mock_provider_with_pkce):
    """Create an OAuth2Client with PKCE support."""
    return OAuth2Client(
        provider=mock_provider_with_pkce,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
    )


# Test Classes
class TestOAuth2ClientInitialization:
    """Test OAuth2Client initialization and configuration."""

    def test_init_with_provider_instance(self, mock_provider):
        """Test initialization with a provider instance."""
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        assert client.client_id == "test_client_id"
        assert client.client_secret == "test_client_secret"
        assert client.redirect_uri == "https://example.com/callback"
        assert client.provider == mock_provider

    def test_init_with_http_clients(
        self, mock_provider, mock_http_client, mock_async_http_client
    ):
        """Test initialization with custom HTTP clients."""
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            http_client=mock_http_client,
            async_http_client=mock_async_http_client,
        )

        assert client.http_client == mock_http_client
        assert client.async_http_client == mock_async_http_client

    def test_init_passes_http_clients_to_provider(
        self, mock_http_client, mock_async_http_client
    ):
        """Test that HTTP clients are passed to provider when instantiated."""
        # Create a provider instance with custom HTTP clients
        provider = MockProvider(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            http_client=mock_http_client,
            async_http_client=mock_async_http_client,
        )

        client = OAuth2Client(
            provider=provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            http_client=mock_http_client,
            async_http_client=mock_async_http_client,
        )

        # Verify the provider has the http clients
        assert client.provider.http_client == mock_http_client
        assert client.provider.async_http_client == mock_async_http_client

    def test_init_with_scopes(self, mock_provider):
        """Test initialization with scopes."""
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["email", "profile"],
        )

        assert client.scopes == ["email", "profile"]

    def test_init_without_client_id_raises_error(self, mock_provider):
        """Test that missing client_id raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="client_id is required"):
            OAuth2Client(
                provider=mock_provider,
                client_id="",
                client_secret="test_client_secret",
                redirect_uri="https://example.com/callback",
            )

    def test_init_with_provider_enum_string(self):
        """Test initialization with provider as string."""
        # Test invalid provider string
        with pytest.raises(ConfigurationError, match="Unsupported provider"):
            OAuth2Client(
                provider="invalid_provider",
                client_id="test_client_id",
                client_secret="test_client_secret",
                redirect_uri="https://example.com/callback",
            )


class TestProviderCapabilities:
    """Test provider capability checking methods."""

    def test_supports_refresh_true(self, oauth_client_with_refresh):
        """Test supports_refresh returns True for providers with refresh support."""
        assert oauth_client_with_refresh.supports_refresh() is True

    def test_supports_refresh_false(self, oauth_client):
        """Test supports_refresh returns False for providers without refresh support."""
        assert oauth_client.supports_refresh() is False

    def test_supports_revocation_true(self, oauth_client_with_revocation):
        """Test supports_revocation returns True for providers with revocation support."""
        assert oauth_client_with_revocation.supports_revocation() is True

    def test_supports_revocation_false(self, oauth_client):
        """Test supports_revocation returns False for providers without revocation support."""
        assert oauth_client.supports_revocation() is False

    def test_supports_pkce_true(self, oauth_client_with_pkce):
        """Test supports_pkce returns True for providers with PKCE support."""
        assert oauth_client_with_pkce.supports_pkce() is True

    def test_supports_pkce_false(self, oauth_client):
        """Test supports_pkce returns False for providers without PKCE support."""
        assert oauth_client.supports_pkce() is False


class TestAuthorizationSession:
    """Test authorization session generation."""

    def test_get_authorization_session_basic(self, oauth_client):
        """Test basic authorization session generation."""
        session = oauth_client.get_authorization_session()

        assert isinstance(session, OAuthSession)
        assert "https://mock.provider.com/oauth/authorize" in session.url
        assert "client_id=test_client_id" in session.url
        assert "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback" in session.url
        assert "response_type=code" in session.url
        assert "state=" in session.url
        assert session.state is not None

    def test_get_authorization_session_with_scopes(self, oauth_client):
        """Test authorization session with custom scopes."""
        session = oauth_client.get_authorization_session(scopes=["email", "profile"])

        assert "scope=email+profile" in session.url
        assert session.scopes == ["email", "profile"]

    def test_get_authorization_session_with_metadata(self, oauth_client):
        """Test authorization session with metadata."""
        metadata = {"user_ip": "192.168.1.1", "device": "mobile"}
        session = oauth_client.get_authorization_session(metadata=metadata)

        assert session.metadata == metadata

    def test_get_authorization_session_with_nonce(self, oauth_client):
        """Test authorization session with nonce."""
        session = oauth_client.get_authorization_session(nonce="test_nonce")

        assert session.nonce == "test_nonce"

    def test_get_authorization_session_with_pkce(self, oauth_client_with_pkce):
        """Test authorization session generation with PKCE."""
        session = oauth_client_with_pkce.get_authorization_session()

        assert "code_challenge=" in session.url
        assert "code_challenge_method=S256" in session.url
        assert session.code_verifier is not None
        assert session.code_challenge is not None


class TestTokenExchange:
    """Test authorization code exchange for tokens (SYNC)."""

    def test_exchange_code_success(self, oauth_client):
        """Test successful code exchange."""
        tokens = oauth_client.exchange_code("test_auth_code")

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "mock_access_token"
        assert tokens.token_type == "Bearer"
        assert tokens.expires_in == 3600
        assert tokens.refresh_token == "mock_refresh_token"
        assert tokens.scope == "read write"

    def test_exchange_code_with_pkce_using_session(self, oauth_client_with_pkce):
        """Test code exchange with PKCE using session."""
        # First generate auth session to create code_verifier
        session = oauth_client_with_pkce.get_authorization_session()

        # Exchange code with session
        tokens = oauth_client_with_pkce.exchange_code("test_auth_code", session=session)

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "pkce_access_token"

    def test_exchange_code_with_pkce_explicit_verifier(self, oauth_client_with_pkce):
        """Test code exchange with PKCE using explicitly provided verifier."""
        tokens = oauth_client_with_pkce.exchange_code(
            "test_auth_code", code_verifier="explicit_code_verifier"
        )

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "pkce_access_token"

    def test_exchange_code_pkce_missing_verifier_raises_error(
        self, oauth_client_with_pkce
    ):
        """Test that PKCE exchange without verifier raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="requires PKCE"):
            oauth_client_with_pkce.exchange_code("test_auth_code")

    def test_exchange_code_empty_response_raises_error(self):
        """Test that empty token response raises TokenError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(TokenError, match="Failed to obtain tokens"):
            client.exchange_code("empty_response")

    def test_exchange_code_provider_error_raises_authorization_error(self):
        """Test that provider errors during exchange raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error exchanging code"):
            client.exchange_code("invalid_code")


class TestAsyncTokenExchange:
    """Test authorization code exchange for tokens (ASYNC)."""

    @pytest.mark.asyncio
    async def test_aexchange_code_success(self, oauth_client):
        """Test successful async code exchange."""
        tokens = await oauth_client.aexchange_code("test_auth_code")

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "async_mock_access_token"
        assert tokens.token_type == "Bearer"
        assert tokens.expires_in == 3600
        assert tokens.refresh_token == "async_mock_refresh_token"

    @pytest.mark.asyncio
    async def test_aexchange_code_with_pkce_using_session(self, oauth_client_with_pkce):
        """Test async code exchange with PKCE using session."""
        session = oauth_client_with_pkce.get_authorization_session()
        tokens = await oauth_client_with_pkce.aexchange_code(
            "test_auth_code", session=session
        )

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "async_pkce_access_token"

    @pytest.mark.asyncio
    async def test_aexchange_code_with_pkce_explicit_verifier(
        self, oauth_client_with_pkce
    ):
        """Test async code exchange with PKCE using explicit verifier."""
        tokens = await oauth_client_with_pkce.aexchange_code(
            "test_auth_code", code_verifier="explicit_code_verifier"
        )

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "async_pkce_access_token"

    @pytest.mark.asyncio
    async def test_aexchange_code_pkce_missing_verifier_raises_error(
        self, oauth_client_with_pkce
    ):
        """Test that async PKCE exchange without verifier raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="requires PKCE"):
            await oauth_client_with_pkce.aexchange_code("test_auth_code")

    @pytest.mark.asyncio
    async def test_aexchange_code_empty_response_raises_error(self):
        """Test that empty async token response raises TokenError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(TokenError, match="Failed to obtain tokens"):
            await client.aexchange_code("empty_response")

    @pytest.mark.asyncio
    async def test_aexchange_code_provider_error_raises_authorization_error(self):
        """Test that provider errors during async exchange raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error exchanging code"):
            await client.aexchange_code("invalid_code")


class TestUserInfo:
    """Test user information retrieval (SYNC)."""

    def test_get_user_info_success(self, oauth_client):
        """Test successful user info retrieval."""
        user_info = oauth_client.get_user_info("mock_access_token")

        assert isinstance(user_info, UserInfo)
        assert user_info.id == "12345"
        assert user_info.email == "user@example.com"
        assert user_info.name == "Test User"
        assert user_info.given_name == "Test"
        assert user_info.family_name == "User"
        assert user_info.picture == "https://example.com/photo.jpg"
        assert user_info.verified_email is True

    def test_get_user_info_empty_response_raises_error(self):
        """Test that empty user info response raises AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(
            AuthorizationError, match="Error retrieving user information"
        ):
            client.get_user_info("empty_response")

    def test_get_user_info_provider_error_raises_authorization_error(self):
        """Test that provider errors during user info retrieval raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(
            AuthorizationError, match="Error retrieving user information"
        ):
            client.get_user_info("invalid_token")


class TestAsyncUserInfo:
    """Test user information retrieval (ASYNC)."""

    @pytest.mark.asyncio
    async def test_aget_user_info_success(self, oauth_client):
        """Test successful async user info retrieval."""
        user_info = await oauth_client.aget_user_info("async_mock_access_token")

        assert isinstance(user_info, UserInfo)
        assert user_info.id == "async_12345"
        assert user_info.email == "async_user@example.com"
        assert user_info.name == "Async Test User"

    @pytest.mark.asyncio
    async def test_aget_user_info_empty_response_raises_error(self):
        """Test that empty async user info response raises AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(
            AuthorizationError, match="Error retrieving user information"
        ):
            await client.aget_user_info("empty_response")

    @pytest.mark.asyncio
    async def test_aget_user_info_provider_error_raises_authorization_error(self):
        """Test that provider errors during async user info retrieval raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(
            AuthorizationError, match="Error retrieving user information"
        ):
            await client.aget_user_info("invalid_token")


class TestTokenRefresh:
    """Test token refresh functionality (SYNC)."""

    def test_refresh_token_success(self, oauth_client_with_refresh):
        """Test successful token refresh."""
        new_tokens = oauth_client_with_refresh.refresh_token("mock_refresh_token")

        assert isinstance(new_tokens, TokenResponse)
        assert new_tokens.access_token == "new_mock_access_token"
        assert new_tokens.refresh_token == "new_mock_refresh_token"

    def test_refresh_token_not_supported_raises_error(self, oauth_client):
        """Test that refresh on unsupported provider raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="does not support token refresh"):
            oauth_client.refresh_token("mock_refresh_token")

    def test_refresh_token_provider_error_raises_authorization_error(
        self, mock_provider_with_refresh
    ):
        """Test that provider errors during refresh raise AuthorizationError."""
        mock_provider_with_refresh.refresh_token = Mock(
            side_effect=Exception("Refresh failed")
        )

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error refreshing tokens"):
            client.refresh_token("mock_refresh_token")

    def test_refresh_token_empty_response_raises_error(
        self, mock_provider_with_refresh
    ):
        """Test that empty refresh response raises TokenError."""
        mock_provider_with_refresh.refresh_token = Mock(return_value=None)

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(TokenError, match="Failed to refresh tokens"):
            client.refresh_token("mock_refresh_token")


class TestAsyncTokenRefresh:
    """Test token refresh functionality (ASYNC)."""

    @pytest.mark.asyncio
    async def test_arefresh_token_success(self, oauth_client_with_refresh):
        """Test successful async token refresh."""
        new_tokens = await oauth_client_with_refresh.arefresh_token(
            "mock_refresh_token"
        )

        assert isinstance(new_tokens, TokenResponse)
        assert new_tokens.access_token == "async_new_mock_access_token"
        assert new_tokens.refresh_token == "async_new_mock_refresh_token"

    @pytest.mark.asyncio
    async def test_arefresh_token_not_supported_raises_error(self, oauth_client):
        """Test that async refresh on unsupported provider raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="does not support token refresh"):
            await oauth_client.arefresh_token("mock_refresh_token")

    @pytest.mark.asyncio
    async def test_arefresh_token_provider_error_raises_authorization_error(
        self, mock_provider_with_refresh
    ):
        """Test that provider errors during async refresh raise AuthorizationError."""
        mock_provider_with_refresh.arefresh_token = AsyncMock(
            side_effect=Exception("Refresh failed")
        )

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error refreshing tokens"):
            await client.arefresh_token("mock_refresh_token")

    @pytest.mark.asyncio
    async def test_arefresh_token_empty_response_raises_error(
        self, mock_provider_with_refresh
    ):
        """Test that empty async refresh response raises TokenError."""
        mock_provider_with_refresh.arefresh_token = AsyncMock(return_value=None)

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(TokenError, match="Failed to refresh tokens"):
            await client.arefresh_token("mock_refresh_token")


class TestTokenRevocation:
    """Test token revocation functionality (SYNC)."""

    def test_revoke_token_success(self, oauth_client_with_revocation):
        """Test successful token revocation."""
        result = oauth_client_with_revocation.revoke_token("mock_access_token")

        assert result is True

    def test_revoke_token_not_supported_raises_error(self, oauth_client):
        """Test that revoke on unsupported provider raises ConfigurationError."""
        with pytest.raises(
            ConfigurationError, match="does not support token revocation"
        ):
            oauth_client.revoke_token("mock_access_token")

    def test_revoke_token_provider_error_raises_authorization_error(
        self, mock_provider_with_revocation
    ):
        """Test that provider errors during revocation raise AuthorizationError."""
        mock_provider_with_revocation.revoke_token = Mock(
            side_effect=Exception("Revocation failed")
        )

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error revoking token"):
            client.revoke_token("mock_access_token")

    def test_revoke_token_unsuccessful_response(self, mock_provider_with_revocation):
        """Test revocation with unsuccessful response."""
        mock_provider_with_revocation.revoke_token = Mock(
            return_value={"success": False}
        )

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        result = client.revoke_token("mock_access_token")
        assert result is False


class TestAsyncTokenRevocation:
    """Test token revocation functionality (ASYNC)."""

    @pytest.mark.asyncio
    async def test_arevoke_token_success(self, oauth_client_with_revocation):
        """Test successful async token revocation."""
        result = await oauth_client_with_revocation.arevoke_token("mock_access_token")

        assert result is True

    @pytest.mark.asyncio
    async def test_arevoke_token_not_supported_raises_error(self, oauth_client):
        """Test that async revoke on unsupported provider raises ConfigurationError."""
        with pytest.raises(
            ConfigurationError, match="does not support token revocation"
        ):
            await oauth_client.arevoke_token("mock_access_token")

    @pytest.mark.asyncio
    async def test_arevoke_token_provider_error_raises_authorization_error(
        self, mock_provider_with_revocation
    ):
        """Test that provider errors during async revocation raise AuthorizationError."""
        mock_provider_with_revocation.arevoke_token = AsyncMock(
            side_effect=Exception("Revocation failed")
        )

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        with pytest.raises(AuthorizationError, match="Error revoking token"):
            await client.arevoke_token("mock_access_token")

    @pytest.mark.asyncio
    async def test_arevoke_token_unsuccessful_response(
        self, mock_provider_with_revocation
    ):
        """Test async revocation with unsuccessful response."""
        mock_provider_with_revocation.arevoke_token = AsyncMock(
            return_value={"success": False}
        )

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
        )

        result = await client.arevoke_token("mock_access_token")
        assert result is False


class TestIntegrationScenarios:
    """Test realistic OAuth flow scenarios."""

    def test_complete_oauth_flow(self, oauth_client):
        """Test a complete OAuth flow from authorization to user info."""
        # Step 1: Get authorization session
        session = oauth_client.get_authorization_session(scopes=["email", "profile"])
        assert "https://mock.provider.com/oauth/authorize" in session.url

        # Step 2: Exchange code for tokens
        tokens = oauth_client.exchange_code("auth_code_from_redirect")
        assert tokens.access_token == "mock_access_token"

        # Step 3: Get user info
        user_info = oauth_client.get_user_info(tokens.access_token)
        assert user_info.email == "user@example.com"

    def test_complete_oauth_flow_with_refresh(self, oauth_client_with_refresh):
        """Test OAuth flow with token refresh."""
        # Get tokens
        tokens = oauth_client_with_refresh.exchange_code("auth_code")
        assert tokens.access_token == "mock_access_token"

        # Refresh tokens
        new_tokens = oauth_client_with_refresh.refresh_token(tokens.refresh_token)
        assert new_tokens.access_token == "new_mock_access_token"

    def test_complete_oauth_flow_with_revocation(self, oauth_client_with_revocation):
        """Test OAuth flow with token revocation."""
        # Get tokens
        tokens = oauth_client_with_revocation.exchange_code("auth_code")

        # Get user info
        user_info = oauth_client_with_revocation.get_user_info(tokens.access_token)
        assert user_info.id == "12345"

        # Revoke token
        result = oauth_client_with_revocation.revoke_token(tokens.access_token)
        assert result is True

    def test_complete_pkce_flow(self, oauth_client_with_pkce):
        """Test complete PKCE flow."""
        # Step 1: Get authorization session (generates code_verifier and code_challenge)
        session = oauth_client_with_pkce.get_authorization_session()
        assert "code_challenge=" in session.url
        assert session.code_verifier is not None

        # Step 2: Exchange code (uses session's code_verifier)
        tokens = oauth_client_with_pkce.exchange_code("auth_code", session=session)
        assert tokens.access_token == "pkce_access_token"

        # Step 3: Get user info
        user_info = oauth_client_with_pkce.get_user_info(tokens.access_token)
        assert user_info.id == "12345"

    @pytest.mark.asyncio
    async def test_complete_async_oauth_flow(self, oauth_client):
        """Test a complete async OAuth flow."""
        # Step 1: Get authorization session (sync)
        session = oauth_client.get_authorization_session(scopes=["email", "profile"])
        assert "https://mock.provider.com/oauth/authorize" in session.url

        # Step 2: Exchange code for tokens (async)
        tokens = await oauth_client.aexchange_code("auth_code_from_redirect")
        assert tokens.access_token == "async_mock_access_token"

        # Step 3: Get user info (async)
        user_info = await oauth_client.aget_user_info(tokens.access_token)
        assert user_info.email == "async_user@example.com"

    @pytest.mark.asyncio
    async def test_complete_async_oauth_flow_with_refresh(
        self, oauth_client_with_refresh
    ):
        """Test async OAuth flow with token refresh."""
        # Get tokens
        tokens = await oauth_client_with_refresh.aexchange_code("auth_code")
        assert tokens.access_token == "async_mock_access_token"

        # Refresh tokens
        new_tokens = await oauth_client_with_refresh.arefresh_token(
            tokens.refresh_token
        )
        assert new_tokens.access_token == "async_new_mock_access_token"

    @pytest.mark.asyncio
    async def test_complete_async_pkce_flow(self, oauth_client_with_pkce):
        """Test complete async PKCE flow."""
        # Step 1: Get authorization session
        session = oauth_client_with_pkce.get_authorization_session()
        assert "code_challenge=" in session.url

        # Step 2: Exchange code (async)
        tokens = await oauth_client_with_pkce.aexchange_code(
            "auth_code", session=session
        )
        assert tokens.access_token == "async_pkce_access_token"

        # Step 3: Get user info (async)
        user_info = await oauth_client_with_pkce.aget_user_info(tokens.access_token)
        assert user_info.id == "async_12345"

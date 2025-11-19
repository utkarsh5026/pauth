"""
Comprehensive tests for OAuth2Client with mock providers.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Optional
from src.client import OAuth2Client
from src.providers.base import BaseProvider
from src.models import TokenResponse, UserInfo, Providers
from src.storage import MemoryTokenStorage
from src.exceptions import (
    ConfigurationError,
    TokenError,
    AuthorizationError,
)


# Mock Provider Classes for Testing
class MockProvider(BaseProvider):
    """A basic mock provider without refresh/revocation/PKCE support."""

    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = False
    SUPPORTS_PKCE = False

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes=None):
        super().__init__(client_id, client_secret, redirect_uri, scopes)
        self.authorization_endpoint = "https://mock.provider.com/oauth/authorize"
        self.token_endpoint = "https://mock.provider.com/oauth/token"
        self.user_info_endpoint = "https://mock.provider.com/oauth/userinfo"

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        """Mock token exchange."""
        return {
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "mock_refresh_token",
            "scope": "read write",
        }

    def get_user_info(self, access_token: str) -> dict:
        """Mock user info retrieval."""
        return {
            "id": "12345",
            "email": "user@example.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
            "verified_email": True,
        }


class MockProviderWithRefresh(MockProvider):
    """Mock provider with refresh token support."""

    SUPPORTS_REFRESH = True

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes=None):
        super().__init__(client_id, client_secret, redirect_uri, scopes)
        self.revocation_endpoint = "https://mock.provider.com/oauth/revoke"

    def refresh_token(self, refresh_token: str) -> dict:
        """Mock token refresh."""
        return {
            "access_token": "new_mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_mock_refresh_token",
        }


class MockProviderWithRevocation(MockProviderWithRefresh):
    """Mock provider with revocation support."""

    SUPPORTS_REVOCATION = True

    def revoke_token(self, token: str) -> dict:
        """Mock token revocation."""
        return {"success": True}


class MockProviderWithPKCE(MockProvider):
    """Mock provider with PKCE support."""

    SUPPORTS_PKCE = True

    def prepare_auth_url(self, additional_params: Optional[dict] = None):
        """Prepare auth URL with PKCE parameters."""
        additional_params = additional_params or {}

        # Generate PKCE parameters
        verifier, challenge = self.generate_pkce_parameters()
        additional_params['code_challenge'] = challenge
        additional_params['code_challenge_method'] = 'S256'

        return super().prepare_auth_url(additional_params)

    def exchange_code_for_access_token_pkce(self, code: str, code_verifier: str) -> dict:
        """Mock token exchange with PKCE."""
        return {
            "access_token": "pkce_access_token",
            "token_type": "Bearer",
            "expires_in": 7200,
            "refresh_token": "pkce_refresh_token",
        }


class MockProviderWithErrors(MockProvider):
    """Mock provider that simulates various error scenarios."""

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        """Simulate token exchange failure."""
        if code == "invalid_code":
            raise Exception("Invalid authorization code")
        if code == "empty_response":
            return {}
        return super().exchange_code_for_access_token(code, **kwargs)

    def get_user_info(self, access_token: str) -> dict:
        """Simulate user info retrieval failure."""
        if access_token == "invalid_token":
            raise Exception("Invalid access token")
        if access_token == "empty_response":
            return {}
        return super().get_user_info(access_token)


# Fixtures
@pytest.fixture
def mock_provider():
    """Create a basic mock provider instance."""
    return MockProvider(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback",
        scopes=["read", "write"]
    )


@pytest.fixture
def mock_provider_with_refresh():
    """Create a mock provider with refresh support."""
    return MockProviderWithRefresh(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def mock_provider_with_revocation():
    """Create a mock provider with revocation support."""
    return MockProviderWithRevocation(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def mock_provider_with_pkce():
    """Create a mock provider with PKCE support."""
    return MockProviderWithPKCE(
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def oauth_client(mock_provider):
    """Create an OAuth2Client with basic mock provider."""
    return OAuth2Client(
        provider=mock_provider,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def oauth_client_with_refresh(mock_provider_with_refresh):
    """Create an OAuth2Client with refresh support."""
    return OAuth2Client(
        provider=mock_provider_with_refresh,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def oauth_client_with_revocation(mock_provider_with_revocation):
    """Create an OAuth2Client with revocation support."""
    return OAuth2Client(
        provider=mock_provider_with_revocation,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
    )


@pytest.fixture
def oauth_client_with_pkce(mock_provider_with_pkce):
    """Create an OAuth2Client with PKCE support."""
    return OAuth2Client(
        provider=mock_provider_with_pkce,
        client_id="test_client_id",
        client_secret="test_client_secret",
        redirect_uri="https://example.com/callback"
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
            redirect_uri="https://example.com/callback"
        )

        assert client.client_id == "test_client_id"
        assert client.client_secret == "test_client_secret"
        assert client.redirect_uri == "https://example.com/callback"
        assert client.provider == mock_provider
        assert isinstance(client.tok_store, MemoryTokenStorage)

    def test_init_with_custom_token_storage(self, mock_provider):
        """Test initialization with custom token storage."""
        custom_storage = MemoryTokenStorage()
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            tok_store=custom_storage
        )

        assert client.tok_store == custom_storage

    def test_init_with_scopes(self, mock_provider):
        """Test initialization with scopes."""
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["email", "profile"]
        )

        assert client.scopes == ["email", "profile"]

    def test_init_without_client_id_raises_error(self, mock_provider):
        """Test that missing client_id raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="client_id is required"):
            OAuth2Client(
                provider=mock_provider,
                client_id="",
                client_secret="test_client_secret",
                redirect_uri="https://example.com/callback"
            )

    def test_init_with_provider_enum_string(self):
        """Test initialization with provider as string."""
        with patch('src.models.provider.Providers') as mock_providers_enum:
            mock_providers_enum.return_value.get_provider_class.return_value = MockProvider

            # We can't easily test this without actual providers,
            # so we just verify the error for invalid provider
            with pytest.raises(ConfigurationError, match="Unsupported provider"):
                OAuth2Client(
                    provider="invalid_provider",
                    client_id="test_client_id",
                    client_secret="test_client_secret",
                    redirect_uri="https://example.com/callback"
                )

    def test_init_with_invalid_provider_type(self):
        """Test initialization with invalid provider type."""
        with pytest.raises(ConfigurationError, match="Invalid provider type"):
            OAuth2Client(
                provider=12345,  # Invalid type
                client_id="test_client_id",
                client_secret="test_client_secret",
                redirect_uri="https://example.com/callback"
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


class TestAuthorizationURL:
    """Test authorization URL generation."""

    def test_get_authorization_url_basic(self, oauth_client):
        """Test basic authorization URL generation."""
        auth_url = oauth_client.get_authorization_url()

        assert "https://mock.provider.com/oauth/authorize" in auth_url
        assert "client_id=test_client_id" in auth_url
        assert "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback" in auth_url
        assert "response_type=code" in auth_url
        assert "state=" in auth_url

    def test_get_authorization_url_with_scopes(self, oauth_client):
        """Test authorization URL with custom scopes."""
        auth_url = oauth_client.get_authorization_url(scope=["email", "profile"])

        assert "scope=email+profile" in auth_url

    def test_get_authorization_url_with_additional_params(self, oauth_client):
        """Test authorization URL with additional parameters."""
        auth_url = oauth_client.get_authorization_url(
            access_type="offline",
            prompt="consent"
        )

        assert "access_type=offline" in auth_url
        assert "prompt=consent" in auth_url

    def test_get_authorization_url_with_pkce(self, oauth_client_with_pkce):
        """Test authorization URL generation with PKCE."""
        auth_url = oauth_client_with_pkce.get_authorization_url()

        assert "code_challenge=" in auth_url
        assert "code_challenge_method=S256" in auth_url

    def test_get_code_verifier_after_auth_url(self, oauth_client_with_pkce):
        """Test retrieving code verifier after generating auth URL."""
        oauth_client_with_pkce.get_authorization_url()
        code_verifier = oauth_client_with_pkce.get_code_verifier()

        assert code_verifier is not None
        assert isinstance(code_verifier, str)
        assert len(code_verifier) >= 43

    def test_get_code_verifier_without_pkce(self, oauth_client):
        """Test get_code_verifier returns None for non-PKCE providers."""
        code_verifier = oauth_client.get_code_verifier()
        assert code_verifier is None


class TestTokenExchange:
    """Test authorization code exchange for tokens."""

    def test_exchange_code_success(self, oauth_client):
        """Test successful code exchange."""
        tokens = oauth_client.exchange_code("test_auth_code")

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "mock_access_token"
        assert tokens.token_type == "Bearer"
        assert tokens.expires_in == 3600
        assert tokens.refresh_token == "mock_refresh_token"
        assert tokens.scope == "read write"

    def test_exchange_code_with_pkce_auto_verifier(self, oauth_client_with_pkce):
        """Test code exchange with PKCE using automatically stored verifier."""
        # First generate auth URL to create code_verifier
        oauth_client_with_pkce.get_authorization_url()

        # Exchange code should use stored verifier automatically
        tokens = oauth_client_with_pkce.exchange_code("test_auth_code")

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "pkce_access_token"

    def test_exchange_code_with_pkce_explicit_verifier(self, oauth_client_with_pkce):
        """Test code exchange with PKCE using explicitly provided verifier."""
        tokens = oauth_client_with_pkce.exchange_code(
            "test_auth_code",
            code_verifier="explicit_code_verifier"
        )

        assert isinstance(tokens, TokenResponse)
        assert tokens.access_token == "pkce_access_token"

    def test_exchange_code_pkce_missing_verifier_raises_error(self, oauth_client_with_pkce):
        """Test that PKCE exchange without verifier raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="requires PKCE"):
            oauth_client_with_pkce.exchange_code("test_auth_code")

    def test_exchange_code_empty_response_raises_error(self, mock_provider):
        """Test that empty token response raises TokenError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(TokenError, match="Failed to obtain tokens"):
            client.exchange_code("empty_response")

    def test_exchange_code_provider_error_raises_authorization_error(self, mock_provider):
        """Test that provider errors during exchange raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(AuthorizationError, match="Error exchanging code"):
            client.exchange_code("invalid_code")


class TestUserInfo:
    """Test user information retrieval."""

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

    def test_get_user_info_empty_response_raises_error(self, mock_provider):
        """Test that empty user info response raises AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(AuthorizationError, match="Error retrieving user information"):
            client.get_user_info("empty_response")

    def test_get_user_info_provider_error_raises_authorization_error(self, mock_provider):
        """Test that provider errors during user info retrieval raise AuthorizationError."""
        error_provider = MockProviderWithErrors(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )
        client = OAuth2Client(
            provider=error_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(AuthorizationError, match="Error retrieving user information"):
            client.get_user_info("invalid_token")


class TestTokenRefresh:
    """Test token refresh functionality."""

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

    def test_refresh_token_provider_error_raises_authorization_error(self, mock_provider_with_refresh):
        """Test that provider errors during refresh raise AuthorizationError."""
        # Mock the refresh_token method to raise an exception
        mock_provider_with_refresh.refresh_token = Mock(side_effect=Exception("Refresh failed"))

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(AuthorizationError, match="Error refreshing tokens"):
            client.refresh_token("mock_refresh_token")

    def test_refresh_token_empty_response_raises_error(self, mock_provider_with_refresh):
        """Test that empty refresh response raises TokenError."""
        # Mock the refresh_token method to return None
        mock_provider_with_refresh.refresh_token = Mock(return_value=None)

        client = OAuth2Client(
            provider=mock_provider_with_refresh,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(TokenError, match="Failed to refresh tokens"):
            client.refresh_token("mock_refresh_token")


class TestTokenRevocation:
    """Test token revocation functionality."""

    def test_revoke_token_success(self, oauth_client_with_revocation):
        """Test successful token revocation."""
        result = oauth_client_with_revocation.revoke_token("mock_access_token")

        assert result is True

    def test_revoke_token_not_supported_raises_error(self, oauth_client):
        """Test that revoke on unsupported provider raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="does not support token revocation"):
            oauth_client.revoke_token("mock_access_token")

    def test_revoke_token_provider_error_raises_authorization_error(self, mock_provider_with_revocation):
        """Test that provider errors during revocation raise AuthorizationError."""
        # Mock the revoke_token method to raise an exception
        mock_provider_with_revocation.revoke_token = Mock(side_effect=Exception("Revocation failed"))

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        with pytest.raises(AuthorizationError, match="Error revoking token"):
            client.revoke_token("mock_access_token")

    def test_revoke_token_unsuccessful_response(self, mock_provider_with_revocation):
        """Test revocation with unsuccessful response."""
        # Mock the revoke_token method to return unsuccessful response
        mock_provider_with_revocation.revoke_token = Mock(return_value={"success": False})

        client = OAuth2Client(
            provider=mock_provider_with_revocation,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        result = client.revoke_token("mock_access_token")
        assert result is False


class TestIntegrationScenarios:
    """Test realistic OAuth flow scenarios."""

    def test_complete_oauth_flow(self, oauth_client):
        """Test a complete OAuth flow from authorization to user info."""
        # Step 1: Get authorization URL
        auth_url = oauth_client.get_authorization_url(scope=["email", "profile"])
        assert "https://mock.provider.com/oauth/authorize" in auth_url

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
        # Step 1: Get authorization URL (generates code_verifier and code_challenge)
        auth_url = oauth_client_with_pkce.get_authorization_url()
        assert "code_challenge=" in auth_url

        # Step 2: Retrieve code_verifier for storage
        code_verifier = oauth_client_with_pkce.get_code_verifier()
        assert code_verifier is not None

        # Step 3: Exchange code (uses stored code_verifier automatically)
        tokens = oauth_client_with_pkce.exchange_code("auth_code")
        assert tokens.access_token == "pkce_access_token"

        # Step 4: Get user info
        user_info = oauth_client_with_pkce.get_user_info(tokens.access_token)
        assert user_info.id == "12345"

    def test_multiple_concurrent_clients(self):
        """Test multiple OAuth clients working independently."""
        client1 = OAuth2Client(
            provider=MockProvider(
                client_id="client1_id",
                client_secret="client1_secret",
                redirect_uri="https://app1.com/callback"
            ),
            client_id="client1_id",
            client_secret="client1_secret",
            redirect_uri="https://app1.com/callback"
        )

        client2 = OAuth2Client(
            provider=MockProvider(
                client_id="client2_id",
                client_secret="client2_secret",
                redirect_uri="https://app2.com/callback"
            ),
            client_id="client2_id",
            client_secret="client2_secret",
            redirect_uri="https://app2.com/callback"
        )

        # Both clients should work independently
        url1 = client1.get_authorization_url()
        url2 = client2.get_authorization_url()

        assert "client_id=client1_id" in url1
        assert "client_id=client2_id" in url2
        assert url1 != url2


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_client_with_no_scopes(self, mock_provider):
        """Test client initialization without scopes."""
        client = OAuth2Client(
            provider=mock_provider,
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback"
        )

        assert client.scopes == []

    def test_get_authorization_url_updates_provider_scopes(self, oauth_client):
        """Test that get_authorization_url updates provider scopes."""
        new_scopes = ["email", "profile", "openid"]
        oauth_client.get_authorization_url(scope=new_scopes)

        assert oauth_client.provider.scopes == new_scopes

    def test_token_response_conversion(self, oauth_client):
        """Test that token responses are properly converted to TokenResponse objects."""
        tokens = oauth_client.exchange_code("test_code")

        assert hasattr(tokens, 'access_token')
        assert hasattr(tokens, 'token_type')
        assert hasattr(tokens, 'expires_in')
        assert hasattr(tokens, 'refresh_token')

    def test_user_info_conversion(self, oauth_client):
        """Test that user info responses are properly converted to UserInfo objects."""
        user_info = oauth_client.get_user_info("test_token")

        assert hasattr(user_info, 'id')
        assert hasattr(user_info, 'email')
        assert hasattr(user_info, 'name')
        assert hasattr(user_info, 'to_dict')

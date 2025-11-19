"""
Stateless OAuth provider base class with unified sync/async support.
"""

from abc import ABC, abstractmethod
from typing import Optional, Any
from urllib.parse import urlencode
import secrets
import hashlib
import base64
from src.http import HTTPClient, AsyncHTTPClient, HTTPResponse, HttpMethod
from src.exceptions import PAuthError
from src.models.session import OAuthSession


class BaseProviderMixin:
    """
    Mixin class containing common data preparation methods.

    This class contains pure functions that don't perform I/O operations,
    only data transformation and validation logic.

    Requires the following attributes from the implementing class:
        - client_id: str
        - client_secret: str
        - redirect_uri: str
        - scopes: list[str]
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str]

    def _build_authorization_params(
        self,
        state: str,
        scopes: Optional[list[str]] = None,
        additional_params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Build authorization URL parameters.

        Args:
            state: CSRF protection token
            scopes: Scopes to request (uses self.scopes if None)
            additional_params: Additional query parameters

        Returns:
            dict: URL parameters for authorization request
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes or self.scopes),
            "state": state,
        }

        if additional_params:
            params.update(additional_params)

        return params

    def _validate_and_parse_response(
        self, response: HTTPResponse, error_message: str = "Request failed"
    ) -> dict[str, Any]:
        """
        Validate HTTP response and parse JSON.

        Args:
            response: HTTP response object
            error_message: Error message prefix for failures

        Returns:
            dict: Parsed JSON response

        Raises:
            PAuthError: If response status is not 200 or JSON parsing fails
        """
        if response.status_code != 200:
            raise PAuthError(
                message=f"{error_message}: HTTP {response.status_code}",
            )

        try:
            return response.json()
        except Exception as e:
            raise PAuthError(message=f"Failed to parse response: {e}")

    def _generate_state(self) -> str:
        """
        Generate a secure random state parameter for CSRF protection.

        Returns:
            str: URL-safe random state token
        """
        return secrets.token_urlsafe(32)

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """
        Generate PKCE code verifier and code challenge pair.

        Returns:
            tuple[str, str]: (code_verifier, code_challenge)
        """
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        return code_verifier, code_challenge


class BaseProvider(BaseProviderMixin, ABC):

    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = False
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
        Initialize the OAuth provider.

        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: Default scopes (provider-specific defaults if None)
            http_client: Custom sync HTTP client (uses RequestsAdapter if None)
            async_http_client: Custom async HTTP client (uses HttpxAdapter if None)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes or self._get_default_scopes()
        self.__setup_client(http_client, async_http_client)

        self.authorization_endpoint: Optional[str] = None
        self.token_endpoint: Optional[str] = None
        self.revocation_endpoint: Optional[str] = None
        self.user_info_endpoint: Optional[str] = None

    def __setup_client(
        self,
        http_client: Optional[HTTPClient],
        async_http_client: Optional[AsyncHTTPClient],
    ) -> None:
        """
        Setup sync and async HTTP clients.

        Args:
            http_client: Custom HTTP client or None
            async_http_client: Custom async HTTP client or None
        """
        if http_client is None:
            from src.http import RequestsAdapter

            http_client = RequestsAdapter()

        if async_http_client is None:
            from src.http import HttpxAdapter

            async_http_client = HttpxAdapter()

        self.http_client = http_client
        self.async_http_client = async_http_client

    def _get_default_scopes(self) -> list[str]:
        """
        Get provider-specific default scopes.
        Subclasses should override this.
        """
        return []

    def _ensure(self, s: Optional[str]) -> str:
        """
        Ensure that a required endpoint is set.
        """
        if s is None:
            raise ValueError("Required endpoint is not set")
        return s

    def build_authorization_url(
        self,
        state: str,
        scopes: Optional[list[str]] = None,
        additional_params: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Build the authorization URL (stateless).

        Args:
            state: CSRF protection token (caller provides)
            scopes: Scopes to request (uses default if None)
            additional_params: Additional query parameters

        Returns:
            str: Complete authorization URL
        """
        if not self.authorization_endpoint:
            raise ValueError(
                f"Authorization endpoint not set for {self.__class__.__name__}"
            )

        params = self._build_authorization_params(
            state=state, scopes=scopes, additional_params=additional_params
        )

        return f"{self.authorization_endpoint}?{urlencode(params)}"

    def get_authorization_session(
        self,
        scopes: Optional[list[str]] = None,
        additional_params: Optional[dict[str, Any]] = None,
        nonce: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> OAuthSession:
        """
        Create an OAuth authorization session with all required parameters.

        This method generates the authorization URL along with state, PKCE parameters
        (if supported), and packages everything into an OAuthSession object.

        Args:
            scopes: Scopes to request (uses default if None)
            additional_params: Additional query parameters
            nonce: Optional nonce for OpenID Connect
            metadata: Optional custom metadata to store in session

        Returns:
            OAuthSession: Session object containing URL, state, PKCE params, etc.
        """
        if not self.authorization_endpoint:
            raise ValueError(
                f"Authorization endpoint not set for {self.__class__.__name__}"
            )

        state = self._generate_state()
        if additional_params is None:
            additional_params = {}

        code_verifier: Optional[str] = None
        code_challenge: Optional[str] = None

        if self.SUPPORTS_PKCE:
            code_verifier, code_challenge = self._generate_pkce_pair()
            additional_params["code_challenge"] = code_challenge
            additional_params["code_challenge_method"] = "S256"

        # Build authorization URL
        url = self.build_authorization_url(
            state=state, scopes=scopes, additional_params=additional_params
        )

        # Create and return OAuthSession
        return OAuthSession(
            url=url,
            state=state,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            nonce=nonce,
            scopes=scopes or self.scopes,
            metadata=metadata or {},
        )

    @abstractmethod
    def exchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (SYNC).

        Args:
            code: Authorization code from callback
            code_verifier: Optional PKCE code verifier (required for PKCE providers)

        Returns:
            dict: Token response containing access_token, refresh_token, etc.

        Raises:
            PAuthError: If exchange fails
        """
        raise NotImplementedError()

    def get_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information using access token (SYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information

        Raises:
            PAuthError: If request fails
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement get_user_info()"
        )

    def refresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh an access token (SYNC).

        Args:
            refresh_token: Refresh token

        Returns:
            dict: New token response

        Raises:
            NotImplementedError: If provider doesn't support refresh
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token refresh. "
            f"Check SUPPORTS_REFRESH before calling."
        )

    def revoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access or refresh token (SYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response

        Raises:
            NotImplementedError: If provider doesn't support revocation
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token revocation. "
            f"Check SUPPORTS_REVOCATION before calling."
        )

    def _make_request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
        error_message: str = "Request failed",
    ) -> dict[str, Any]:
        """
        Make a sync HTTP request using the configured client.

        Args:
            method: HTTP method
            url: Request URL
            data: Form data
            headers: HTTP headers
            params: Query parameters
            json: JSON body
            error_message: Error message if request fails

        Returns:
            dict: Parsed JSON response

        Raises:
            PAuthError: If request fails
        """
        response: HTTPResponse = self.http_client.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            params=params,
            json=json,
        )

        return self._validate_and_parse_response(response, error_message)

    @abstractmethod
    async def aexchange_code_for_access_token(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token (ASYNC).

        Args:
            code: Authorization code from callback
            code_verifier: Optional PKCE code verifier (required for PKCE providers)

        Returns:
            dict: Token response containing access_token, refresh_token, etc.

        Raises:
            PAuthError: If exchange fails
        """
        raise NotImplementedError()

    async def aget_user_info(self, access_token: str) -> dict[str, Any]:
        """
        Fetch user information using access token (ASYNC).

        Args:
            access_token: Valid access token

        Returns:
            dict: User information

        Raises:
            PAuthError: If request fails
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement aget_user_info()"
        )

    async def arefresh_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh an access token (ASYNC).

        Args:
            refresh_token: Refresh token

        Returns:
            dict: New token response

        Raises:
            NotImplementedError: If provider doesn't support refresh
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token refresh"
        )

    async def arevoke_token(self, token: str) -> dict[str, Any]:
        """
        Revoke an access or refresh token (ASYNC).

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response

        Raises:
            NotImplementedError: If provider doesn't support revocation
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token revocation"
        )

    async def _amake_request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
        error_message: str = "Request failed",
    ) -> dict[str, Any]:
        """
        Make an async HTTP request using the configured async client.

        Args:
            method: HTTP method
            url: Request URL
            data: Form data
            headers: HTTP headers
            params: Query parameters
            json: JSON body
            error_message: Error message if request fails

        Returns:
            dict: Parsed JSON response

        Raises:
            PAuthError: If request fails
        """
        response: HTTPResponse = await self.async_http_client.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            params=params,
            json=json,
        )

        return self._validate_and_parse_response(response, error_message)

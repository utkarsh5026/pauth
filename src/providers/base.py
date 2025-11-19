import json
import secrets
import requests
from urllib.parse import urlencode
from typing import Optional, Literal, Any, Tuple
from collections.abc import Mapping
from src.exceptions import PAuthError
from src.utils import make_request, generate_pkce_pair


class BaseProvider:
    """
    A base class for OAuth providers to inherit from, providing common attributes and methods.

    Attributes:
        client_id (str): The client ID for the OAuth application.
        client_secret (str): The client secret for the OAuth application.
        redirect_uri (str): The URI to redirect to after authorization.
        scopes (list, optional): The list of scopes for which the authorization is requested.
        authorization_endpoint (str): The endpoint URL for the authorization request.
        token_endpoint (str): The endpoint URL for the token request.
        revocation_endpoint (str): The endpoint URL for the token revocation.
        user_info_endpoint (str): The endpoint URL for fetching user information.

    Class Attributes:
        SUPPORTS_REFRESH (bool): Whether this provider supports token refresh.
        SUPPORTS_REVOCATION (bool): Whether this provider supports token revocation.
        SUPPORTS_PKCE (bool): Whether this provider supports PKCE flow.

    Methods:
        exchange_code_for_access_token(code: str) -> dict: Abstract method to be implemented by subclasses
            for exchanging an authorization code for an access token.
    """

    # Provider capability flags - subclasses should override these
    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = False
    SUPPORTS_PKCE = False

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, scopes=None
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.authorization_endpoint = None
        self.token_endpoint = None
        self.revocation_endpoint = None
        self.user_info_endpoint = None
        self.state = None
        # PKCE attributes (only used if SUPPORTS_PKCE is True)
        self.code_verifier = None
        self.code_challenge = None

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        """
        Exchange an authorization code for an access token.

        Args:
            code (str): The authorization code received from the OAuth provider.
            **kwargs: Additional provider-specific parameters.

        Returns:
            dict: A dictionary containing the access token and related information.

        Raises:
            NotImplementedError: This method must be implemented by subclasses.
        """
        raise NotImplementedError()

    def prepare_auth_url(self, additional_params: Optional[dict[str, str]] = None):
        """
        Prepare the authorization URL for the OAuth flow.

        Args:
            additional_params (Optional[dict[str, str]]): Additional query parameters to include in the URL.

        Returns:
            str: The complete authorization URL with all required parameters.
        """
        scopes = self.scopes if self.scopes else []
        additional_params = additional_params if additional_params else {}
        self.state = self.create_state()
        base_params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": self.state,
        }

        for key, value in additional_params.items():
            base_params[key] = value

        return f"{self.get_auth_endpoint()}?{urlencode(base_params)}"

    def get_user_info(self, access_token: str) -> dict:
        """
        Fetch user information.

        Args:
            access_token: Valid access token

        Returns:
            dict: User information

        Raises:
            OAuthError: If fetching user info fails
        """
        raise NotImplementedError()

    def refresh_token(self, refresh_token: str) -> dict:
        """
        Refresh an access token.

        Args:
            refresh_token: Refresh token

        Returns:
            dict: New token response

        Raises:
            NotImplementedError: If the provider does not support token refresh
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token refresh. "
            f"Check SUPPORTS_REFRESH before calling this method."
        )

    def revoke_token(self, token: str) -> dict:
        """
        Revoke an access or refresh token.

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response

        Raises:
            NotImplementedError: If the provider does not support token revocation
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support token revocation. "
            f"Check SUPPORTS_REVOCATION before calling this method."
        )

    def get_auth_endpoint(self):
        """
        Get the authorization endpoint URL.

        Returns:
            str: The authorization endpoint URL.

        Raises:
            ValueError: If the authorization endpoint is not set.
        """
        if not self.authorization_endpoint:
            raise ValueError(
                "Authorization endpoint is not set for this provider")
        return self.authorization_endpoint

    def oauth(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
        url: str,
        params: Any = None,
        headers: Optional[Mapping[str, str | bytes]] = None,
        data: Any = None,
        err_msg: str = "OAuth request failed",
    ):
        """
        Make an OAuth request to the specified URL.

        Args:
            method (Literal["GET", "POST", "PUT", "DELETE", "PATCH"]): The HTTP method to use.
            url (str): The URL to send the request to.
            params (Any, optional): Query parameters for the request.
            headers (Optional[Mapping[str, str | bytes]], optional): HTTP headers for the request.
            data (Any, optional): Request body data.
            err_msg (str, optional): Custom error message if the request fails. Defaults to "OAuth request failed".

        Returns:
            dict: The parsed JSON response from the server.

        Raises:
            PAuthError: If the request fails or returns a non-200 status code.
        """
        response = make_request(
            method=method, url=url, params=params, headers=headers, data=data
        )
        return self.validate_response_or_raise(response, err_msg)

    def validate_response_or_raise(
        self, response: requests.Response | None, err_msg: str
    ) -> dict[str, str]:
        """
        Validate the HTTP response and parse JSON or raise an error.

        Args:
            response (requests.Response | None): The HTTP response object.
            err_msg (str): The error message to use if validation fails.

        Returns:
            dict[str, str]: The parsed JSON response.

        Raises:
            PAuthError: If the response is invalid or status code is not 200.
        """
        if response and response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                return {}
        else:
            raise PAuthError(message=err_msg)

    def generate_pkce_parameters(self, length: int = 64, method: str = "S256") -> Tuple[str, str]:
        """
        Generate and store PKCE code verifier and code challenge.

        This method is useful for providers that support PKCE. It generates
        both the code verifier and challenge, stores them in the instance,
        and returns them for use in the authorization URL.

        Args:
            length (int): Length of the code verifier (43-128). Defaults to 64.
            method (str): Challenge method, either "S256" or "plain". Defaults to "S256".

        Returns:
            Tuple[str, str]: A tuple of (code_verifier, code_challenge).

        Example:
            ```python
            # In a provider's prepare_auth_url method
            if self.SUPPORTS_PKCE:
                verifier, challenge = self.generate_pkce_parameters()
                additional_params['code_challenge'] = challenge
                additional_params['code_challenge_method'] = 'S256'
            ```
        """
        self.code_verifier, self.code_challenge = generate_pkce_pair(
            length=length, method=method)
        return self.code_verifier, self.code_challenge

    @staticmethod
    def create_state() -> str:
        """
        Create a secure random state parameter for CSRF protection.

        Returns:
            str: A URL-safe random string.
        """
        return secrets.token_urlsafe(32)

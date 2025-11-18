from utils import make_request
from exceptions import PAuthError
from .base import BaseProvider


class GoogleProvider(BaseProvider):
    """
    Google OAuth 2.0 provider implementation.

    Supports:
    - Authorization code flow
    - Token exchange
    - Token refresh
    - Token revocation
    - User info retrieval
    - OpenID Connect
    """

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, scopes=None
    ):
        """
        Initialize Google OAuth provider.

        Args:
            client_id: Google OAuth client ID
            client_secret: Google OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: List of scopes (defaults to openid, email, profile)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["openid", "email", "profile"],
        )
        self.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_endpoint = "https://oauth2.googleapis.com/token"
        self.revocation_endpoint = "https://oauth2.googleapis.com/revoke"
        self.user_info_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo"

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            **kwargs: Additional parameters

        Returns:
            dict: Token response

        Raises:
            PAuthError: If token exchange fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }

        response = make_request("POST", self.token_endpoint, data=data)

        if response:
            return response.json()
        else:
            raise PAuthError("Failed to exchange code for access token")

    def refresh_token(self, refresh_token: str) -> dict:
        """
        Refresh an access token.

        Args:
            refresh_token: Refresh token

        Returns:
            dict: New token response

        Raises:
            PAuthError: If token refresh fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        response = make_request("POST", self.token_endpoint, data=data)

        if response:
            return response.json()
        else:
            raise PAuthError("Failed to refresh token")

    def revoke_token(self, token: str) -> dict:
        """
        Revoke an access or refresh token.

        Args:
            token: Token to revoke

        Returns:
            dict: Revocation response

        Raises:
            PAuthError: If token revocation fails
        """
        params = {"token": token}

        response = make_request("POST", self.revocation_endpoint, params=params)

        if response is not None:
            return response.json()
        else:
            raise PAuthError("Failed to revoke token")

    def get_user_info(self, access_token: str) -> dict:
        """
        Fetch user information.

        Args:
            access_token: Valid access token

        Returns:
            dict: User information

        Raises:
            PAuthError: If fetching user info fails
        """
        headers = {"Authorization": f"Bearer {access_token}"}

        response = make_request("GET", self.user_info_endpoint, headers=headers)

        if response:
            return response.json()
        else:
            raise PAuthError("Failed to fetch user info")

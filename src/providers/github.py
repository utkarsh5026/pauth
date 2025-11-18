import base64
from .base import BaseProvider


class GithubProvider(BaseProvider):
    """
    GitHub OAuth 2.0 provider implementation.
    Note: GitHub does not support token refresh for OAuth apps.
    """

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, scopes=None
    ):
        """
        Initialize GitHub OAuth provider.

        Args:
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: List of scopes (defaults to read:user, user:email)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["read:user", "user:email"],
        )
        self.authorization_endpoint = "https://github.com/login/oauth/authorize"
        self.token_endpoint = "https://github.com/login/oauth/access_token"
        self.revocation_endpoint = (
            "https://api.github.com/applications/{client_id}/token"
        )
        self.user_info_endpoint = "https://api.github.com/user"

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            **kwargs: Additional parameters

        Returns:
            dict: Token response
        Raises:
            OAuthError: If token exchange fails
        """
        headers = {
            "Accept": "application/json",
        }

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

        return self.oauth(
            "POST",
            self.token_endpoint,
            headers=headers,
            data=data,
            err_msg="Failed to exchange code for access token",
        )

    def revoke_token(self, token: str) -> dict:
        """
        Revoke an access token.

        Args:
            token: Access token to revoke

        Returns:
            dict: Revocation response

        Raises:
            OAuthError: If token revocation fails
        """
        auth_header = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()

        headers = {
            "Authorization": f"Basic {auth_header}",
            "Accept": "application/vnd.github.v3+json",
        }

        data = {"access_token": token}

        return self.oauth(
            "DELETE",
            self.revocation_endpoint.format(client_id=self.client_id),
            headers=headers,
            data=data,
            err_msg="Failed to revoke token",
        )

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
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        return self.oauth(
            "GET",
            self.user_info_endpoint,
            headers=headers,
            err_msg="Failed to fetch user info",
        )

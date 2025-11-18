from .base import BaseProvider


class LinkedInProvider(BaseProvider):
    """
    LinkedIn OAuth 2.0 provider implementation.
    """

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, scopes=None
    ):
        """
        Initialize LinkedIn OAuth provider.

        Args:
            client_id: LinkedIn OAuth client ID
            client_secret: LinkedIn OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: List of scopes (defaults to r_liteprofile, r_emailaddress)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["r_liteprofile", "r_emailaddress"],
        )
        self.authorization_endpoint = "https://www.linkedin.com/oauth/v2/authorization"
        self.token_endpoint = "https://www.linkedin.com/oauth/v2/accessToken"
        self.user_info_endpoint = "https://api.linkedin.com/v2/me"

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        return self.oauth(
            method="POST",
            url=self.token_endpoint,
            data=data,
            err_msg="Failed to exchange code for access token",
        )

    def refresh_token(self, refresh_token: str) -> dict:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        return self.oauth(
            method="POST",
            url=self.token_endpoint,
            data=data,
            err_msg="Failed to refresh token",
        )

    def get_user_info(self, access_token: str) -> dict:
        headers = {"Authorization": f"Bearer {access_token}"}
        return self.oauth(
            method="GET",
            url=self.user_info_endpoint,
            headers=headers,
            err_msg="Failed to fetch user info",
        )

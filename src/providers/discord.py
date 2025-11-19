"""
Discord OAuth 2.0 provider implementation.
"""

from .base import BaseProvider


class DiscordProvider(BaseProvider):
    """
    Discord OAuth 2.0 provider implementation.
    """

    SUPPORTS_REFRESH = True
    SUPPORTS_REVOCATION = True
    SUPPORTS_PKCE = False

    def __init__(
        self, client_id: str, client_secret: str, redirect_uri: str, scopes=None
    ):
        """
        Initialize Discord OAuth provider.

        Args:
            client_id: Discord OAuth client ID
            client_secret: Discord OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: List of scopes (defaults to identify, email)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["identify", "email"],
        )
        self.authorization_endpoint = "https://discord.com/api/oauth2/authorize"
        self.token_endpoint = "https://discord.com/api/oauth2/token"
        self.revocation_endpoint = "https://discord.com/api/oauth2/token/revoke"
        self.user_info_endpoint = "https://discord.com/api/users/@me"

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self.oauth(
            method="POST",
            url=self.token_endpoint,
            headers=headers,
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

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self.oauth(
            method="POST",
            url=self.token_endpoint,
            headers=headers,
            data=data,
            err_msg="Failed to refresh token",
        )

    def revoke_token(self, token: str) -> dict:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "token": token,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self.oauth(
            method="POST",
            url=self.revocation_endpoint,
            headers=headers,
            data=data,
            err_msg="Failed to revoke token",
        )

    def get_user_info(self, access_token: str) -> dict:
        headers = {"Authorization": f"Bearer {access_token}"}

        return self.oauth(
            method="GET",
            url=self.user_info_endpoint,
            headers=headers,
            err_msg="Failed to fetch user info",
        )

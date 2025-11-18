from .base import BaseProvider


class MicrosoftProvider(BaseProvider):
    """
    Microsoft OAuth 2.0 provider implementation.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes=None,
        tenant="common",
    ):
        """
        Initialize Microsoft OAuth provider.

        Args:
            client_id: Microsoft OAuth client ID
            client_secret: Microsoft OAuth client secret
            redirect_uri: Registered redirect URI
            scopes: List of scopes (defaults to openid, email, profile)
            tenant: Azure AD tenant ID (defaults to 'common' for multi-tenant)
        """
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or ["openid", "email", "profile"],
        )
        self.tenant = tenant
        self.authorization_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
        )
        self.token_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )
        self.revocation_endpoint = (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout"
        )
        self.user_info_endpoint = "https://graph.microsoft.com/v1.0/me"

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

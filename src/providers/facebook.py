from dataclasses import dataclass

from src.utils import make_request, OAuthError
from .base import BaseProvider


class FacebookProvider(BaseProvider):
    @dataclass
    class AccessTokenResponse:
        """
        A dataclass for structuring the access token response from Facebook.

        Attributes:
            access_token (str): The access token issued by the authorization server.
            token_type (str): The type of the token issued.
            expires_in (int): The lifetime in seconds of the access token.
        """
        access_token: str
        token_type: str
        expires_in: int

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes: list[str] = None):
        """
        Initializes the FacebookProvider with necessary OAuth 2.0 credentials and endpoints.

        Args:
            client_id (str): The client ID issued to the app by the Facebook Developer Console.
            client_secret (str): The client secret issued to the app by the Facebook Developer Console.
            redirect_uri (str): The URI to redirect to after the user authorizes the app.
            scopes (list[str], optional): The scopes of the access request.
        """

        super().__init__(client_id=client_id,
                         client_secret=client_secret,
                         redirect_uri=redirect_uri,
                         scopes=scopes or ['email', 'public_profile'])
        self.authorization_endpoint = "https://www.facebook.com/v20.0/dialog/oauth"
        self.token_endpoint = "https://graph.facebook.com/v20.0/oauth/access_token"
        self.revocation_endpoint = "https://graph.facebook.com/me/permissions"

    def exchange_code_for_access_token(self, code: str) -> dict:
        """
        Exchanges an authorization code for an access token.

        Args:
            code (str): The authorization code received from the authorization server.

        Returns:
            dict: The access token information as a dictionary.

        Raises:
            OAuthError: If the token exchange fails.
        """
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }

        response = make_request('GET', self.token_endpoint, params=params)
        if response and response.status_code == 200:
            return response.json()

        else:
            raise OAuthError("Unable to exchange code for access token")

    def revoke_token(self, token):
        """
        Revokes the given access token.

        Args:
            token (str): The access token to be revoked.

        Returns:
            The response from the token revocation endpoint.
        """
        data = {'access_token': token}
        return make_request('DELETE', self.revocation_endpoint, data=data)

    def parse_access_token_response(self, response: dict) -> AccessTokenResponse:
        """
        Parses the access token response into an AccessTokenResponse dataclass.

        Args:
            response (dict): The raw access token response from the token endpoint.

        Returns:
            AccessTokenResponse: The parsed access token response.
        """
        keys = ['access_token', 'token_type', 'expires_in']

        if not all(key in response for key in keys):
            raise ValueError("Invalid access token response from Facebook")

        return self.AccessTokenResponse(
            access_token=response['access_token'],
            token_type=response['token_type'],
            expires_in=response['expires_in']
        )

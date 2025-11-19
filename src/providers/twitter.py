import base64

from src.utils import make_request
from .base import BaseProvider


class TwitterProvider(BaseProvider):
    """
    Twitter OAuth 2.0 provider implementation with PKCE support.

    Twitter requires PKCE (Proof Key for Code Exchange) for all OAuth 2.0 flows.
    The code verifier and challenge are automatically generated when calling
    prepare_auth_url().
    """

    SUPPORTS_REFRESH = False
    SUPPORTS_REVOCATION = True
    SUPPORTS_PKCE = True

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes: list[str] = None):
        """
        Initializes the TwitterProvider with necessary OAuth 2.0 credentials and endpoints.

        Args:
            client_id (str): The client ID issued to the app by the Twitter Developer Console.
            client_secret (str): The client secret issued to the app by the Twitter Developer Console.
            redirect_uri (str): The URI to redirect to after the user authorizes the app.
            scopes (list[str], optional): The scopes of the access request.
        """
        super().__init__(client_id=client_id,
                         client_secret=client_secret,
                         redirect_uri=redirect_uri,
                         scopes=scopes or ['tweet.read', 'users.read', 'follows.read', 'follows.write'])
        self.authorization_endpoint = "https://twitter.com/i/oauth2/authorize"
        self.token_endpoint = "https://api.twitter.com/2/oauth2/token"
        self.revocation_endpoint = "https://api.twitter.com/2/oauth2/revoke"
        self.code_challenge_method = 'S256'

    def prepare_auth_url(self, additional_params: dict[str, str] = None) -> str:
        """
        Prepares the authorization URL for the OAuth provider.

        This method generates a code verifier and a code challenge for PKCE and includes them in the
        authorization URL.

        Args:
            additional_params (dict[str, str], optional): Additional parameters to include in the URL.

        Returns:
            str: The authorization URL for the OAuth provider
        """
        # Use the base class method to generate PKCE parameters
        self.generate_pkce_parameters(length=64, method='S256')

        additional_params = additional_params if additional_params else {}
        additional_params.update({
            'code_challenge': self.code_challenge,
            'code_challenge_method': self.code_challenge_method,
        })

        return super().prepare_auth_url(additional_params)

    def exchange_code_for_access_token_pkce(self, code: str, code_verifier: str) -> dict[str]:
        """
        Exchanges an authorization code for an access token.

        Args:
            code (str): The authorization code received from the authorization server.
            code_verifier (str): The code verifier used to generate the code challenge.

        Returns:
            AccessTokenResponse: The access token response dataclass.

        Raises:
            OAuthError: If the token exchange fails.
        """

        headers = self._get_authorization_header()
        data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }

        response = make_request('POST', self.token_endpoint, headers=headers, data=data)
        return self.validate_response_or_raise(response, "Failed to exchange code for access token")

    def revoke_token(self, token: str) -> dict:
        """
        Revokes the given access token.

        Args:
            token (str): The access token to be revoked.

        Returns:
            dict: The response from the token revocation endpoint.

        Raises:
            OAuthError: If the token revocation fails.
        """
        headers = self._get_authorization_header()
        data = {'token': token, 'token_type_hint': 'access_token'}

        response = make_request('POST', self.revocation_endpoint, headers=headers, data=data)
        return self.validate_response_or_raise(response, "Unable to revoke token")

    def _get_authorization_header(self) -> dict[str, str]:
        """
        Generates the authorization header required for making requests to the OAuth server.

        This method encodes the client ID and client secret using Base64 and formats them
        according to the Basic Authentication standard.

        Returns:
            dict[str, str]: A dictionary containing the 'Content-Type' and 'Authorization'
            headers, ready to be used in a request.
        """
        auth_header = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Basic {auth_header}'
        }
        return headers

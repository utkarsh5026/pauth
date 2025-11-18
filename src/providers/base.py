import json
import secrets
import requests
from urllib.parse import urlencode
from typing import Optional
from exceptions import PAuthError


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

    Methods:
        exchange_code_for_access_token(code: str) -> dict: Abstract method to be implemented by subclasses
            for exchanging an authorization code for an access token.
    """

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
        self.state = None

    def exchange_code_for_access_token(self, code: str, **kwargs) -> dict:
        raise NotImplementedError()

    def exchange_code_for_access_token_pkce(self, code: str, code_verifier: str):
        raise NotImplementedError()

    def prepare_auth_url(self, additional_params: Optional[dict[str, str]] = None):
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

    def get_auth_endpoint(self):
        if not self.authorization_endpoint:
            raise ValueError("Authorization endpoint is not set for this provider")
        return self.authorization_endpoint

    @staticmethod
    def create_state() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def try_reading_response(response: requests.Response | None) -> dict[str, str]:
        if response and response.status_code == 200:
            try:
                return json.loads(response.json())
            except ValueError:
                return {}
        else:
            raise PAuthError("Response from the server was not successful")

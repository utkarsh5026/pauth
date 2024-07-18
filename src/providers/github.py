import base64
import http
import json

from src.utils import make_request
from .base import BaseProvider


class GithubProvider(BaseProvider):

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes=None):
        super().__init__(client_id=client_id,
                         client_secret=client_secret,
                         redirect_uri=redirect_uri,
                         scopes=scopes or ['read:user', 'user:email'])
        self.authorization_endpoint = "https://github.com/login/oauth/authorize"
        self.token_endpoint = "https://github.com/login/oauth/access_token"
        self.revocation_endpoint = "https://api.github.com/applications/{client_id}/token"

    def revoke_token(self, token):
        headers = {
            'Authorization': f'Basic {base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()}',
            'Accept': 'application/vnd.github.v3+json'
        }
        data = {'access_token': token}
        return make_request('DELETE', self.revocation_endpoint.format(client_id=self.client_id), headers=headers,
                            data=data)

    def exchange_code_for_access_token(self, code: str):
        headers = {
            'Accept': 'application/json',
        }

        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri
        }

        response = make_request('POST', self.token_endpoint, headers=headers, data=data)

        if response and response.status_code == http.HTTPStatus.OK:
            try:
                resp_data = response.json()
                return json.loads(resp_data)
            except json.JSONDecodeError:
                raise ValueError("Unable to decode response from Github")

        return None

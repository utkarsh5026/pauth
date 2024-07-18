from .base import BaseProvider


class GoogleProvider(BaseProvider):

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, scopes=None):
        super().__init__(client_id=client_id,
                         client_secret=client_secret,
                         redirect_uri=redirect_uri,
                         scopes=scopes or ['openid', 'email', 'profile'])
        self.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        self.token_endpoint = "https://oauth2.googleapis.com/token"
        self.revocation_endpoint = "https://oauth2.googleapis.com/revoke"

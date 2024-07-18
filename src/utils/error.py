class OAuthError(Exception):

    def __int__(self, message: str):
        self.message = message
        super().__init__(message)

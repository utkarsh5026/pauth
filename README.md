# PAuth: Making OAuth 2.0 Authentication Simple

Welcome to PAuth, a modern Python library that takes the complexity out of OAuth 2.0 authentication. Whether you're building a small Flask application or a large Django project, PAuth provides a clean, consistent, and secure way to handle authentication with popular OAuth providers.

## Why PAuth?

OAuth 2.0 implementation can be tricky. You need to manage authorization flows, handle tokens securely, validate states, and deal with different provider quirks. PAuth handles all of this for you while providing:

- 🔐 **Complete OAuth 2.0 Implementation**: All the standard flows, with modern security features built in
- 🌐 **Multiple Provider Support**: One consistent interface for all major OAuth providers
- 🛠️ **Framework Integration**: Seamless integration with Flask and Django
- 🔒 **Security First**: Built-in PKCE support, state validation, and secure token handling
- 💡 **Developer-Friendly**: Clear APIs, comprehensive error handling, and TypeScript-style hints

## Quick Start

Let's get you authenticating in minutes:

```bash
# Basic installation
pip install pauth

# With framework support
pip install pauth[flask]    # For Flask applications
pip install pauth[django]   # For Django applications
```

### Basic Usage

Here's a simple example using Google OAuth:

```python
from pauth import OAuth2Client, Providers

# Initialize the client
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

# Get the authorization URL
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    state="your_secure_state"  # PAuth can generate this for you
)

# Later, in your callback handler...
tokens = client.exchange_code(
    code="authorization_code_from_callback",
    state="your_secure_state"  # Validate the state
)

# Access user information
user_info = client.get_user_info(tokens.access_token)
```

### Flask Integration

PAuth makes Flask integration smooth and simple:

```python
from flask import Flask, redirect, request
from pauth.integrations.flask import FlaskOAuth

app = Flask(__name__)
oauth = FlaskOAuth(
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)

@app.route('/login')
def login():
    return redirect(oauth.get_authorization_url())

@app.route('/callback')
def callback():
    tokens = oauth.handle_callback(request)
    user = oauth.get_user_info(tokens.access_token)
    # Handle user login in your application
    return f"Welcome, {user.name}!"
```

### Django Integration

For Django applications, PAuth provides a seamless experience:

```python
# settings.py
INSTALLED_APPS = [
    ...
    'pauth.integrations.django',
]

PAUTH_CONFIG = {
    'PROVIDERS': {
        'google': {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'redirect_uri': 'http://localhost:8000/oauth/callback',
        }
    }
}

# urls.py
from django.urls import path, include

urlpatterns = [
    path('oauth/', include('pauth.integrations.django.urls')),
]

# views.py
from pauth.integrations.django import oauth

def login(request):
    return oauth.redirect_to_provider('google')

def callback(request):
    user_info = oauth.handle_callback(request)
    # Handle user login in your application
```

## Advanced Features

### PKCE Support

PAuth implements PKCE (Proof Key for Code Exchange) for enhanced security:

```python
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_client_id",
    use_pkce=True  # Enable PKCE
)

# PAuth handles code verifier generation and challenge creation
auth_url = client.get_authorization_url(scope=["user"])
```

### Custom Token Storage

Implement custom token storage for your specific needs:

```python
from pauth.storage import BaseTokenStorage

class RedisTokenStorage(BaseTokenStorage):
    def __init__(self, redis_client):
        self.redis = redis_client

    def save_token(self, user_id: str, tokens: dict):
        self.redis.hmset(f"user:{user_id}:tokens", tokens)

    def get_token(self, user_id: str) -> dict:
        return self.redis.hgetall(f"user:{user_id}:tokens")

    def delete_token(self, user_id: str):
        self.redis.delete(f"user:{user_id}:tokens")

# Use your custom storage
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    token_storage=RedisTokenStorage(redis_client)
)
```

### Error Handling

PAuth provides comprehensive error handling:

```python
from pauth.exceptions import (
    AuthorizationError,
    TokenError,
    InvalidStateError,
    ProviderError
)

try:
    tokens = client.exchange_code(code, state)
except AuthorizationError as e:
    # Handle authorization errors (e.g., invalid code)
    print(f"Authorization failed: {e}")
except TokenError as e:
    # Handle token-related errors
    print(f"Token error: {e}")
except InvalidStateError as e:
    # Handle state validation errors
    print(f"State validation failed: {e}")
except ProviderError as e:
    # Handle provider-specific errors
    print(f"Provider error: {e}")
```


## Future Development

PAuth is actively developing new features:

### Upcoming Providers
- Microsoft OAuth integration
- LinkedIn authentication
- Discord OAuth support
- Apple Sign-In

### Framework Support
- FastAPI integration
- aiohttp support
- Starlette compatibility

### Enhanced Features
- Automatic token refresh
- Rate limiting support
- More storage backends
- Enhanced token encryption



## License

PAuth is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## About the Author

PAuth is created and maintained by Utkarsh Priyadarshi (utkarshpriyadarshi5026@gmail.com), a passionate developer focused on making authentication simpler and more secure for Python applications.

Need help or have questions? Feel free to:
- Open an issue on GitHub
- Send me an email
- Join our Discord community

Your feedback and contributions help make PAuth better for everyone!
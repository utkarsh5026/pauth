# Configuration

Learn how to configure PAuth for different environments and use cases.

## Client Configuration

The `OAuth2Client` is the main entry point for PAuth. Here are all the configuration options:

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GOOGLE,        # The OAuth provider
    client_id="your_client_id",       # OAuth client ID
    client_secret="your_client_secret", # OAuth client secret
    redirect_uri="http://localhost:5000/callback", # Callback URL
    use_pkce=True,                    # Enable PKCE (default: False)
    token_storage=custom_storage      # Custom token storage (optional)
)
```

### Required Parameters

- `provider`: The OAuth provider to use (from `Providers` enum)
- `client_id`: Your application's client ID from the provider
- `client_secret`: Your application's client secret from the provider
- `redirect_uri`: The callback URL where users will be redirected after authorization

### Optional Parameters

- `use_pkce`: Enable PKCE for enhanced security (recommended for public clients)
- `token_storage`: Custom token storage implementation (defaults to in-memory storage)

## Provider Configuration

Each provider has specific requirements and configuration options.

### Google

```python
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_google_client_id.apps.googleusercontent.com",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

# Common scopes for Google
scopes = ["openid", "email", "profile"]
```

### GitHub

```python
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_github_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

# Common scopes for GitHub
scopes = ["user", "user:email"]
```

### Facebook

```python
client = OAuth2Client(
    provider=Providers.FACEBOOK,
    client_id="your_facebook_app_id",
    client_secret="your_app_secret",
    redirect_uri="https://your-app.com/callback"
)

# Common scopes for Facebook
scopes = ["email", "public_profile"]
```

## Environment Variables

It's best practice to store sensitive credentials in environment variables:

```python
import os
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri=os.getenv("OAUTH_REDIRECT_URI")
)
```

### Example .env File

```bash
# .env
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_secret
OAUTH_REDIRECT_URI=http://localhost:5000/callback
```

!!! warning "Security"
    Never commit your `.env` file or credentials to version control. Add `.env` to your `.gitignore` file.

## Configuration for Different Environments

### Development

```python
# config/development.py
from pauth import OAuth2Client, Providers

def get_oauth_client():
    return OAuth2Client(
        provider=Providers.GOOGLE,
        client_id="dev_client_id",
        client_secret="dev_client_secret",
        redirect_uri="http://localhost:5000/callback",
        use_pkce=False  # Can be disabled in dev for easier testing
    )
```

### Production

```python
# config/production.py
import os
from pauth import OAuth2Client, Providers
from myapp.storage import RedisTokenStorage

def get_oauth_client():
    return OAuth2Client(
        provider=Providers.GOOGLE,
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        redirect_uri=os.getenv("OAUTH_REDIRECT_URI"),
        use_pkce=True,  # Always enable in production
        token_storage=RedisTokenStorage()  # Use persistent storage
    )
```

## PKCE Configuration

PKCE (Proof Key for Code Exchange) adds an extra layer of security:

```python
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    use_pkce=True  # Enable PKCE
)
```

When enabled, PAuth automatically:

- Generates a code verifier
- Creates a code challenge
- Includes the challenge in the authorization URL
- Sends the verifier during token exchange

Learn more in the [PKCE Guide](../advanced/pkce.md).

## Custom Token Storage

Configure custom token storage for production use:

```python
from pauth import OAuth2Client, Providers
from pauth.storage import BaseTokenStorage

class DatabaseTokenStorage(BaseTokenStorage):
    def save_token(self, user_id: str, tokens: dict):
        # Save to database
        pass

    def get_token(self, user_id: str) -> dict:
        # Retrieve from database
        pass

    def delete_token(self, user_id: str):
        # Delete from database
        pass

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    token_storage=DatabaseTokenStorage()
)
```

Learn more in the [Token Storage Guide](../advanced/token-storage.md).

## Next Steps

- [Quick Start Guide](quick-start.md) - Build your first integration
- [Provider Guides](../providers/overview.md) - Provider-specific configuration
- [Framework Integrations](../integrations/flask.md) - Flask and Django setup

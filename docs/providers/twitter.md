# Twitter OAuth 2.0

Twitter OAuth 2.0 provides access to Twitter's API and user data.

## Setup

### 1. Create Twitter App

1. Go to [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard)
2. Create a new project and app
3. Note your Client ID and Client Secret
4. Add callback URLs in app settings

### 2. Initialize the Client

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.TWITTER,
    client_id="your_twitter_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Common Scopes

| Scope | Description |
|-------|-------------|
| `tweet.read` | Read tweets |
| `tweet.write` | Post tweets |
| `users.read` | Read user profile |
| `offline.access` | Get refresh token |

## Resources

- [Twitter OAuth 2.0 Documentation](https://developer.twitter.com/en/docs/authentication/oauth-2-0)

# Provider Overview

PAuth supports multiple OAuth 2.0 providers, each with a consistent API while handling provider-specific details behind the scenes.

## Supported Providers

| Provider | Status | Documentation |
|----------|--------|---------------|
| Google | ✅ Available | [Guide](google.md) |
| GitHub | ✅ Available | [Guide](github.md) |
| Facebook | ✅ Available | [Guide](facebook.md) |
| Twitter | ✅ Available | [Guide](twitter.md) |
| Microsoft | ✅ Available | [Guide](microsoft.md) |
| LinkedIn | ✅ Available | [Guide](linkedin.md) |
| Discord | ✅ Available | [Guide](discord.md) |

## Common Usage Pattern

All providers follow the same basic pattern:

```python
from pauth import OAuth2Client, Providers

# 1. Initialize client
client = OAuth2Client(
    provider=Providers.GOOGLE,  # Change this to any supported provider
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

# 2. Generate authorization URL
auth_url = client.get_authorization_url(
    scope=["scope1", "scope2"],
    state="secure_random_state"
)

# 3. Exchange code for tokens
tokens = client.exchange_code(code="auth_code", state="secure_random_state")

# 4. Get user information
user_info = client.get_user_info(tokens.access_token)
```

## Provider-Specific Differences

While the API is consistent, each provider has:

- **Different scopes**: Each provider uses different scope names
- **Different user info fields**: The structure of user data varies
- **Different token lifetimes**: Access token expiration times differ
- **Different refresh token policies**: Some providers don't issue refresh tokens by default

## Choosing a Provider

Consider these factors when choosing a provider:

### Google OAuth

- ✅ Wide adoption
- ✅ Good documentation
- ✅ Reliable service
- ✅ Refresh tokens available
- Use for: General purpose authentication

### GitHub OAuth

- ✅ Developer-focused
- ✅ Simple scopes
- ✅ Good for dev tools
- ❌ No refresh tokens
- Use for: Developer tools, code-related apps

### Facebook Login

- ✅ Large user base
- ✅ Rich profile data
- ⚠️ Complex permissions
- Use for: Social apps, general authentication

### Twitter OAuth

- ✅ Real-time data
- ✅ OAuth 2.0 support
- Use for: Social apps, content platforms

### Microsoft OAuth

- ✅ Enterprise support
- ✅ Azure AD integration
- ✅ Office 365 integration
- Use for: Enterprise apps, B2B

### LinkedIn OAuth

- ✅ Professional network
- ✅ Business context
- Use for: Professional networking, B2B

### Discord OAuth

- ✅ Gaming community
- ✅ Rich presence data
- Use for: Gaming apps, community platforms

## Getting Provider Credentials

Each provider requires you to register your application:

1. **Google**: [Google Cloud Console](https://console.cloud.google.com/)
2. **GitHub**: [GitHub OAuth Apps](https://github.com/settings/developers)
3. **Facebook**: [Facebook Developers](https://developers.facebook.com/)
4. **Twitter**: [Twitter Developer Portal](https://developer.twitter.com/)
5. **Microsoft**: [Azure Portal](https://portal.azure.com/)
6. **LinkedIn**: [LinkedIn Developers](https://www.linkedin.com/developers/)
7. **Discord**: [Discord Developer Portal](https://discord.com/developers/applications)

## Next Steps

Choose a provider and read its specific guide:

- [Google OAuth Guide](google.md)
- [GitHub OAuth Guide](github.md)
- [Facebook OAuth Guide](facebook.md)
- [Twitter OAuth Guide](twitter.md)
- [Microsoft OAuth Guide](microsoft.md)
- [LinkedIn OAuth Guide](linkedin.md)
- [Discord OAuth Guide](discord.md)

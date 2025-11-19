# GitHub OAuth

GitHub OAuth is popular for developer tools and applications that need access to GitHub resources.

## Setup

### 1. Create OAuth App

1. Go to [GitHub Settings > Developer settings > OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details
4. Set the Authorization callback URL (e.g., `http://localhost:5000/callback`)
5. Note your Client ID and Client Secret

### 2. Initialize the Client

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_github_client_id",
    client_secret="your_github_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Common Scopes

| Scope | Description |
|-------|-------------|
| `user` | Read/write access to profile info |
| `user:email` | Access user email addresses |
| `user:follow` | Access following/followers |
| `repo` | Full control of repositories |
| `public_repo` | Access public repositories |
| `read:org` | Read org and team membership |

### Example with Scopes

```python
auth_url = client.get_authorization_url(
    scope=["user", "user:email"]
)
```

## User Information

GitHub returns the following user information:

```python
user_info = client.get_user_info(access_token)

# Available fields:
print(user_info.id)           # GitHub user ID
print(user_info.login)        # Username
print(user_info.name)         # Display name
print(user_info.email)        # Primary email
print(user_info.avatar_url)   # Profile picture
print(user_info.bio)          # User bio
print(user_info.company)      # Company name
print(user_info.location)     # Location
```

## Complete Example

```python
from pauth import OAuth2Client, Providers

# Initialize client
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_github_client_id",
    client_secret="your_github_client_secret",
    redirect_uri="http://localhost:5000/callback"
)

# Get authorization URL
auth_url = client.get_authorization_url(
    scope=["user", "user:email"],
    state="secure_random_state"
)

# Exchange code for tokens
tokens = client.exchange_code(
    code="authorization_code",
    state="secure_random_state"
)

# Get user information
user_info = client.get_user_info(tokens.access_token)
print(f"Logged in as: {user_info.name} (@{user_info.login})")
```

## Important Notes

!!! warning "No Refresh Tokens"
    GitHub OAuth does not provide refresh tokens. Access tokens are long-lived and do not expire automatically.

## Best Practices

1. **Request minimal scopes** - GitHub users are security-conscious
2. **Use HTTPS** in production
3. **Store access tokens securely**
4. **Verify email scope** separately if needed

## Resources

- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [GitHub OAuth Scopes](https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps)

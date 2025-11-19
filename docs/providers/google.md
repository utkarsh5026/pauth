# Google OAuth

Google OAuth is one of the most popular authentication providers, offering reliable service and comprehensive documentation.

## Setup

### 1. Create OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Web application"
6. Add your redirect URI (e.g., `http://localhost:5000/callback`)
7. Note your Client ID and Client Secret

### 2. Initialize the Client

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id.apps.googleusercontent.com",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Common Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Required for OpenID Connect |
| `email` | Access user's email address |
| `profile` | Access basic profile information |
| `https://www.googleapis.com/auth/userinfo.profile` | Extended profile info |
| `https://www.googleapis.com/auth/userinfo.email` | Extended email info |

### Example with Scopes

```python
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"]
)
```

## User Information

Google returns the following user information:

```python
user_info = client.get_user_info(access_token)

# Available fields:
print(user_info.id)           # Google user ID
print(user_info.email)        # Email address
print(user_info.name)         # Full name
print(user_info.picture)      # Profile picture URL
print(user_info.given_name)   # First name
print(user_info.family_name)  # Last name
print(user_info.locale)       # User locale
```

## Complete Example

```python
from pauth import OAuth2Client, Providers
from pauth.exceptions import AuthorizationError

# Initialize client
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id.apps.googleusercontent.com",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback",
    use_pkce=True  # Recommended for enhanced security
)

# Get authorization URL
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    state="secure_random_state"
)

print(f"Visit: {auth_url}")

# After user authorizes, exchange code for tokens
try:
    tokens = client.exchange_code(
        code="authorization_code",
        state="secure_random_state"
    )

    # Get user information
    user_info = client.get_user_info(tokens.access_token)
    print(f"Logged in as: {user_info.name} ({user_info.email})")

except AuthorizationError as e:
    print(f"Authorization failed: {e}")
```

## Token Refresh

Google provides refresh tokens that can be used to get new access tokens:

```python
# Refresh the access token
new_tokens = client.refresh_token(tokens.refresh_token)
```

!!! note "Refresh Token Availability"
    Refresh tokens are only issued on the first authorization. To get a new refresh token, add `access_type=offline` and `prompt=consent` to the authorization URL.

## Advanced Configuration

### Request Offline Access

```python
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    state="secure_random_state",
    extra_params={
        "access_type": "offline",  # Request refresh token
        "prompt": "consent"         # Force consent screen
    }
)
```

### Force Account Selection

```python
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    extra_params={
        "prompt": "select_account"  # Show account selector
    }
)
```

## Best Practices

1. **Always use HTTPS** in production
2. **Enable PKCE** for enhanced security
3. **Request minimal scopes** - only what you need
4. **Store tokens securely** - never expose them client-side
5. **Handle token expiration** - implement refresh token flow
6. **Verify email** - check `email_verified` claim if using OpenID Connect

## Common Issues

### Issue: "redirect_uri_mismatch"

**Cause**: The redirect URI doesn't match what's registered in Google Cloud Console.

**Solution**: Ensure the redirect URI in your code exactly matches the one in the console, including the protocol (http/https) and trailing slashes.

### Issue: "invalid_grant"

**Cause**: Authorization code has expired or was already used.

**Solution**: Authorization codes are single-use and expire quickly. Ensure you exchange them immediately.

## Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OpenID Connect](https://developers.google.com/identity/protocols/oauth2/openid-connect)

# Quick Start

This guide will walk you through creating your first OAuth integration with PAuth.

## Basic OAuth Flow

Let's implement a basic OAuth flow with Google as the provider.

### Step 1: Import PAuth

```python
from pauth import OAuth2Client, Providers
```

### Step 2: Initialize the Client

```python
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_google_client_id",
    client_secret="your_google_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

!!! tip "Getting OAuth Credentials"
    You'll need to register your application with the OAuth provider to get client credentials:

    - [Google OAuth Console](https://console.developers.google.com/)
    - [GitHub OAuth Apps](https://github.com/settings/developers)
    - [Facebook Developers](https://developers.facebook.com/)

### Step 3: Generate Authorization URL

```python
# Generate the authorization URL
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    state="random_secure_state_string"  # Important for security
)

# Redirect the user to this URL
print(f"Please visit: {auth_url}")
```

### Step 4: Handle the Callback

After the user authorizes your application, they'll be redirected back to your `redirect_uri` with an authorization code:

```python
# Extract the code and state from the callback URL
# In a real application, you'd get these from request parameters
authorization_code = "code_from_callback_url"
state = "state_from_callback_url"

# Exchange the code for tokens
tokens = client.exchange_code(
    code=authorization_code,
    state=state
)

# Access the tokens
print(f"Access Token: {tokens.access_token}")
print(f"Refresh Token: {tokens.refresh_token}")
print(f"Expires In: {tokens.expires_in} seconds")
```

### Step 5: Get User Information

```python
# Fetch user information using the access token
user_info = client.get_user_info(tokens.access_token)

print(f"User ID: {user_info.id}")
print(f"Name: {user_info.name}")
print(f"Email: {user_info.email}")
```

## Complete Example

Here's a complete example putting it all together:

```python
from pauth import OAuth2Client, Providers
from pauth.exceptions import AuthorizationError, TokenError

# Initialize the client
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)

# Step 1: Generate authorization URL
auth_url = client.get_authorization_url(
    scope=["openid", "email", "profile"],
    state="secure_random_state"
)
print(f"Visit this URL to authorize: {auth_url}")

# Step 2: After user authorizes, exchange the code for tokens
try:
    tokens = client.exchange_code(
        code="authorization_code_from_callback",
        state="secure_random_state"
    )

    # Step 3: Get user information
    user_info = client.get_user_info(tokens.access_token)

    print(f"Successfully authenticated user: {user_info.name}")

except AuthorizationError as e:
    print(f"Authorization failed: {e}")
except TokenError as e:
    print(f"Token exchange failed: {e}")
```

## Framework Integration

For production applications, you'll typically want to use PAuth with a web framework:

- **Flask**: See the [Flask Integration Guide](../integrations/flask.md)
- **Django**: See the [Django Integration Guide](../integrations/django.md)

## Security Considerations

!!! warning "Important Security Notes"
    - Always use HTTPS in production
    - Generate secure random strings for the `state` parameter
    - Store tokens securely (never in client-side code)
    - Consider using PKCE for enhanced security
    - Validate the `state` parameter to prevent CSRF attacks

Learn more about security best practices in the [Security Guide](../advanced/security.md).

## Next Steps

Now that you've created your first OAuth integration:

- Explore [PKCE Support](../advanced/pkce.md) for enhanced security
- Learn about [Token Storage](../advanced/token-storage.md) options
- Check out provider-specific guides in the [Providers](../providers/overview.md) section

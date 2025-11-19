# Facebook Login

Facebook Login provides access to Facebook's vast user base for authentication.

## Setup

### 1. Create Facebook App

1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Click "My Apps" > "Create App"
3. Select "Consumer" or appropriate type
4. Fill in app details
5. Add "Facebook Login" product
6. Configure OAuth redirect URIs in Settings > Basic
7. Note your App ID and App Secret

### 2. Initialize the Client

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.FACEBOOK,
    client_id="your_facebook_app_id",
    client_secret="your_app_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Common Scopes

| Scope | Description |
|-------|-------------|
| `email` | Access user's email address |
| `public_profile` | Access basic profile info |
| `user_friends` | Access friend list |
| `user_photos` | Access user photos |
| `user_posts` | Access user posts |

### Example with Scopes

```python
auth_url = client.get_authorization_url(
    scope=["email", "public_profile"]
)
```

## User Information

```python
user_info = client.get_user_info(access_token)

# Available fields:
print(user_info.id)        # Facebook user ID
print(user_info.name)      # Full name
print(user_info.email)     # Email address
print(user_info.picture)   # Profile picture URL
```

## Best Practices

1. **Request minimal permissions** - Users are wary of excessive permissions
2. **Use HTTPS** in production
3. **Handle permission denial gracefully**
4. **Keep app in development mode** until ready for review

## Resources

- [Facebook Login Documentation](https://developers.facebook.com/docs/facebook-login)
- [Facebook Permissions Reference](https://developers.facebook.com/docs/permissions/reference)

# PAuth: Making OAuth 2.0 Authentication Simple

Welcome to PAuth, a modern Python library that takes the complexity out of OAuth 2.0 authentication. Whether you're building a small Flask application or a large Django project, PAuth provides a clean, consistent, and secure way to handle authentication with popular OAuth providers.

## Why PAuth?

OAuth 2.0 implementation can be tricky. You need to manage authorization flows, handle tokens securely, validate states, and deal with different provider quirks. PAuth handles all of this for you while providing:

- **Complete OAuth 2.0 Implementation**: All the standard flows, with modern security features built in
- **Multiple Provider Support**: One consistent interface for all major OAuth providers
- **Framework Integration**: Seamless integration with Flask and Django
- **Security First**: Built-in PKCE support, state validation, and secure token handling
- **Developer-Friendly**: Clear APIs, comprehensive error handling, and type hints

## Supported Providers

PAuth currently supports authentication with:

- Google OAuth 2.0
- GitHub OAuth
- Facebook Login
- Twitter OAuth 2.0
- Microsoft Azure AD
- LinkedIn OAuth
- Discord OAuth

## Quick Example

Here's how simple OAuth can be with PAuth:

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
    scope=["openid", "email", "profile"]
)

# Exchange the authorization code for tokens
tokens = client.exchange_code(code="authorization_code")

# Access user information
user_info = client.get_user_info(tokens.access_token)
print(f"Welcome, {user_info.name}!")
```

## Getting Started

Ready to integrate OAuth into your application? Check out our guides:

- [Installation](getting-started/installation.md) - Get PAuth installed in your project
- [Quick Start](getting-started/quick-start.md) - Your first OAuth integration
- [Configuration](getting-started/configuration.md) - Configure PAuth for your needs

## Framework Integrations

PAuth provides seamless integration with popular Python web frameworks:

- [Flask Integration](integrations/flask.md) - Flask-specific OAuth helpers
- [Django Integration](integrations/django.md) - Django app for OAuth

## Features

### Security First

PAuth implements modern security best practices:

- PKCE (Proof Key for Code Exchange) support
- State parameter validation
- Secure token storage options
- Token refresh handling

[Learn more about security features →](advanced/security.md)

### Flexible Storage

Choose how and where to store your tokens:

- In-memory storage for development
- Custom storage backends for production
- Easy integration with databases, Redis, or any storage system

[Explore token storage options →](advanced/token-storage.md)

### Comprehensive Error Handling

PAuth provides clear, actionable error messages:

```python
from pauth.exceptions import AuthorizationError, TokenError

try:
    tokens = client.exchange_code(code, state)
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
except TokenError as e:
    print(f"Token error: {e}")
```

[Read about error handling →](advanced/error-handling.md)

## API Reference

For detailed API documentation, see:

- [OAuth2Client](api/client.md) - Main client class
- [Providers](api/providers.md) - Provider implementations
- [Models](api/models.md) - Data models
- [Storage](api/storage.md) - Token storage interfaces
- [Exceptions](api/exceptions.md) - Exception classes

## Contributing

PAuth is an open-source project, and we welcome contributions! Check out our [contributing guide](contributing.md) to get started.

## License

PAuth is licensed under the Apache License 2.0. See the [LICENSE](https://github.com/utkarsh5026/pauth/blob/main/LICENSE) file for details.

## Support

Need help or have questions?

- Open an issue on [GitHub](https://github.com/utkarsh5026/pauth/issues)
- Email: [utkarshpriyadarshi5026@gmail.com](mailto:utkarshpriyadarshi5026@gmail.com)

Your feedback and contributions help make PAuth better for everyone!

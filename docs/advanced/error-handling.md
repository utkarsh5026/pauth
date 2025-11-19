# Error Handling

PAuth provides comprehensive error handling to help you build robust OAuth integrations.

## Exception Hierarchy

```python
from pauth.exceptions import (
    PAuthError,           # Base exception
    AuthorizationError,   # Authorization failures
    TokenError,           # Token exchange failures
    InvalidStateError,    # State validation failures
    ProviderError         # Provider-specific errors
)
```

## Common Exceptions

### AuthorizationError

Raised when authorization fails:

```python
from pauth import OAuth2Client, Providers
from pauth.exceptions import AuthorizationError

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

try:
    tokens = client.exchange_code(code="invalid_code", state="state")
except AuthorizationError as e:
    print(f"Authorization failed: {e}")
    # Handle: redirect to login, show error message, etc.
```

**Common causes:**
- Invalid authorization code
- Expired authorization code
- Code already used
- Mismatched redirect URI

### TokenError

Raised during token operations:

```python
from pauth.exceptions import TokenError

try:
    tokens = client.exchange_code(code=code, state=state)
except TokenError as e:
    print(f"Token error: {e}")
    # Handle: retry, show error, log incident
```

**Common causes:**
- Network failures
- Invalid client credentials
- Token endpoint unavailable
- Malformed token response

### InvalidStateError

Raised when state validation fails:

```python
from pauth.exceptions import InvalidStateError

try:
    tokens = client.exchange_code(code=code, state="wrong_state")
except InvalidStateError as e:
    print(f"State validation failed: {e}")
    # Handle: potential CSRF attack, reject request
```

**Common causes:**
- State parameter mismatch
- Missing state parameter
- Session expired
- Potential CSRF attack

### ProviderError

Raised for provider-specific errors:

```python
from pauth.exceptions import ProviderError

try:
    user_info = client.get_user_info(access_token)
except ProviderError as e:
    print(f"Provider error: {e}")
    print(f"Provider: {e.provider}")
    print(f"Error code: {e.error_code}")
    # Handle: check provider status, retry later
```

## Complete Error Handling Example

```python
from pauth import OAuth2Client, Providers
from pauth.exceptions import (
    AuthorizationError,
    TokenError,
    InvalidStateError,
    ProviderError,
    PAuthError
)

client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
)

try:
    # Exchange authorization code
    tokens = client.exchange_code(code=code, state=state)

    # Get user information
    user_info = client.get_user_info(tokens.access_token)

    # Success!
    print(f"Welcome, {user_info.name}!")

except InvalidStateError:
    # Potential CSRF attack
    return "Security error: Invalid state parameter", 403

except AuthorizationError as e:
    # Authorization failed
    return f"Authorization failed: {str(e)}", 401

except TokenError as e:
    # Token exchange failed
    return f"Token error: {str(e)}", 500

except ProviderError as e:
    # Provider-specific error
    return f"Provider error: {str(e)}", 502

except PAuthError as e:
    # Catch-all for other PAuth errors
    return f"Authentication error: {str(e)}", 500

except Exception as e:
    # Unexpected error
    return f"Unexpected error: {str(e)}", 500
```

## Error Response Handling

Handle error responses from OAuth providers:

```python
def handle_oauth_callback(request):
    # Check for error in callback
    error = request.args.get('error')
    if error:
        error_description = request.args.get('error_description', '')

        if error == 'access_denied':
            return "User denied access", 403

        elif error == 'server_error':
            return "Provider error, please try again", 502

        else:
            return f"OAuth error: {error} - {error_description}", 400

    # Continue with normal flow
    code = request.args.get('code')
    # ...
```

## Logging Errors

Implement proper error logging:

```python
import logging

logger = logging.getLogger(__name__)

try:
    tokens = client.exchange_code(code=code, state=state)
except AuthorizationError as e:
    logger.error(f"Authorization failed for user: {e}", exc_info=True)
    # Don't log sensitive data!
except Exception as e:
    logger.exception("Unexpected OAuth error")
    raise
```

## Retry Logic

Implement retry logic for transient errors:

```python
import time
from pauth.exceptions import TokenError, ProviderError

def exchange_code_with_retry(client, code, state, max_retries=3):
    for attempt in range(max_retries):
        try:
            return client.exchange_code(code=code, state=state)

        except (TokenError, ProviderError) as e:
            if attempt == max_retries - 1:
                raise

            wait_time = 2 ** attempt  # Exponential backoff
            logger.warning(f"Retry {attempt + 1}/{max_retries} after {wait_time}s")
            time.sleep(wait_time)
```

## User-Friendly Error Messages

Provide clear messages to users:

```python
ERROR_MESSAGES = {
    'invalid_state': 'Security check failed. Please try logging in again.',
    'access_denied': 'You denied access. To use this app, please authorize it.',
    'server_error': 'Authentication service is unavailable. Please try again later.',
    'invalid_request': 'Something went wrong. Please try again.',
}

def get_user_message(error):
    return ERROR_MESSAGES.get(error, 'An error occurred. Please try again.')
```

## Best Practices

1. ✅ **Catch specific exceptions** before general ones
2. ✅ **Log errors** with context but without sensitive data
3. ✅ **Provide user-friendly messages**
4. ✅ **Implement retry logic** for transient failures
5. ✅ **Monitor error rates**
6. ✅ **Handle provider downtime** gracefully
7. ✅ **Validate all inputs**
8. ❌ **Don't expose internal errors** to users
9. ❌ **Don't log tokens or secrets**

## Testing Error Handling

Test your error handling:

```python
import pytest
from pauth.exceptions import AuthorizationError

def test_invalid_code_handling():
    client = OAuth2Client(...)

    with pytest.raises(AuthorizationError):
        client.exchange_code(code="invalid", state="state")

def test_invalid_state_handling():
    client = OAuth2Client(...)

    with pytest.raises(InvalidStateError):
        client.exchange_code(code="valid_code", state="wrong_state")
```

## Next Steps

- Learn about [Security Best Practices](security.md)
- Explore [PKCE Support](pkce.md)
- Read about [Token Storage](token-storage.md)

# PKCE Support

PKCE (Proof Key for Code Exchange) is a security enhancement for OAuth 2.0 that prevents authorization code interception attacks.

## What is PKCE?

PKCE adds an extra layer of security to the OAuth flow by:

1. Generating a random `code_verifier`
2. Creating a `code_challenge` from the verifier
3. Sending the challenge with the authorization request
4. Sending the verifier with the token request

This ensures that even if an authorization code is intercepted, it cannot be exchanged for tokens without the original verifier.

## When to Use PKCE

PKCE is recommended for:

- ✅ **Single Page Applications (SPAs)**
- ✅ **Mobile applications**
- ✅ **Any public client** (applications that can't keep secrets)
- ✅ **Native desktop applications**
- ✅ **All applications** as a security best practice

## Enabling PKCE in PAuth

Enable PKCE by setting `use_pkce=True`:

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    use_pkce=True  # Enable PKCE
)
```

## How It Works

When PKCE is enabled, PAuth automatically handles:

### 1. Code Verifier Generation

```python
# PAuth generates a secure random verifier internally
# Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

### 2. Code Challenge Creation

```python
# PAuth creates a SHA-256 hash of the verifier
# challenge = BASE64URL(SHA256(verifier))
```

### 3. Authorization Request

PAuth includes the challenge in the authorization URL:

```python
auth_url = client.get_authorization_url(
    scope=["openid", "email"],
    state="secure_state"
)
# URL includes: &code_challenge=...&code_challenge_method=S256
```

### 4. Token Exchange

PAuth includes the verifier when exchanging the code:

```python
tokens = client.exchange_code(code="auth_code", state="state")
# Request includes: code_verifier=original_verifier
```

## Complete Example

```python
from pauth import OAuth2Client, Providers

# Initialize with PKCE enabled
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_github_client_id",
    client_secret="your_github_client_secret",
    redirect_uri="https://your-app.com/callback",
    use_pkce=True
)

# Step 1: Get authorization URL
# PKCE parameters are automatically included
auth_url = client.get_authorization_url(
    scope=["user", "user:email"],
    state="secure_random_state"
)

print(f"Visit: {auth_url}")

# Step 2: Exchange code for tokens
# Code verifier is automatically included
tokens = client.exchange_code(
    code="authorization_code_from_callback",
    state="secure_random_state"
)

# Step 3: Use the tokens
user_info = client.get_user_info(tokens.access_token)
print(f"Logged in as: {user_info.name}")
```

## Provider Support

PKCE support varies by provider:

| Provider | PKCE Support |
|----------|--------------|
| Google | ✅ Supported |
| GitHub | ✅ Supported |
| Facebook | ✅ Supported |
| Microsoft | ✅ Supported |
| Twitter | ✅ Supported |
| LinkedIn | ⚠️ Check docs |
| Discord | ✅ Supported |

## Manual PKCE (Advanced)

If you need manual control over PKCE:

```python
from pauth.utils.pkce import generate_code_verifier, generate_code_challenge

# Generate verifier and challenge
verifier = generate_code_verifier()
challenge = generate_code_challenge(verifier)

# Store verifier securely (in session, database, etc.)
session['code_verifier'] = verifier

# Include challenge in authorization request
auth_url = client.get_authorization_url(
    scope=["openid"],
    state="state",
    extra_params={
        'code_challenge': challenge,
        'code_challenge_method': 'S256'
    }
)

# Later, when exchanging code:
tokens = client.exchange_code(
    code="auth_code",
    state="state",
    code_verifier=session['code_verifier']
)
```

## Security Benefits

PKCE provides protection against:

1. **Authorization Code Interception**: Even if the code is stolen, it can't be used
2. **Man-in-the-Middle Attacks**: The verifier proves the token request comes from the original client
3. **Cross-Site Request Forgery**: Combined with state validation

## Best Practices

1. ✅ **Always enable PKCE** for public clients
2. ✅ **Use S256 challenge method** (PAuth default)
3. ✅ **Generate secure random verifiers** (PAuth does this automatically)
4. ✅ **Store verifiers securely** until token exchange
5. ✅ **Combine with state validation** for maximum security

## Troubleshooting

### Error: "code_verifier required"

**Cause**: PKCE is enabled but no verifier was provided for token exchange.

**Solution**: PAuth handles this automatically. This usually indicates session loss or improper state management.

### Error: "invalid code_verifier"

**Cause**: The verifier doesn't match the original challenge.

**Solution**: Ensure the verifier is stored and retrieved correctly between authorization and token exchange.

## Resources

- [RFC 7636: PKCE Specification](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

## Next Steps

- Learn about [Token Storage](token-storage.md)
- Read about [Security Best Practices](security.md)
- Explore [Error Handling](error-handling.md)

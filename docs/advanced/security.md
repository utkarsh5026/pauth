# Security Best Practices

Security is paramount when implementing OAuth. Follow these best practices to keep your application and users safe.

## Essential Security Measures

### 1. Always Use HTTPS

**Never** use OAuth over HTTP in production:

```python
# ❌ INSECURE
redirect_uri = "http://your-app.com/callback"

# ✅ SECURE
redirect_uri = "https://your-app.com/callback"
```

**Why:** HTTP traffic can be intercepted, exposing authorization codes and tokens.

### 2. Enable PKCE

Use PKCE for all applications:

```python
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    use_pkce=True  # ✅ Always enable
)
```

[Learn more about PKCE →](pkce.md)

### 3. Validate State Parameter

Always generate and validate the state parameter:

```python
import secrets

# Generate secure random state
state = secrets.token_urlsafe(32)

# Store in session
session['oauth_state'] = state

# Get authorization URL with state
auth_url = client.get_authorization_url(
    scope=["openid", "email"],
    state=state
)

# Later, in callback:
if request.args.get('state') != session.get('oauth_state'):
    raise InvalidStateError("State mismatch - potential CSRF attack")
```

### 4. Secure Token Storage

Never store tokens in plain text:

```python
# ❌ INSECURE
def save_token(user_id, token):
    with open(f'{user_id}.txt', 'w') as f:
        f.write(token)

# ✅ SECURE
from cryptography.fernet import Fernet

def save_token(user_id, token):
    cipher = Fernet(encryption_key)
    encrypted = cipher.encrypt(token.encode())
    db.save(user_id, encrypted)
```

[Learn more about token storage →](token-storage.md)

### 5. Protect Client Secrets

Never expose client secrets:

```python
# ❌ INSECURE - Hardcoded secret
client_secret = "abc123secret"

# ❌ INSECURE - In version control
# config.py
GOOGLE_SECRET = "abc123secret"

# ✅ SECURE - Environment variables
import os
client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
```

## Common Security Vulnerabilities

### CSRF Attacks

**Vulnerability:** Attackers trick users into authorizing malicious apps.

**Protection:**
```python
# Generate unique state for each request
state = secrets.token_urlsafe(32)
session['oauth_state'] = state

# Validate state in callback
if state != session.get('oauth_state'):
    raise SecurityError("CSRF attempt detected")
```

### Authorization Code Interception

**Vulnerability:** Attackers intercept authorization codes.

**Protection:**
```python
# Use PKCE
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    use_pkce=True  # Prevents code interception
)
```

### Token Leakage

**Vulnerability:** Tokens exposed in logs, URLs, or client-side code.

**Protection:**
```python
# ❌ INSECURE
logger.info(f"User token: {access_token}")
redirect(f"/dashboard?token={access_token}")

# ✅ SECURE
logger.info("User authenticated successfully")
session['access_token'] = access_token
redirect("/dashboard")
```

### Session Fixation

**Vulnerability:** Attackers hijack user sessions.

**Protection:**
```python
from flask import session

# Regenerate session after login
@app.route('/callback')
def callback():
    # ... OAuth flow ...

    # Regenerate session ID
    session.regenerate()

    # Store user data
    session['user_id'] = user.id
```

## Configuration Security

### Secure Session Cookies

```python
# Flask
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800  # 30 minute timeout
)

# Django
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 1800
```

### Restrict Redirect URIs

Register exact redirect URIs with providers:

```python
# ✅ Specific URI
redirect_uri = "https://your-app.com/oauth/callback"

# ❌ Wildcard (if supported - avoid!)
redirect_uri = "https://your-app.com/*"
```

### Minimal Scopes

Request only necessary scopes:

```python
# ❌ Excessive permissions
scopes = ["openid", "email", "profile", "contacts", "calendar", "drive"]

# ✅ Minimal permissions
scopes = ["openid", "email", "profile"]
```

## Token Management

### Token Expiration

Implement proper token expiration:

```python
import time

def is_token_expired(tokens):
    if 'expires_at' in tokens:
        return time.time() > tokens['expires_at']
    return False

def get_valid_token(user_id):
    tokens = storage.get_token(user_id)

    if is_token_expired(tokens):
        # Refresh token
        new_tokens = client.refresh_token(tokens['refresh_token'])
        storage.save_token(user_id, new_tokens)
        return new_tokens

    return tokens
```

### Token Revocation

Implement logout and token revocation:

```python
@app.route('/logout')
def logout():
    user_id = session.get('user_id')

    # Revoke token with provider (if supported)
    try:
        client.revoke_token(session.get('access_token'))
    except Exception:
        pass  # Best effort

    # Delete from storage
    storage.delete_token(user_id)

    # Clear session
    session.clear()

    return redirect('/')
```

## Monitoring and Auditing

### Log Security Events

```python
import logging

security_logger = logging.getLogger('security')

# Log authentication attempts
security_logger.info(f"Login attempt for user: {user_id}")

# Log failures
security_logger.warning(f"Failed login from IP: {request.remote_addr}")

# Log state mismatches (potential attacks)
security_logger.error(f"State mismatch - possible CSRF: {request.remote_addr}")
```

### Rate Limiting

Implement rate limiting:

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/login')
@limiter.limit("5 per minute")
def login():
    # OAuth flow
    pass
```

## Compliance Considerations

### GDPR

```python
# Implement data export
@app.route('/export-data')
def export_data():
    user_data = get_user_data(session['user_id'])
    return jsonify(user_data)

# Implement data deletion
@app.route('/delete-account')
def delete_account():
    user_id = session['user_id']
    storage.delete_token(user_id)
    delete_user_data(user_id)
    return "Account deleted"
```

## Security Checklist

- [ ] HTTPS enabled in production
- [ ] PKCE enabled
- [ ] State parameter validated
- [ ] Tokens encrypted at rest
- [ ] Client secrets in environment variables
- [ ] Secure session cookies configured
- [ ] Minimal scopes requested
- [ ] Token expiration handled
- [ ] Token revocation implemented
- [ ] Security events logged
- [ ] Rate limiting enabled
- [ ] Error messages don't leak sensitive info
- [ ] No tokens in URLs or logs
- [ ] Regular security audits performed

## Testing Security

```python
def test_state_validation():
    """Test that invalid state is rejected"""
    with pytest.raises(InvalidStateError):
        client.exchange_code(code="valid", state="wrong_state")

def test_https_required():
    """Test that HTTP is rejected in production"""
    if app.config['ENV'] == 'production':
        assert client.redirect_uri.startswith('https://')

def test_token_encryption():
    """Test that tokens are encrypted"""
    storage.save_token(user_id, token)
    raw_data = storage.get_raw_data(user_id)
    assert token not in raw_data  # Token should be encrypted
```

## Resources

- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)

## Next Steps

- Implement [PKCE Support](pkce.md)
- Set up [Token Storage](token-storage.md)
- Configure [Error Handling](error-handling.md)

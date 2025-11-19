# Flask Integration

PAuth provides seamless integration with Flask applications through helper utilities and patterns.

## Installation

Install PAuth with Flask support:

```bash
pip install pauth[flask]
```

## Basic Setup

Here's a complete Flask application with OAuth:

```python
from flask import Flask, redirect, request, session, url_for
from pauth import OAuth2Client, Providers
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for sessions

# Initialize OAuth client
oauth_client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri="http://localhost:5000/callback"
)

@app.route('/')
def index():
    if 'user' in session:
        return f"Hello, {session['user']['name']}! <a href='/logout'>Logout</a>"
    return '<a href="/login">Login with Google</a>'

@app.route('/login')
def login():
    # Generate and store state in session for CSRF protection
    import secrets
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Get authorization URL
    auth_url = oauth_client.get_authorization_url(
        scope=["openid", "email", "profile"],
        state=state
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    # Verify state parameter
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "Invalid state parameter", 400

    # Get authorization code
    code = request.args.get('code')
    if not code:
        return "No code provided", 400

    try:
        # Exchange code for tokens
        tokens = oauth_client.exchange_code(code=code, state=state)

        # Get user information
        user_info = oauth_client.get_user_info(tokens.access_token)

        # Store user in session
        session['user'] = {
            'id': user_info.id,
            'name': user_info.name,
            'email': user_info.email
        }
        session['access_token'] = tokens.access_token

        return redirect(url_for('index'))

    except Exception as e:
        return f"Authentication failed: {str(e)}", 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
```

## Multiple Providers

Support multiple OAuth providers in one application:

```python
from flask import Flask, redirect, request, session
from pauth import OAuth2Client, Providers

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configure multiple providers
OAUTH_PROVIDERS = {
    'google': OAuth2Client(
        provider=Providers.GOOGLE,
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        redirect_uri="http://localhost:5000/callback/google"
    ),
    'github': OAuth2Client(
        provider=Providers.GITHUB,
        client_id=os.getenv("GITHUB_CLIENT_ID"),
        client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
        redirect_uri="http://localhost:5000/callback/github"
    ),
}

@app.route('/login/<provider>')
def login(provider):
    if provider not in OAUTH_PROVIDERS:
        return "Unknown provider", 404

    client = OAUTH_PROVIDERS[provider]
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oauth_provider'] = provider

    scopes = {
        'google': ["openid", "email", "profile"],
        'github': ["user", "user:email"],
    }

    auth_url = client.get_authorization_url(
        scope=scopes.get(provider, []),
        state=state
    )
    return redirect(auth_url)

@app.route('/callback/<provider>')
def callback(provider):
    if provider not in OAUTH_PROVIDERS:
        return "Unknown provider", 404

    client = OAUTH_PROVIDERS[provider]

    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        return "Invalid state", 400

    code = request.args.get('code')
    tokens = client.exchange_code(code=code, state=state)
    user_info = client.get_user_info(tokens.access_token)

    session['user'] = {
        'id': user_info.id,
        'name': user_info.name,
        'email': user_info.email,
        'provider': provider
    }

    return redirect(url_for('index'))
```

## Protected Routes

Use decorators to protect routes:

```python
from functools import wraps
from flask import session, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/protected')
@login_required
def protected():
    return f"Welcome to protected area, {session['user']['name']}!"
```

## Best Practices

1. **Use environment variables** for credentials
2. **Enable HTTPS** in production
3. **Set secure session cookies**:
   ```python
   app.config.update(
       SESSION_COOKIE_SECURE=True,
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SAMESITE='Lax'
   )
   ```
4. **Implement CSRF protection** with Flask-WTF
5. **Store tokens securely** - consider using Flask-Login for session management

## Complete Example with Database

```python
from flask import Flask, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from pauth import OAuth2Client, Providers

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    oauth_provider = db.Column(db.String(50))
    oauth_id = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))

@app.route('/callback')
def callback():
    # ... OAuth flow ...

    # Find or create user
    user = User.query.filter_by(
        oauth_provider='google',
        oauth_id=user_info.id
    ).first()

    if not user:
        user = User(
            oauth_provider='google',
            oauth_id=user_info.id,
            name=user_info.name,
            email=user_info.email
        )
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    return redirect(url_for('index'))
```

## Next Steps

- Check out the [Django Integration](django.md) guide
- Learn about [Token Storage](../advanced/token-storage.md)
- Read about [Security Best Practices](../advanced/security.md)

# Django Integration

PAuth can be integrated into Django applications for OAuth authentication.

## Installation

Install PAuth with Django support:

```bash
pip install pauth[django]
```

## Basic Setup

### 1. Configure Settings

Add to your `settings.py`:

```python
# settings.py
import os

INSTALLED_APPS = [
    # ... other apps
    'django.contrib.sessions',
    # Your apps
]

# OAuth Configuration
PAUTH_PROVIDERS = {
    'google': {
        'client_id': os.getenv('GOOGLE_CLIENT_ID'),
        'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
        'redirect_uri': 'http://localhost:8000/oauth/callback/google/',
        'scopes': ['openid', 'email', 'profile'],
    },
    'github': {
        'client_id': os.getenv('GITHUB_CLIENT_ID'),
        'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
        'redirect_uri': 'http://localhost:8000/oauth/callback/github/',
        'scopes': ['user', 'user:email'],
    },
}
```

### 2. Create Views

```python
# views.py
from django.shortcuts import redirect
from django.http import HttpResponse
from django.contrib.auth import login
from django.contrib.auth.models import User
from pauth import OAuth2Client, Providers
from django.conf import settings
import secrets

def oauth_login(request, provider):
    """Initiate OAuth flow"""
    if provider not in settings.PAUTH_PROVIDERS:
        return HttpResponse("Unknown provider", status=404)

    config = settings.PAUTH_PROVIDERS[provider]

    # Create OAuth client
    provider_enum = getattr(Providers, provider.upper())
    client = OAuth2Client(
        provider=provider_enum,
        client_id=config['client_id'],
        client_secret=config['client_secret'],
        redirect_uri=config['redirect_uri']
    )

    # Generate state and store in session
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    request.session['oauth_provider'] = provider

    # Get authorization URL
    auth_url = client.get_authorization_url(
        scope=config['scopes'],
        state=state
    )

    return redirect(auth_url)

def oauth_callback(request, provider):
    """Handle OAuth callback"""
    if provider not in settings.PAUTH_PROVIDERS:
        return HttpResponse("Unknown provider", status=404)

    # Verify state
    state = request.GET.get('state')
    if state != request.session.get('oauth_state'):
        return HttpResponse("Invalid state", status=400)

    code = request.GET.get('code')
    if not code:
        return HttpResponse("No code provided", status=400)

    config = settings.PAUTH_PROVIDERS[provider]
    provider_enum = getattr(Providers, provider.upper())

    client = OAuth2Client(
        provider=provider_enum,
        client_id=config['client_id'],
        client_secret=config['client_secret'],
        redirect_uri=config['redirect_uri']
    )

    try:
        # Exchange code for tokens
        tokens = client.exchange_code(code=code, state=state)

        # Get user information
        user_info = client.get_user_info(tokens.access_token)

        # Find or create Django user
        user, created = User.objects.get_or_create(
            username=f"{provider}_{user_info.id}",
            defaults={
                'email': user_info.email,
                'first_name': user_info.name,
            }
        )

        # Log the user in
        login(request, user)

        return redirect('home')

    except Exception as e:
        return HttpResponse(f"Authentication failed: {str(e)}", status=400)

def logout_view(request):
    from django.contrib.auth import logout
    logout(request)
    return redirect('home')
```

### 3. Configure URLs

```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('oauth/login/<str:provider>/', views.oauth_login, name='oauth_login'),
    path('oauth/callback/<str:provider>/', views.oauth_callback, name='oauth_callback'),
    path('logout/', views.logout_view, name='logout'),
]
```

### 4. Create Templates

{% raw %}

```html
<!-- templates/home.html -->
{% if user.is_authenticated %}
    <p>Welcome, {{ user.first_name }}!</p>
    <a href="{% url 'logout' %}">Logout</a>
{% else %}
    <a href="{% url 'oauth_login' 'google' %}">Login with Google</a>
    <a href="{% url 'oauth_login' 'github' %}">Login with GitHub</a>
{% endif %}
```

{% endraw %}

## Custom User Model

Store OAuth data in a custom user model:

```python
# models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    oauth_provider = models.CharField(max_length=50, blank=True)
    oauth_id = models.CharField(max_length=100, blank=True)
    avatar_url = models.URLField(blank=True)

    class Meta:
        unique_together = [['oauth_provider', 'oauth_id']]
```

Update `settings.py`:

```python
AUTH_USER_MODEL = 'yourapp.User'
```

## Middleware for Token Refresh

Automatically refresh expired tokens:

```python
# middleware.py
from django.utils.deprecation import MiddlewareMixin
from pauth import OAuth2Client

class TokenRefreshMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            # Check if token needs refresh
            # Implement your token refresh logic here
            pass
```

## Best Practices

1. **Use environment variables** for all credentials
2. **Enable HTTPS** in production
3. **Configure secure session cookies**:
   ```python
   SESSION_COOKIE_SECURE = True
   SESSION_COOKIE_HTTPONLY = True
   SESSION_COOKIE_SAMESITE = 'Lax'
   ```
4. **Use Django's CSRF protection**
5. **Implement proper user logout**

## Next Steps

- Learn about [Token Storage](../advanced/token-storage.md)
- Read about [Security Best Practices](../advanced/security.md)
- Check out the [Flask Integration](flask.md) guide

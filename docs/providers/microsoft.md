# Microsoft OAuth

Microsoft OAuth provides access to Azure AD and Microsoft services.

## Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Register a new application
3. Add redirect URIs
4. Note Application (client) ID and create a client secret

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.MICROSOFT,
    client_id="your_application_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Resources

- [Microsoft Identity Platform Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)

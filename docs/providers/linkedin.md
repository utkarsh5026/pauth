# LinkedIn OAuth

LinkedIn OAuth provides access to professional profile data.

## Setup

1. Go to [LinkedIn Developers](https://www.linkedin.com/developers/)
2. Create a new app
3. Add redirect URLs
4. Note Client ID and Client Secret

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.LINKEDIN,
    client_id="your_linkedin_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Resources

- [LinkedIn OAuth Documentation](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authentication)

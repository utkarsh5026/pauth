# Discord OAuth

Discord OAuth is perfect for gaming and community applications.

## Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Add OAuth2 redirect URIs
4. Note Client ID and Client Secret

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.DISCORD,
    client_id="your_discord_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:5000/callback"
)
```

## Resources

- [Discord OAuth Documentation](https://discord.com/developers/docs/topics/oauth2)

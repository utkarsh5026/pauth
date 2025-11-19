# Token Storage

Learn how to securely store and manage OAuth tokens in your application.

## Storage Options

PAuth provides flexible token storage through a simple interface.

### In-Memory Storage (Default)

The default storage keeps tokens in memory:

```python
from pauth import OAuth2Client, Providers

client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback"
    # Uses in-memory storage by default
)
```

**Pros:**
- Fast access
- Simple setup
- Good for development

**Cons:**
- Tokens lost on restart
- Not suitable for production
- Not scalable

### Custom Storage

Implement custom storage for production use:

```python
from pauth.storage import BaseTokenStorage

class CustomTokenStorage(BaseTokenStorage):
    def save_token(self, user_id: str, tokens: dict) -> None:
        """Save tokens for a user"""
        pass

    def get_token(self, user_id: str) -> dict:
        """Retrieve tokens for a user"""
        pass

    def delete_token(self, user_id: str) -> None:
        """Delete tokens for a user"""
        pass

# Use custom storage
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    token_storage=CustomTokenStorage()
)
```

## Implementation Examples

### Database Storage (SQLAlchemy)

```python
from pauth.storage import BaseTokenStorage
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json

Base = declarative_base()

class TokenModel(Base):
    __tablename__ = 'oauth_tokens'

    id = Column(Integer, primary_key=True)
    user_id = Column(String(100), unique=True)
    tokens = Column(String(1000))

class DatabaseTokenStorage(BaseTokenStorage):
    def __init__(self, db_url):
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.session = Session()

    def save_token(self, user_id: str, tokens: dict) -> None:
        token_record = self.session.query(TokenModel).filter_by(
            user_id=user_id
        ).first()

        if token_record:
            token_record.tokens = json.dumps(tokens)
        else:
            token_record = TokenModel(
                user_id=user_id,
                tokens=json.dumps(tokens)
            )
            self.session.add(token_record)

        self.session.commit()

    def get_token(self, user_id: str) -> dict:
        token_record = self.session.query(TokenModel).filter_by(
            user_id=user_id
        ).first()

        if token_record:
            return json.loads(token_record.tokens)
        return None

    def delete_token(self, user_id: str) -> None:
        self.session.query(TokenModel).filter_by(
            user_id=user_id
        ).delete()
        self.session.commit()

# Usage
storage = DatabaseTokenStorage('sqlite:///tokens.db')
client = OAuth2Client(
    provider=Providers.GOOGLE,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    token_storage=storage
)
```

### Redis Storage

```python
from pauth.storage import BaseTokenStorage
import redis
import json

class RedisTokenStorage(BaseTokenStorage):
    def __init__(self, redis_url='redis://localhost:6379'):
        self.redis = redis.from_url(redis_url)

    def save_token(self, user_id: str, tokens: dict) -> None:
        key = f"oauth_tokens:{user_id}"
        self.redis.set(key, json.dumps(tokens))

        # Optional: Set expiration
        if 'expires_in' in tokens:
            self.redis.expire(key, tokens['expires_in'])

    def get_token(self, user_id: str) -> dict:
        key = f"oauth_tokens:{user_id}"
        data = self.redis.get(key)

        if data:
            return json.loads(data)
        return None

    def delete_token(self, user_id: str) -> None:
        key = f"oauth_tokens:{user_id}"
        self.redis.delete(key)

# Usage
storage = RedisTokenStorage('redis://localhost:6379')
client = OAuth2Client(
    provider=Providers.GITHUB,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    token_storage=storage
)
```

### Encrypted File Storage

```python
from pauth.storage import BaseTokenStorage
from cryptography.fernet import Fernet
import json
import os

class EncryptedFileStorage(BaseTokenStorage):
    def __init__(self, directory='tokens', key=None):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

        # Generate or load encryption key
        if key is None:
            key = Fernet.generate_key()
        self.cipher = Fernet(key)

    def save_token(self, user_id: str, tokens: dict) -> None:
        filename = os.path.join(self.directory, f"{user_id}.enc")
        data = json.dumps(tokens).encode()
        encrypted = self.cipher.encrypt(data)

        with open(filename, 'wb') as f:
            f.write(encrypted)

    def get_token(self, user_id: str) -> dict:
        filename = os.path.join(self.directory, f"{user_id}.enc")

        if not os.path.exists(filename):
            return None

        with open(filename, 'rb') as f:
            encrypted = f.read()

        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted)

    def delete_token(self, user_id: str) -> None:
        filename = os.path.join(self.directory, f"{user_id}.enc")
        if os.path.exists(filename):
            os.remove(filename)
```

## Security Considerations

### Encryption at Rest

Always encrypt tokens when storing:

```python
from cryptography.fernet import Fernet

# Generate a key (store this securely!)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt before storing
encrypted_token = cipher.encrypt(token.encode())

# Decrypt when retrieving
decrypted_token = cipher.decrypt(encrypted_token).decode()
```

### Access Control

Implement proper access control:

```python
class SecureTokenStorage(BaseTokenStorage):
    def save_token(self, user_id: str, tokens: dict) -> None:
        # Validate user_id
        if not self.is_valid_user(user_id):
            raise ValueError("Invalid user_id")

        # Encrypt tokens
        encrypted = self.encrypt(tokens)

        # Save with proper permissions
        self.db.save(user_id, encrypted, permissions='0600')
```

### Token Rotation

Implement automatic token rotation:

```python
def save_token(self, user_id: str, tokens: dict) -> None:
    # Add timestamp
    tokens['stored_at'] = time.time()

    # Save encrypted
    self.storage.save(user_id, self.encrypt(tokens))

    # Schedule rotation check
    if 'expires_in' in tokens:
        self.schedule_refresh(user_id, tokens['expires_in'])
```

## Best Practices

1. ✅ **Encrypt tokens** at rest
2. ✅ **Use secure connections** (TLS/SSL)
3. ✅ **Implement access control**
4. ✅ **Set appropriate expiration**
5. ✅ **Log access** for auditing
6. ✅ **Rotate tokens** regularly
7. ✅ **Never log token values**
8. ✅ **Use environment-specific storage**

## Testing Storage

Test your custom storage implementation:

```python
def test_token_storage():
    storage = CustomTokenStorage()
    user_id = "test_user"
    tokens = {
        'access_token': 'test_access_token',
        'refresh_token': 'test_refresh_token',
        'expires_in': 3600
    }

    # Test save
    storage.save_token(user_id, tokens)

    # Test retrieve
    retrieved = storage.get_token(user_id)
    assert retrieved == tokens

    # Test delete
    storage.delete_token(user_id)
    assert storage.get_token(user_id) is None
```

## Next Steps

- Learn about [PKCE Support](pkce.md)
- Read about [Security Best Practices](security.md)
- Explore [Error Handling](error-handling.md)

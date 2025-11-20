"""
Comprehensive tests for MemoryTokenStorage.
"""

import threading
from datetime import datetime, timedelta, timezone

import pytest

from src.models.token import TokenResponse
from src.storage.mem import MemoryTokenStorage


@pytest.fixture
def storage():
    """Create a fresh MemoryTokenStorage instance for each test."""
    return MemoryTokenStorage()


@pytest.fixture
def sample_token():
    """Create a sample TokenResponse for testing."""
    return TokenResponse(
        access_token="test_access_token_123",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="test_refresh_token_456",
        scope="read write",
        id_token="test_id_token_789",
        raw_response={"custom_field": "custom_value"},
    )


@pytest.fixture
def expired_token():
    """Create an expired TokenResponse for testing."""
    past_time = datetime.now(timezone.utc) - timedelta(hours=2)
    return TokenResponse(
        access_token="expired_access_token",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="expired_refresh_token",
        issued_at=past_time,
    )


class TestBasicOperations:
    """Test basic CRUD operations."""

    def test_save_and_get_token(self, storage, sample_token):
        """Test saving and retrieving a token."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        retrieved_token = storage.get_token(user_id)

        assert retrieved_token is not None
        assert retrieved_token.access_token == sample_token.access_token
        assert retrieved_token.token_type == sample_token.token_type
        assert retrieved_token.expires_in == sample_token.expires_in
        assert retrieved_token.refresh_token == sample_token.refresh_token
        assert retrieved_token.scope == sample_token.scope
        assert retrieved_token.id_token == sample_token.id_token

    def test_get_nonexistent_token(self, storage):
        """Test retrieving a token that doesn't exist."""
        retrieved_token = storage.get_token("nonexistent_user")
        assert retrieved_token is None

    def test_delete_existing_token(self, storage, sample_token):
        """Test deleting an existing token."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        result = storage.delete_token(user_id)

        assert result is True
        assert storage.get_token(user_id) is None

    def test_delete_nonexistent_token(self, storage):
        """Test deleting a token that doesn't exist."""
        result = storage.delete_token("nonexistent_user")
        assert result is False

    def test_update_token(self, storage, sample_token):
        """Test updating an existing token."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        new_token = TokenResponse(
            access_token="new_access_token",
            token_type="Bearer",
            refresh_token="new_refresh_token",
        )
        storage.update_token(user_id, new_token)

        retrieved_token = storage.get_token(user_id)
        assert retrieved_token.access_token == "new_access_token"
        assert retrieved_token.refresh_token == "new_refresh_token"

    def test_update_nonexistent_token(self, storage, sample_token):
        """Test updating a token for a user that doesn't exist yet."""
        user_id = "new_user"
        storage.update_token(user_id, sample_token)

        retrieved_token = storage.get_token(user_id)
        assert retrieved_token is not None
        assert retrieved_token.access_token == sample_token.access_token


class TestEdgeCasesAndValidation:
    """Test edge cases and input validation."""

    def test_save_token_empty_user_id(self, storage, sample_token):
        """Test saving a token with empty user_id."""
        with pytest.raises(ValueError, match="user_id must be provided"):
            storage.save_token("", sample_token)

    def test_save_token_none_user_id(self, storage, sample_token):
        """Test saving a token with None user_id."""
        with pytest.raises(ValueError, match="user_id must be provided"):
            storage.save_token(None, sample_token)

    def test_update_token_empty_user_id(self, storage, sample_token):
        """Test updating a token with empty user_id."""
        with pytest.raises(ValueError, match="user_id must be provided"):
            storage.update_token("", sample_token)

    def test_update_token_none_user_id(self, storage, sample_token):
        """Test updating a token with None user_id."""
        with pytest.raises(ValueError, match="user_id must be provided"):
            storage.update_token(None, sample_token)

    def test_get_token_empty_user_id(self, storage):
        """Test retrieving a token with empty user_id."""
        result = storage.get_token("")
        assert result is None

    def test_delete_token_empty_user_id(self, storage):
        """Test deleting a token with empty user_id."""
        result = storage.delete_token("")
        assert result is False

    def test_multiple_users(self, storage):
        """Test storing tokens for multiple users."""
        users = {
            "user1": TokenResponse(access_token="token1"),
            "user2": TokenResponse(access_token="token2"),
            "user3": TokenResponse(access_token="token3"),
        }

        for user_id, token in users.items():
            storage.save_token(user_id, token)

        for user_id, token in users.items():
            retrieved = storage.get_token(user_id)
            assert retrieved.access_token == token.access_token

    def test_overwrite_token(self, storage):
        """Test overwriting an existing token."""
        user_id = "user123"

        first_token = TokenResponse(access_token="first_token")
        storage.save_token(user_id, first_token)

        second_token = TokenResponse(access_token="second_token")
        storage.save_token(user_id, second_token)

        retrieved = storage.get_token(user_id)
        assert retrieved.access_token == "second_token"


class TestDataIsolation:
    """Test that stored data is properly isolated."""

    def test_token_deep_copy_on_save(self, storage, sample_token):
        """Test that saving a token creates a deep copy."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        # Modify the original token
        sample_token.access_token = "modified_token"

        # Retrieved token should not be affected
        retrieved = storage.get_token(user_id)
        assert retrieved.access_token == "test_access_token_123"

    def test_token_deep_copy_on_get(self, storage, sample_token):
        """Test that getting a token returns a deep copy."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        # Get token and modify it
        retrieved1 = storage.get_token(user_id)
        retrieved1.access_token = "modified_token"

        # Getting again should return original value
        retrieved2 = storage.get_token(user_id)
        assert retrieved2.access_token == "test_access_token_123"


class TestHelperMethods:
    """Test helper methods."""

    def test_clear_all_empty(self, storage):
        """Test clearing an empty storage."""
        storage.clear_all()
        assert storage.get_all_user_ids() == []

    def test_clear_all_with_data(self, storage, sample_token):
        """Test clearing storage with data."""
        storage.save_token("user1", sample_token)
        storage.save_token("user2", sample_token)
        storage.save_token("user3", sample_token)

        storage.clear_all()

        assert storage.get_all_user_ids() == []
        assert storage.get_token("user1") is None
        assert storage.get_token("user2") is None
        assert storage.get_token("user3") is None

    def test_get_all_user_ids_empty(self, storage):
        """Test getting user IDs from empty storage."""
        assert storage.get_all_user_ids() == []

    def test_get_all_user_ids_with_data(self, storage, sample_token):
        """Test getting all user IDs."""
        user_ids = ["user1", "user2", "user3"]

        for user_id in user_ids:
            storage.save_token(user_id, sample_token)

        retrieved_ids = storage.get_all_user_ids()
        assert set(retrieved_ids) == set(user_ids)
        assert len(retrieved_ids) == 3

    def test_get_all_user_ids_after_delete(self, storage, sample_token):
        """Test getting user IDs after deleting some."""
        storage.save_token("user1", sample_token)
        storage.save_token("user2", sample_token)
        storage.save_token("user3", sample_token)

        storage.delete_token("user2")

        retrieved_ids = storage.get_all_user_ids()
        assert set(retrieved_ids) == {"user1", "user3"}

    def test_token_exists(self, storage, sample_token):
        """Test checking if token exists (from BaseTokenStorage)."""
        user_id = "user123"

        assert storage.token_exists(user_id) is False

        storage.save_token(user_id, sample_token)
        assert storage.token_exists(user_id) is True

        storage.delete_token(user_id)
        assert storage.token_exists(user_id) is False


class TestThreadSafety:
    """Test thread safety of MemoryTokenStorage."""

    def test_concurrent_saves(self, storage):
        """Test concurrent saves from multiple threads."""
        num_threads = 10
        threads = []

        def save_token(user_id):
            token = TokenResponse(access_token=f"token_{user_id}")
            storage.save_token(user_id, token)

        for i in range(num_threads):
            thread = threading.Thread(target=save_token, args=(f"user{i}",))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All tokens should be saved
        assert len(storage.get_all_user_ids()) == num_threads

        for i in range(num_threads):
            token = storage.get_token(f"user{i}")
            assert token is not None
            assert token.access_token == f"token_user{i}"

    def test_concurrent_reads(self, storage, sample_token):
        """Test concurrent reads from multiple threads."""
        user_id = "shared_user"
        storage.save_token(user_id, sample_token)

        num_threads = 20
        results = []
        threads = []

        def read_token():
            token = storage.get_token(user_id)
            results.append(token.access_token if token else None)

        for _ in range(num_threads):
            thread = threading.Thread(target=read_token)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All reads should succeed
        assert len(results) == num_threads
        assert all(r == sample_token.access_token for r in results)

    def test_concurrent_updates(self, storage, sample_token):
        """Test concurrent updates to the same user."""
        user_id = "user123"
        storage.save_token(user_id, sample_token)

        num_threads = 10
        threads = []

        def update_token(thread_id):
            token = TokenResponse(access_token=f"token_from_thread_{thread_id}")
            storage.update_token(user_id, token)

        for i in range(num_threads):
            thread = threading.Thread(target=update_token, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Token should exist and be from one of the threads
        token = storage.get_token(user_id)
        assert token is not None
        assert token.access_token.startswith("token_from_thread_")

    def test_concurrent_mixed_operations(self, storage):
        """Test mixed concurrent operations."""
        num_operations = 50
        threads = []

        def save_operation(i):
            token = TokenResponse(access_token=f"token_{i}")
            storage.save_token(f"user_{i}", token)

        def read_operation(i):
            storage.get_token(f"user_{i}")

        def delete_operation(i):
            storage.delete_token(f"user_{i}")

        # Prepare some data
        for i in range(0, num_operations, 3):
            storage.save_token(f"user_{i}", TokenResponse(access_token=f"init_{i}"))

        # Mix of operations
        for i in range(num_operations):
            if i % 3 == 0:
                thread = threading.Thread(target=save_operation, args=(i,))
            elif i % 3 == 1:
                thread = threading.Thread(target=read_operation, args=(i,))
            else:
                thread = threading.Thread(target=delete_operation, args=(i,))

            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Storage should still be in a consistent state
        user_ids = storage.get_all_user_ids()
        assert isinstance(user_ids, list)

    def test_race_condition_save_delete(self, storage, sample_token):
        """Test race condition between save and delete."""
        user_id = "race_user"
        iterations = 100
        threads = []

        def save_repeatedly():
            for _ in range(iterations):
                storage.save_token(user_id, sample_token)

        def delete_repeatedly():
            for _ in range(iterations):
                storage.delete_token(user_id)

        save_thread = threading.Thread(target=save_repeatedly)
        delete_thread = threading.Thread(target=delete_repeatedly)

        threads = [save_thread, delete_thread]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # No exceptions should occur, final state is either saved or deleted
        storage.get_token(user_id)
        # Token can be either present or absent, but no corruption


class TestTokenWithDifferentAttributes:
    """Test handling tokens with various attribute combinations."""

    def test_minimal_token(self, storage):
        """Test token with only required fields."""
        minimal_token = TokenResponse(access_token="minimal_token")

        storage.save_token("user123", minimal_token)
        retrieved = storage.get_token("user123")

        assert retrieved.access_token == "minimal_token"
        assert retrieved.token_type == "Bearer"
        assert retrieved.expires_in is None
        assert retrieved.refresh_token is None

    def test_token_with_all_fields(self, storage):
        """Test token with all possible fields."""
        full_token = TokenResponse(
            access_token="full_access",
            token_type="Custom",
            expires_in=7200,
            refresh_token="full_refresh",
            scope="read write admin",
            id_token="full_id",
            raw_response={"extra": "data", "nested": {"key": "value"}},
        )

        storage.save_token("user123", full_token)
        retrieved = storage.get_token("user123")

        assert retrieved.access_token == "full_access"
        assert retrieved.token_type == "Custom"
        assert retrieved.expires_in == 7200
        assert retrieved.refresh_token == "full_refresh"
        assert retrieved.scope == "read write admin"
        assert retrieved.id_token == "full_id"
        assert retrieved.raw_response["extra"] == "data"

    def test_expired_token_storage(self, storage, expired_token):
        """Test that expired tokens can be stored and retrieved."""
        storage.save_token("user123", expired_token)
        retrieved = storage.get_token("user123")

        assert retrieved is not None
        assert retrieved.is_expired is True
        assert retrieved.expires_in == 3600
        assert retrieved.expires_at is not None

    def test_token_with_unicode(self, storage):
        """Test storing tokens with unicode characters."""
        unicode_token = TokenResponse(
            access_token="token_with_émojis_🔐", refresh_token="refresh_中文_русский"
        )

        storage.save_token("user_unicode", unicode_token)
        retrieved = storage.get_token("user_unicode")

        assert retrieved.access_token == "token_with_émojis_🔐"
        assert retrieved.refresh_token == "refresh_中文_русский"


class TestStorageStateManagement:
    """Test overall storage state management."""

    def test_storage_independence(self):
        """Test that multiple storage instances are independent."""
        storage1 = MemoryTokenStorage()
        storage2 = MemoryTokenStorage()

        token1 = TokenResponse(access_token="token1")
        token2 = TokenResponse(access_token="token2")

        storage1.save_token("user", token1)
        storage2.save_token("user", token2)

        assert storage1.get_token("user").access_token == "token1"
        assert storage2.get_token("user").access_token == "token2"

    def test_storage_size_tracking(self, storage, sample_token):
        """Test tracking the number of stored tokens."""
        assert len(storage.get_all_user_ids()) == 0

        for i in range(10):
            storage.save_token(f"user{i}", sample_token)

        assert len(storage.get_all_user_ids()) == 10

        storage.delete_token("user5")
        assert len(storage.get_all_user_ids()) == 9

        storage.clear_all()
        assert len(storage.get_all_user_ids()) == 0

    def test_large_scale_storage(self, storage):
        """Test storing a large number of tokens."""
        num_users = 1000

        for i in range(num_users):
            token = TokenResponse(access_token=f"token_{i}")
            storage.save_token(f"user_{i}", token)

        assert len(storage.get_all_user_ids()) == num_users

        # Verify random samples
        for i in [0, 100, 500, 999]:
            retrieved = storage.get_token(f"user_{i}")
            assert retrieved.access_token == f"token_{i}"

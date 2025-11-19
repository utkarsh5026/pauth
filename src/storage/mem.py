"""
In-memory token storage implementation.
"""

from typing import Optional, Dict
from models import TokenResponse
from src.storage.base import BaseTokenStorage


class MemoryTokenStorage(BaseTokenStorage):
    """
    In-memory token storage.

    This storage backend keeps tokens in memory and is suitable for:
    - Development and testing
    - Single-process applications
    - Temporary token storage

    Note: Tokens are lost when the application restarts.
    """

    def __init__(self):
        """Initialize the in-memory storage."""
        self._storage: Dict[str, TokenResponse] = {}

    def save_token(self, user_id: str, tokens: TokenResponse) -> None:
        """
        Save tokens for a user in memory.

        Args:
            user_id (str): Unique identifier for the user
            tokens (TokenResponse): Token response to save
        """
        self._storage[user_id] = tokens

    def get_token(self, user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve tokens for a user from memory.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            TokenResponse: Stored tokens, or None if not found
        """
        return self._storage.get(user_id)

    def delete_token(self, user_id: str) -> bool:
        """
        Delete tokens for a user from memory.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            bool: True if deleted, False if not found
        """
        if user_id in self._storage:
            del self._storage[user_id]
            return True
        return False

    def update_token(self, user_id: str, tokens: TokenResponse) -> None:
        """
        Update tokens for a user in memory.

        Args:
            user_id (str): Unique identifier for the user
            tokens (TokenResponse): New token response
        """
        self._storage[user_id] = tokens

    def clear_all(self) -> None:
        """Clear all stored tokens."""
        self._storage.clear()

    def get_all_user_ids(self) -> list[str]:
        """
        Get all user IDs with stored tokens.

        Returns:
            list[str]: List of user IDs
        """
        return list(self._storage.keys())

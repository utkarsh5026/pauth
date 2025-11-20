"""
In-memory token storage implementation.
"""

import copy
import threading
from typing import Dict, Optional

from src.models.token import TokenResponse
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
        self._lock = threading.RLock()

    def save_token(self, user_id: str, token: TokenResponse) -> None:
        """
        Save tokens for a user in memory.

        Args:
            user_id (str): Unique identifier for the user
            token (TokenResponse): Token response to save
        """
        if not user_id:
            raise ValueError("user_id must be provided")

        with self._lock:
            self._storage[user_id] = copy.deepcopy(token)

    def get_token(self, user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve tokens for a user from memory.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            TokenResponse: Stored tokens, or None if not found
        """
        with self._lock:
            token = self._storage.get(user_id)
            return copy.deepcopy(token) if token else None

    def delete_token(self, user_id: str) -> bool:
        """
        Delete tokens for a user from memory.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            bool: True if deleted, False if not found
        """
        with self._lock:
            if user_id in self._storage:
                del self._storage[user_id]
                return True
            return False

    def update_token(self, user_id: str, token: TokenResponse) -> None:
        """
        Update token for a user in memory.

        Args:
            user_id (str): Unique identifier for the user
            token (TokenResponse): New token response
        """
        if not user_id:
            raise ValueError("user_id must be provided")

        with self._lock:
            self._storage[user_id] = copy.deepcopy(token)

    def clear_all(self) -> None:
        """Clear all stored tokens."""
        with self._lock:
            self._storage.clear()

    def get_all_user_ids(self) -> list[str]:
        """
        Get all user IDs with stored tokens.

        Returns:
            list[str]: List of user IDs
        """
        with self._lock:
            return list(self._storage.keys())

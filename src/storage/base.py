"""
Base token storage interface.
"""

from abc import ABC, abstractmethod
from typing import Optional
from models import TokenResponse


class BaseTokenStorage(ABC):
    """
    Abstract base class for token storage backends.

    Implement this class to create custom token storage solutions
    (e.g., Redis, Database, File system, etc.)
    """

    @abstractmethod
    def save_token(self, user_id: str, tokens: TokenResponse) -> None:
        """
        Save tokens for a user.

        Args:
            user_id (str): Unique identifier for the user
            tokens (TokenResponse): Token response to save

        Raises:
            TokenStorageError: If saving fails
        """
        pass

    @abstractmethod
    def get_token(self, user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve tokens for a user.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            TokenResponse: Stored tokens, or None if not found

        Raises:
            TokenStorageError: If retrieval fails
        """
        pass

    @abstractmethod
    def delete_token(self, user_id: str) -> bool:
        """
        Delete tokens for a user.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            bool: True if deleted, False if not found

        Raises:
            TokenStorageError: If deletion fails
        """
        pass

    @abstractmethod
    def update_token(self, user_id: str, tokens: TokenResponse) -> None:
        """
        Update tokens for a user.

        Args:
            user_id (str): Unique identifier for the user
            tokens (TokenResponse): New token response

        Raises:
            TokenStorageError: If update fails
        """
        pass

    def token_exists(self, user_id: str) -> bool:
        """
        Check if tokens exist for a user.

        Args:
            user_id (str): Unique identifier for the user

        Returns:
            bool: True if tokens exist, False otherwise
        """
        return self.get_token(user_id) is not None

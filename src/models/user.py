from typing import Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class UserInfo:
    """
    Represents user information from an OAuth provider.

    Attributes:
        id (str): User's unique identifier
        email (str, optional): User's email address
        name (str, optional): User's full name
        given_name (str, optional): User's first name
        family_name (str, optional): User's last name
        picture (str, optional): URL to user's profile picture
        locale (str, optional): User's locale/language preference
        verified_email (bool, optional): Whether email is verified
        raw_data (dict): Raw user info response from provider
    """

    id: str
    email: Optional[str] = None
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    picture: Optional[str] = None
    locale: Optional[str] = None
    verified_email: Optional[bool] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Convert user info to dictionary.

        Returns:
            dict: Dictionary representation of user info
        """
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "picture": self.picture,
            "locale": self.locale,
            "verified_email": self.verified_email,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UserInfo":
        """
        Create UserInfo from dictionary.

        Args:
            data (dict): Dictionary containing user info data

        Returns:
            UserInfo: User info object
        """
        return cls(
            id=data.get("id", data.get("sub", "")),
            email=data.get("email"),
            name=data.get("name"),
            given_name=data.get("given_name"),
            family_name=data.get("family_name"),
            picture=data.get("picture"),
            locale=data.get("locale"),
            verified_email=data.get("verified_email", data.get("email_verified")),
            raw_data=data,
        )

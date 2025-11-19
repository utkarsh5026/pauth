from typing import Protocol, Literal, Any, Optional
from dataclasses import dataclass

HttpMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH"]


@dataclass
class HTTPResponse:
    """Protocol for HTTP response objects."""

    status_code: int
    content: bytes
    headers: dict[str, str]

    def json(self) -> dict:
        """Parse the response content as JSON and return a dictionary."""
        import json

        return json.loads(self.content)

    @property
    def text(self) -> str:
        """Return the response content as a string."""
        return self.content.decode("utf-8")


class HTTPClient(Protocol):
    """Protocol for HTTP client implementations."""

    def request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse: ...


class AsyncHTTPClient(Protocol):
    """Protocol for asynchronous HTTP client implementations."""

    async def request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse: ...

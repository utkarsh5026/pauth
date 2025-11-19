from typing import Any, Optional
from .protocol import HTTPClient, HttpMethod, AsyncHTTPClient, HTTPResponse


class RequestsAdapter(HTTPClient):
    """HTTP client implementation using the requests library."""

    import requests

    def request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        res = self.requests.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            params=params,
            json=json,
        )
        return HTTPResponse(
            status_code=res.status_code,
            content=res.content,
            headers=dict(res.headers),
        )


class HttpxAdapter(AsyncHTTPClient):
    """Asynchronous HTTP client implementation using the httpx library."""

    import httpx

    async def request(
        self,
        method: HttpMethod,
        url: str,
        data: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        json: Optional[Any] = None,
    ) -> HTTPResponse:
        async with self.httpx.AsyncClient() as client:
            res = await client.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                params=params,
                json=json,
            )
            return HTTPResponse(
                status_code=res.status_code,
                content=res.content,
                headers=dict(res.headers),
            )

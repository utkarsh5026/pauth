import logging
import requests
from typing import Any, Optional, Literal
from collections.abc import Mapping


def make_request(
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"],
    url: str,
    params: Any = None,
    headers: Optional[Mapping[str, str | bytes]] = None,
    data: Any = None,
) -> requests.Response | None:
    """
    Sends a request to the specified URL with the given method, headers, and data.

    :param params: The URL parameters to send with the request.
    :param method: The HTTP method to use for the request (e.g., 'GET', 'POST').
    :param url: The URL to which the request is sent.
    :param headers: A dictionary of HTTP headers to send with the request.
    :param data: The body to attach to the request. Can be a dictionary, a list of tuples,
                 bytes, or a file-like object.
    :return: The JSON response content if the request was successful, None otherwise.
    """

    try:
        response = requests.request(
            method=method, url=url, headers=headers, data=data, params=params
        )
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")
        return None

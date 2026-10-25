import httpx
import pytest


def use_fake_server(
    monkeypatch: pytest.MonkeyPatch, reply: httpx.Response | Exception
) -> list[httpx.Request]:
    """Route httpx to a fake server that answers with `reply`; return its requests."""
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if isinstance(reply, Exception):
            raise reply
        return reply

    real_client = httpx.AsyncClient

    def client_with_fake_transport(**kwargs: object) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_with_fake_transport)
    return requests

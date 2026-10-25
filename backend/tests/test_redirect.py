import ipaddress

import httpx
import pytest

from app.checks.redirect import check_https_redirect
from tests.fakes import use_fake_server

SAFE_IP = ipaddress.ip_address("93.184.215.14")


def redirect_to(location: str, status_code: int = 301) -> httpx.Response:
    """Build a redirect response pointing at `location`."""
    return httpx.Response(status_code, headers={"Location": location})


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
@pytest.mark.parametrize(
    "location", ["https://example.com/", "https://www.example.com/login"]
)
async def test_redirects_to_https(
    monkeypatch: pytest.MonkeyPatch, status_code: int, location: str
) -> None:
    use_fake_server(monkeypatch, redirect_to(location, status_code))
    result = await check_https_redirect("example.com", SAFE_IP)
    assert result.reachable is True
    assert result.redirects_to_https is True
    assert result.status_code == status_code
    assert result.location == location


@pytest.mark.asyncio
async def test_serves_page_over_plain_http(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_server(monkeypatch, httpx.Response(200, text="<html>login</html>"))
    result = await check_https_redirect("example.com", SAFE_IP)
    assert result.reachable is True
    assert result.redirects_to_https is False
    assert result.status_code == 200
    assert result.location is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "http://www.example.com/",  # still plain HTTP
        "https://evil.com/",  # different site
        "https://example.com.evil.com/",  # lookalike host
        "https://notexample.com/",  # suffix match without the dot
        "/login",  # relative path, same plain-HTTP site
    ],
)
async def test_redirect_not_to_https_on_same_site(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    use_fake_server(monkeypatch, redirect_to(location))
    result = await check_https_redirect("example.com", SAFE_IP)
    assert result.reachable is True
    assert result.redirects_to_https is False
    assert result.location == location


@pytest.mark.asyncio
async def test_connects_to_safe_ip_and_does_not_follow_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = use_fake_server(
        monkeypatch, redirect_to("http://169.254.169.254/latest/meta-data/")
    )
    result = await check_https_redirect("example.com", SAFE_IP)
    assert len(requests) == 1
    assert str(requests[0].url) == "http://93.184.215.14/"
    assert requests[0].headers["Host"] == "example.com"
    assert result.redirects_to_https is False


@pytest.mark.asyncio
async def test_ipv6_address_is_bracketed(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = use_fake_server(monkeypatch, httpx.Response(200))
    await check_https_redirect("example.com", ipaddress.ip_address("2606:4700::1"))
    assert requests[0].url.host == "2606:4700::1"
    assert requests[0].url.port is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (httpx.ConnectTimeout("timed out"), "Connection timed out"),
        (httpx.ReadTimeout("timed out"), "Connection timed out"),
        (httpx.ConnectError("connection refused"), "Could not connect over HTTP"),
        (httpx.RemoteProtocolError("bad response"), "Could not connect over HTTP"),
    ],
)
async def test_connection_failure(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    use_fake_server(monkeypatch, error)
    result = await check_https_redirect("example.com", SAFE_IP)
    assert result.reachable is False
    assert result.redirects_to_https is False
    assert result.status_code is None
    assert result.error == message

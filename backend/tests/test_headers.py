import ipaddress

import httpx
import pytest

from app.checks.headers import (
    HomepageFetchError,
    analyze_headers,
    fetch_homepage_headers,
    parse_hsts,
)
from tests.fakes import use_fake_server

SAFE_IP = ipaddress.ip_address("93.184.215.14")

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Server": "nginx",
}


def test_secure_headers() -> None:
    result = analyze_headers(httpx.Headers(SECURE_HEADERS))
    assert result.hsts_max_age == 31536000
    assert result.hsts_include_subdomains is True
    assert result.csp_present is True
    assert result.csp_allows_unsafe_scripts is False
    assert result.nosniff is True
    assert result.clickjacking_protected is True
    assert result.referrer_policy == "strict-origin-when-cross-origin"
    assert result.permissions_policy_present is True
    assert result.leaked_versions == []


def test_no_security_headers() -> None:
    result = analyze_headers(httpx.Headers({}))
    assert result.hsts_max_age is None
    assert result.hsts_include_subdomains is False
    assert result.csp_present is False
    assert result.csp_allows_unsafe_scripts is True
    assert result.nosniff is False
    assert result.clickjacking_protected is False
    assert result.referrer_policy is None
    assert result.permissions_policy_present is False
    assert result.leaked_versions == []


def test_header_names_and_values_ignore_case() -> None:
    result = analyze_headers(
        httpx.Headers(
            {
                "STRICT-TRANSPORT-SECURITY": "MAX-AGE=300; INCLUDESUBDOMAINS",
                "x-content-type-options": "NoSniff",
                "x-frame-options": "sameorigin",
                "referrer-policy": " No-Referrer ",
            }
        )
    )
    assert result.hsts_max_age == 300
    assert result.hsts_include_subdomains is True
    assert result.nosniff is True
    assert result.clickjacking_protected is True
    assert result.referrer_policy == "no-referrer"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000; includeSubDomains; preload", (31536000, True)),
        ('max-age="600"', (600, False)),
        ("max-age=0", (0, False)),
        ("max-age=forever", (None, False)),
        ("max-age=-5", (None, False)),
        ("includeSubDomains", (None, True)),
        ("", (None, False)),
    ],
)
def test_parse_hsts(value: str, expected: tuple[int | None, bool]) -> None:
    assert parse_hsts(value) == expected


@pytest.mark.parametrize(
    ("csp", "unsafe"),
    [
        ("default-src 'self'", False),
        ("default-src 'self'; script-src 'self' cdn.example.com", False),
        ("script-src 'self' 'unsafe-inline'", True),
        ("script-src 'self' 'unsafe-eval'", True),
        ("default-src 'self' 'unsafe-inline'", True),  # fallback for scripts
        ("default-src 'unsafe-inline'; script-src 'self'", False),  # script-src wins
        ("script-src 'nonce-abc123' 'unsafe-inline' 'strict-dynamic'", False),
        ("script-src 'sha256-abc=' 'unsafe-inline'", False),
        ("frame-ancestors 'none'", True),  # no script rules at all
        ("script-src 'self'; script-src 'unsafe-inline'", False),  # first one wins
        ("SCRIPT-SRC 'SELF' 'UNSAFE-INLINE'", True),
    ],
)
def test_csp_unsafe_scripts(csp: str, unsafe: bool) -> None:
    result = analyze_headers(httpx.Headers({"Content-Security-Policy": csp}))
    assert result.csp_present is True
    assert result.csp_allows_unsafe_scripts is unsafe


@pytest.mark.parametrize(
    ("headers", "protected"),
    [
        ({"X-Frame-Options": "DENY"}, True),
        ({"X-Frame-Options": "SAMEORIGIN"}, True),
        ({"X-Frame-Options": "ALLOW-FROM https://example.com"}, False),
        ({"Content-Security-Policy": "frame-ancestors 'self'"}, True),
        ({"Content-Security-Policy": "default-src 'self'"}, False),
    ],
)
def test_clickjacking_protection(headers: dict[str, str], protected: bool) -> None:
    result = analyze_headers(httpx.Headers(headers))
    assert result.clickjacking_protected is protected


def test_nosniff_needs_exact_value() -> None:
    result = analyze_headers(httpx.Headers({"X-Content-Type-Options": "yes"}))
    assert result.nosniff is False


def test_version_leaks() -> None:
    result = analyze_headers(
        httpx.Headers({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"})
    )
    assert result.leaked_versions == ["nginx/1.18.0", "PHP/8.1.2"]


def test_product_name_without_version_is_not_a_leak() -> None:
    result = analyze_headers(
        httpx.Headers({"Server": "cloudflare", "X-Powered-By": "Express"})
    )
    assert result.leaked_versions == []


@pytest.mark.asyncio
async def test_fetch_returns_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_server(monkeypatch, httpx.Response(200, headers=SECURE_HEADERS))
    headers = await fetch_homepage_headers("example.com", SAFE_IP)
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.asyncio
async def test_fetch_connects_to_safe_ip_with_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = use_fake_server(monkeypatch, httpx.Response(200))
    await fetch_homepage_headers("example.com", SAFE_IP)
    assert len(requests) == 1
    assert str(requests[0].url) == "https://93.184.215.14/"
    assert requests[0].headers["Host"] == "example.com"
    assert requests[0].extensions["sni_hostname"] == "example.com"


@pytest.mark.asyncio
async def test_fetch_does_not_follow_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = use_fake_server(
        monkeypatch,
        httpx.Response(
            301,
            headers={
                "Location": "http://169.254.169.254/",
                "Strict-Transport-Security": "max-age=300",
            },
        ),
    )
    headers = await fetch_homepage_headers("example.com", SAFE_IP)
    assert len(requests) == 1
    assert headers["Strict-Transport-Security"] == "max-age=300"


@pytest.mark.asyncio
async def test_fetch_ipv6_address_is_bracketed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = use_fake_server(monkeypatch, httpx.Response(200))
    await fetch_homepage_headers("example.com", ipaddress.ip_address("2606:4700::1"))
    assert requests[0].url.host == "2606:4700::1"
    assert requests[0].url.port is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (httpx.ConnectTimeout("timed out"), "Connection timed out"),
        (httpx.ReadTimeout("timed out"), "Connection timed out"),
        (
            httpx.ConnectError("certificate verify failed"),
            "Could not connect over HTTPS",
        ),
        (httpx.RemoteProtocolError("bad response"), "Could not connect over HTTPS"),
    ],
)
async def test_fetch_failure(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    use_fake_server(monkeypatch, error)
    with pytest.raises(HomepageFetchError, match=message):
        await fetch_homepage_headers("example.com", SAFE_IP)

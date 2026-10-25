import ipaddress

import httpx
import pytest

from app.checks.cookies import CookieFlags, analyze_cookies, parse_set_cookie
from app.checks.headers import fetch_homepage_headers
from tests.fakes import use_fake_server

SAFE_IP = ipaddress.ip_address("93.184.215.14")


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (
            "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
            CookieFlags(name="session", secure=True, http_only=True, same_site="lax"),
        ),
        (
            "theme=dark",
            CookieFlags(name="theme", secure=False, http_only=False, same_site=None),
        ),
        (
            " id = 42 ;SECURE;  httponly ; SameSite = STRICT ",
            CookieFlags(name="id", secure=True, http_only=True, same_site="strict"),
        ),
        (
            "token=YWJjZA==; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure",
            CookieFlags(name="token", secure=True, http_only=False, same_site=None),
        ),
        (
            "a=1; SameSite=None; Secure",
            CookieFlags(name="a", secure=True, http_only=False, same_site="none"),
        ),
        (
            "a=1; SameSite=",
            CookieFlags(name="a", secure=False, http_only=False, same_site=None),
        ),
        ("junk", None),
        ("=abc", None),
        ("", None),
        ("; Secure", None),
    ],
)
def test_parse_set_cookie(header: str, expected: CookieFlags | None) -> None:
    assert parse_set_cookie(header) == expected


def test_cookie_value_is_never_stored() -> None:
    cookie = parse_set_cookie("session=s3cr3t-token; Secure")
    assert cookie is not None
    assert "s3cr3t-token" not in cookie.model_dump_json()


def test_analyze_cookies() -> None:
    headers = httpx.Headers(
        [
            ("Set-Cookie", "session=abc; Secure; HttpOnly"),
            ("set-cookie", "junk"),
            ("SET-COOKIE", "csrf=xyz; SameSite=Strict"),
        ]
    )
    assert [cookie.name for cookie in analyze_cookies(headers)] == ["session", "csrf"]
    assert analyze_cookies(httpx.Headers({})) == []


@pytest.mark.asyncio
async def test_cookies_from_fetched_homepage(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_server(
        monkeypatch,
        httpx.Response(
            200,
            headers=[
                ("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", "theme=dark; Expires=Wed, 21 Oct 2026 07:28:00 GMT"),
            ],
        ),
    )
    headers = await fetch_homepage_headers("example.com", SAFE_IP)
    cookies = analyze_cookies(headers)
    assert [cookie.name for cookie in cookies] == ["session", "theme"]
    assert cookies[0].secure is True
    assert cookies[1].secure is False

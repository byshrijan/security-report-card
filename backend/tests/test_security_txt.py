import ipaddress
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest

from app.checks.security_txt import (
    MAX_BODY_BYTES,
    SecurityTxtFetchError,
    check_security_txt,
    fetch_security_txt,
    parse_expires,
    parse_security_txt,
)
from tests.fakes import use_fake_server

SAFE_IP = ipaddress.ip_address("93.184.215.14")

VALID_FILE = """\
# Report security problems to us
Contact: mailto:security@example.com
CONTACT: https://example.com/report
Expires: 2099-12-31T23:59:59Z
"""


def streamed_text(text: str) -> httpx.Response:
    """A text/plain 200 whose body arrives in 4 KB chunks, like a real server's."""
    data = text.encode()

    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(data), 4096):
            yield data[start : start + 4096]

    return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=chunks())


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2027-12-31T23:59:59Z", datetime(2027, 12, 31, 23, 59, 59, tzinfo=UTC)),
        ("2026-11-24T18:19:24z", datetime(2026, 11, 24, 18, 19, 24, tzinfo=UTC)),
        ("2027-12-31T23:59:59", datetime(2027, 12, 31, 23, 59, 59, tzinfo=UTC)),
        ("next year", None),
        ("", None),
    ],
)
def test_parse_expires(value: str, expected: datetime | None) -> None:
    assert parse_expires(value) == expected


def test_parse_security_txt() -> None:
    contacts, expires = parse_security_txt(VALID_FILE)
    assert contacts == ["mailto:security@example.com", "https://example.com/report"]
    assert expires == datetime(2099, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_parse_security_txt_skips_comments_and_empty_values() -> None:
    contacts, expires = parse_security_txt("# Contact: old@example.com\nContact:\n")
    assert contacts == []
    assert expires is None


@pytest.mark.asyncio
async def test_valid_file(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = use_fake_server(monkeypatch, streamed_text(VALID_FILE))
    result = await check_security_txt("example.com", SAFE_IP)
    assert result.found is True
    assert len(result.contacts) == 2
    assert result.expired is False
    assert requests[0].url.path == "/.well-known/security.txt"
    assert requests[0].headers["host"] == "example.com"
    assert requests[0].headers["accept-encoding"] == "identity"


@pytest.mark.asyncio
async def test_expired_file(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "Contact: mailto:security@example.com\nExpires: 2020-01-01T00:00:00Z\n"
    use_fake_server(monkeypatch, streamed_text(text))
    result = await check_security_txt("example.com", SAFE_IP)
    assert result.found is True
    assert result.expired is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(404, text="Not found"),
        httpx.Response(200, html="<html>Welcome</html>"),
        httpx.Response(301, headers={"Location": "https://www.example.com/"}),
    ],
    ids=["not-found", "html-page", "redirect"],
)
async def test_missing_file(
    monkeypatch: pytest.MonkeyPatch, reply: httpx.Response
) -> None:
    use_fake_server(monkeypatch, reply)
    result = await check_security_txt("example.com", SAFE_IP)
    assert result.found is False
    assert result.contacts == []


@pytest.mark.asyncio
async def test_body_is_cut_at_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    huge = "A" * (MAX_BODY_BYTES * 3)
    use_fake_server(monkeypatch, streamed_text(huge))
    text = await fetch_security_txt("example.com", SAFE_IP)
    assert text is not None
    assert len(text) == MAX_BODY_BYTES


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (httpx.ConnectTimeout("timed out"), "timed out"),
        (httpx.ConnectError("refused"), "Could not connect"),
    ],
)
async def test_connection_failures_raise_fetch_error(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    use_fake_server(monkeypatch, error)
    with pytest.raises(SecurityTxtFetchError, match=message):
        await check_security_txt("example.com", SAFE_IP)

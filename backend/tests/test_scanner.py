import asyncio
import ipaddress
from collections.abc import Callable, Coroutine
from typing import Any

import httpx
import pytest

from app import scanner
from app.checks.dns_records import (
    CaaResult,
    DnsLookupError,
    DnssecResult,
    EmailDnsResult,
    parse_dmarc,
    parse_spf,
)
from app.checks.redirect import RedirectResult
from app.checks.security_txt import SecurityTxtResult
from app.checks.tls import CertificateResult, OldVersionsResult
from app.core.security import UnsafeDomainError

SAFE_IP = ipaddress.ip_address("93.184.215.14")

type FakeCheck = Callable[..., Coroutine[Any, Any, object]]


def returns(value: object) -> FakeCheck:
    async def fake(*args: object) -> object:
        return value

    return fake


def raises(error: Exception) -> FakeCheck:
    async def fake(*args: object) -> object:
        raise error

    return fake


async def hangs(*args: object) -> object:
    await asyncio.Event().wait()


@pytest.fixture
def fake_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace every network call in the scanner with an instant fake."""
    fakes = {
        "resolve_safe_ip": returns(SAFE_IP),
        "check_certificate": returns(CertificateResult(reachable=True, trusted=True)),
        "check_old_versions": returns(OldVersionsResult(tls1_0=False, tls1_1=False)),
        "check_https_redirect": returns(
            RedirectResult(reachable=True, redirects_to_https=True)
        ),
        "fetch_homepage_headers": returns(
            httpx.Headers(
                {"X-Content-Type-Options": "nosniff", "Set-Cookie": "id=1; Secure"}
            )
        ),
        "check_email_dns": returns(
            EmailDnsResult(spf=parse_spf([]), dmarc=parse_dmarc([]))
        ),
        "check_caa": returns(CaaResult(found_at=None, issuers=[])),
        "check_dnssec": returns(DnssecResult(enabled=True)),
        "check_security_txt": returns(
            SecurityTxtResult(found=False, contacts=[], expires=None, expired=False)
        ),
    }
    for name, fake in fakes.items():
        monkeypatch.setattr(scanner, name, fake)


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_checks")
async def test_run_scan_collects_every_check() -> None:
    result = await scanner.run_scan("example.com")

    assert result.errors == {}
    assert all(value is not None for value in result.model_dump().values())
    assert result.homepage is not None
    assert result.homepage.headers.nosniff
    assert result.homepage.cookies[0].name == "id"


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_checks")
@pytest.mark.parametrize(
    ("function", "field", "error", "message"),
    [
        (
            "check_caa",
            "caa",
            DnsLookupError("DNS lookup timed out"),
            "DNS lookup timed out",
        ),
        (
            "check_certificate",
            "certificate",
            RuntimeError("internal detail"),
            "Check failed unexpectedly",
        ),
    ],
)
async def test_failing_check_does_not_stop_the_scan(
    monkeypatch: pytest.MonkeyPatch,
    function: str,
    field: str,
    error: Exception,
    message: str,
) -> None:
    monkeypatch.setattr(scanner, function, raises(error))

    result = await scanner.run_scan("example.com")

    assert getattr(result, field) is None
    assert result.errors == {field: message}
    assert result.redirect is not None
    assert "internal detail" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_checks")
async def test_hanging_check_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "CHECK_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(scanner, "check_dnssec", hangs)

    result = await scanner.run_scan("example.com")

    assert result.dnssec is None
    assert result.errors == {"dnssec": "Check timed out"}
    assert result.caa is not None


@pytest.mark.asyncio
@pytest.mark.usefixtures("fake_checks")
async def test_unsafe_domain_stops_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    error = UnsafeDomainError("Domain points to a non-public IP address")
    monkeypatch.setattr(scanner, "resolve_safe_ip", raises(error))

    with pytest.raises(UnsafeDomainError):
        await scanner.run_scan("internal.example.com")

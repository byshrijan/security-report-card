import asyncio
import ipaddress
import ssl
from datetime import UTC, datetime, timedelta

import pytest

from app.checks import tls
from app.checks.tls import check_certificate

SAFE_IP = ipaddress.ip_address("93.184.215.14")


def make_cert(days_left: int) -> dict[str, object]:
    """Build a certificate dict shaped like the one Python's ssl returns."""
    expires = datetime.now(UTC) + timedelta(days=days_left, hours=1)
    return {
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R11"),),
        ),
        "notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT"),
    }


class FakeWriter:
    """Stands in for the connection; our code only reads the cert and closes."""

    def __init__(self, cert: dict[str, object]) -> None:
        self.cert = cert

    def get_extra_info(self, name: str) -> dict[str, object]:
        return self.cert

    def close(self) -> None:
        pass


def use_fake_server(
    monkeypatch: pytest.MonkeyPatch, cert: dict[str, object]
) -> list[dict[str, object]]:
    """Fake a server with a valid cert; return a list that records each call."""
    calls: list[dict[str, object]] = []

    async def fake_open_connection(
        host: str, port: int, **kwargs: object
    ) -> tuple[None, FakeWriter]:
        calls.append({"host": host, "port": port, **kwargs})
        return None, FakeWriter(cert)

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return calls


def use_failing_server(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Fake a server where connecting always raises `error`."""

    async def fake_open_connection(
        host: str, port: int, **kwargs: object
    ) -> tuple[None, FakeWriter]:
        raise error

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)


def cert_error(message: str) -> ssl.SSLCertVerificationError:
    """Build the error ssl raises when a certificate fails verification."""
    error = ssl.SSLCertVerificationError()
    error.verify_message = message
    return error


@pytest.mark.asyncio
async def test_valid_certificate(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_server(monkeypatch, make_cert(days_left=30))
    result = await check_certificate("example.com", SAFE_IP)
    assert result.reachable is True
    assert result.trusted is True
    assert result.error is None
    assert result.issuer == "Let's Encrypt"
    assert result.days_until_expiry == 30


@pytest.mark.asyncio
async def test_connects_to_safe_ip_but_verifies_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = use_fake_server(monkeypatch, make_cert(days_left=30))
    await check_certificate("example.com", SAFE_IP)
    assert len(calls) == 1
    assert calls[0]["host"] == "93.184.215.14"
    assert calls[0]["port"] == 443
    assert calls[0]["server_hostname"] == "example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message",
    [
        "certificate has expired",
        "Hostname mismatch, certificate is not valid for 'example.com'.",
        "self-signed certificate",
    ],
)
async def test_untrusted_certificate(
    monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    use_failing_server(monkeypatch, cert_error(message))
    result = await check_certificate("example.com", SAFE_IP)
    assert result.reachable is True
    assert result.trusted is False
    assert result.error == message
    assert result.days_until_expiry is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error", [ConnectionRefusedError(), ssl.SSLError("handshake failure")]
)
async def test_connection_failure(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    use_failing_server(monkeypatch, error)
    result = await check_certificate("example.com", SAFE_IP)
    assert result.reachable is False
    assert result.trusted is False
    assert result.error == "Could not connect over HTTPS"


@pytest.mark.asyncio
async def test_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def never_answers(
        host: str, port: int, **kwargs: object
    ) -> tuple[None, FakeWriter]:
        await asyncio.sleep(10)
        raise AssertionError("the timeout should have stopped this")

    monkeypatch.setattr(asyncio, "open_connection", never_answers)
    monkeypatch.setattr(tls, "TLS_TIMEOUT_SECONDS", 0.01)
    result = await check_certificate("example.com", SAFE_IP)
    assert result.reachable is False
    assert result.error == "Connection timed out"

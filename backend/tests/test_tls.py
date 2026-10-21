import asyncio
import ipaddress
import ssl
from datetime import UTC, datetime, timedelta

import pytest

from app.checks import tls
from app.checks.tls import accepts_tls_version, check_certificate, check_old_versions

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


class FakeTransport:
    """Stands in for the network connection underneath the writer."""

    def abort(self) -> None:
        pass


class FakeWriter:
    """Stands in for the connection; our code only reads the cert and closes."""

    def __init__(self, cert: dict[str, object]) -> None:
        self.cert = cert
        self.transport = FakeTransport()

    def get_extra_info(self, name: str) -> dict[str, object]:
        return self.cert


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


@pytest.mark.asyncio
async def test_old_versions_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_server(monkeypatch, make_cert(days_left=30))
    result = await check_old_versions("example.com", SAFE_IP)
    assert result.tls1_0 is True
    assert result.tls1_1 is True


@pytest.mark.asyncio
async def test_handshake_is_pinned_to_one_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = use_fake_server(monkeypatch, make_cert(days_left=30))
    await accepts_tls_version("example.com", SAFE_IP, ssl.TLSVersion.TLSv1_1)
    context = calls[0]["ssl"]
    assert isinstance(context, ssl.SSLContext)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_1
    assert context.maximum_version == ssl.TLSVersion.TLSv1_1
    assert calls[0]["host"] == "93.184.215.14"
    assert calls[0]["server_hostname"] == "example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [ssl.SSLError("tlsv1 alert protocol version"), ConnectionResetError()],
)
async def test_old_versions_refused(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    use_failing_server(monkeypatch, error)
    result = await check_old_versions("example.com", SAFE_IP)
    assert result.tls1_0 is False
    assert result.tls1_1 is False


@pytest.mark.asyncio
async def test_old_versions_timeout_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def never_answers(
        host: str, port: int, **kwargs: object
    ) -> tuple[None, FakeWriter]:
        await asyncio.sleep(10)
        raise AssertionError("timeout did not fire")

    monkeypatch.setattr(asyncio, "open_connection", never_answers)
    monkeypatch.setattr(tls, "TLS_TIMEOUT_SECONDS", 0.01)
    result = await check_old_versions("example.com", SAFE_IP)
    assert result.tls1_0 is None
    assert result.tls1_1 is None

import asyncio
import ssl
import warnings
from datetime import UTC, datetime

from pydantic import BaseModel

from app.core.security import IPAddress

HTTPS_PORT = 443
TLS_TIMEOUT_SECONDS = 5.0


class CertificateResult(BaseModel):
    """What we learned about a site's TLS certificate."""

    reachable: bool
    trusted: bool
    error: str | None = None
    issuer: str | None = None
    expires_at: datetime | None = None
    days_until_expiry: int | None = None


class OldVersionsResult(BaseModel):
    """Whether the site still accepts outdated TLS versions (None = unknown)."""

    tls1_0: bool | None
    tls1_1: bool | None


async def check_certificate(domain: str, ip: IPAddress) -> CertificateResult:
    """Do one TLS handshake with `ip` and verify its certificate for `domain`."""
    context = ssl.create_default_context()
    try:
        async with asyncio.timeout(TLS_TIMEOUT_SECONDS):
            _, writer = await asyncio.open_connection(
                str(ip), HTTPS_PORT, ssl=context, server_hostname=domain
            )
    except ssl.SSLCertVerificationError as error:
        return CertificateResult(
            reachable=True, trusted=False, error=error.verify_message
        )
    except TimeoutError:
        return CertificateResult(
            reachable=False, trusted=False, error="Connection timed out"
        )
    except OSError:
        return CertificateResult(
            reachable=False, trusted=False, error="Could not connect over HTTPS"
        )

    cert = writer.get_extra_info("peercert")
    writer.transport.abort()

    issuer = {key: value for part in cert["issuer"] for key, value in part}
    expires_at = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=UTC
    )
    return CertificateResult(
        reachable=True,
        trusted=True,
        issuer=issuer.get("organizationName"),
        expires_at=expires_at,
        days_until_expiry=(expires_at - datetime.now(UTC)).days,
    )


async def accepts_tls_version(
    domain: str, ip: IPAddress, version: ssl.TLSVersion
) -> bool | None:
    """Return True if the server completes a handshake using only `version`.

    Returns None if we couldn't tell because the server didn't answer in time.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Modern OpenSSL refuses old versions by default; lower that for this test.
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    with warnings.catch_warnings(action="ignore", category=DeprecationWarning):
        context.minimum_version = version
        context.maximum_version = version

    try:
        async with asyncio.timeout(TLS_TIMEOUT_SECONDS):
            _, writer = await asyncio.open_connection(
                str(ip), HTTPS_PORT, ssl=context, server_hostname=domain
            )
    except TimeoutError:
        return None
    except OSError:
        return False

    writer.transport.abort()
    return True


async def check_old_versions(domain: str, ip: IPAddress) -> OldVersionsResult:
    """Check whether the site still accepts TLS 1.0 and TLS 1.1."""
    return OldVersionsResult(
        tls1_0=await accepts_tls_version(domain, ip, ssl.TLSVersion.TLSv1),
        tls1_1=await accepts_tls_version(domain, ip, ssl.TLSVersion.TLSv1_1),
    )

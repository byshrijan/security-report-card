import asyncio
import ssl
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
    writer.close()

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

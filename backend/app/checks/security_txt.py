from datetime import UTC, datetime

import httpx
from pydantic import BaseModel

from app.core.security import IPAddress

HTTPS_PORT = 443
HTTP_TIMEOUT_SECONDS = 5.0
MAX_BODY_BYTES = 32 * 1024
SECURITY_TXT_PATH = "/.well-known/security.txt"


class SecurityTxtFetchError(Exception):
    """Raised when the site can't be reached over HTTPS."""


class SecurityTxtResult(BaseModel):
    """Facts about a site's /.well-known/security.txt file."""

    found: bool
    contacts: list[str]
    expires: datetime | None
    expired: bool


def parse_expires(value: str) -> datetime | None:
    """Parse an RFC 3339 date like 2027-12-31T23:59:59Z; None if invalid."""
    try:
        # RFC 3339 allows a lowercase "t" and "z"; fromisoformat only accepts "Z".
        expires = datetime.fromisoformat(value.upper())
    except ValueError:
        return None
    # RFC 3339 requires an offset; read a missing one as UTC so comparisons work.
    return expires if expires.tzinfo else expires.replace(tzinfo=UTC)


def parse_security_txt(text: str) -> tuple[list[str], datetime | None]:
    """Return the Contact values and the Expires date from a security.txt body."""
    contacts: list[str] = []
    expires = None
    for line in text.splitlines():
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "contact" and value:
            contacts.append(value)
        elif name == "expires" and expires is None:
            expires = parse_expires(value)
    return contacts, expires


async def fetch_security_txt(domain: str, ip: IPAddress) -> str | None:
    """Fetch security.txt for `domain` from `ip`; None if the site has none."""
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    url = f"https://{host}:{HTTPS_PORT}{SECURITY_TXT_PATH}"
    # identity + aiter_raw: bytes arrive uncompressed, so a gzip bomb can't inflate.
    try:
        async with (
            httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
            ) as client,
            client.stream(
                "GET",
                url,
                headers={"Host": domain, "Accept-Encoding": "identity"},
                extensions={"sni_hostname": domain},
            ) as response,
        ):
            # Many sites serve their HTML homepage for every path; require plain text.
            is_text = response.headers.get("content-type", "").startswith("text/plain")
            if response.status_code != 200 or not is_text:
                return None
            body = b""
            async for chunk in response.aiter_raw():
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
    except httpx.TimeoutException:
        raise SecurityTxtFetchError("Connection timed out") from None
    except httpx.HTTPError:
        raise SecurityTxtFetchError("Could not connect over HTTPS") from None
    return body[:MAX_BODY_BYTES].decode(errors="replace")


async def check_security_txt(domain: str, ip: IPAddress) -> SecurityTxtResult:
    """Fetch the site's security.txt and report its contacts and expiry."""
    text = await fetch_security_txt(domain, ip)
    if text is None:
        return SecurityTxtResult(found=False, contacts=[], expires=None, expired=False)
    contacts, expires = parse_security_txt(text)
    return SecurityTxtResult(
        found=True,
        contacts=contacts,
        expires=expires,
        expired=expires is not None and expires < datetime.now(UTC),
    )

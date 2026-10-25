from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel

from app.core.security import IPAddress

HTTP_PORT = 80
HTTP_TIMEOUT_SECONDS = 5.0


class RedirectResult(BaseModel):
    """How a site responds to a plain-HTTP request on port 80."""

    reachable: bool
    redirects_to_https: bool
    status_code: int | None = None
    location: str | None = None
    error: str | None = None


def is_https_url_for(location: str, domain: str) -> bool:
    """True if `location` is an https:// URL on `domain` or one of its subdomains."""
    url = urlsplit(location)
    host = url.hostname or ""
    return url.scheme == "https" and (host == domain or host.endswith(f".{domain}"))


async def check_https_redirect(domain: str, ip: IPAddress) -> RedirectResult:
    """Send one plain-HTTP request to `ip` and report whether it redirects to HTTPS."""
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    url = f"http://{host}:{HTTP_PORT}/"
    # Redirects are recorded, never followed: the target hasn't passed the SSRF guard.
    # trust_env=False stops proxy env vars from routing around the validated IP.
    try:
        async with (
            httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
            ) as client,
            client.stream("GET", url, headers={"Host": domain}) as response,
        ):
            status_code = response.status_code
            location = response.headers.get("location")
            is_redirect = response.is_redirect
    except httpx.TimeoutException:
        return RedirectResult(
            reachable=False, redirects_to_https=False, error="Connection timed out"
        )
    except httpx.HTTPError:
        return RedirectResult(
            reachable=False,
            redirects_to_https=False,
            error="Could not connect over HTTP",
        )

    return RedirectResult(
        reachable=True,
        redirects_to_https=is_redirect and is_https_url_for(location or "", domain),
        status_code=status_code,
        location=location,
    )

import httpx
from pydantic import BaseModel

from app.core.security import IPAddress

HTTPS_PORT = 443
HTTP_TIMEOUT_SECONDS = 5.0
VERSION_HEADERS = ("server", "x-powered-by")


class HeadersResult(BaseModel):
    """Security-relevant facts from the homepage's response headers."""

    hsts_max_age: int | None
    hsts_include_subdomains: bool
    csp_present: bool
    csp_allows_unsafe_scripts: bool
    nosniff: bool
    clickjacking_protected: bool
    referrer_policy: str | None
    permissions_policy_present: bool
    leaked_versions: list[str]


class HomepageFetchError(Exception):
    """Raised when the homepage can't be fetched over HTTPS."""


async def fetch_homepage_headers(domain: str, ip: IPAddress) -> httpx.Headers:
    """Send one HTTPS GET for `domain` to `ip` and return the response headers."""
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    url = f"https://{host}:{HTTPS_PORT}/"
    # sni_hostname: SNI and the certificate check use the domain, not the IP.
    # The body is never read, so a huge page can't exhaust memory.
    try:
        async with (
            httpx.AsyncClient(
                timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
            ) as client,
            client.stream(
                "GET",
                url,
                headers={"Host": domain},
                extensions={"sni_hostname": domain},
            ) as response,
        ):
            return response.headers
    except httpx.TimeoutException:
        raise HomepageFetchError("Connection timed out") from None
    except httpx.HTTPError:
        raise HomepageFetchError("Could not connect over HTTPS") from None


def parse_hsts(value: str) -> tuple[int | None, bool]:
    """Return (max-age in seconds, includeSubDomains) from an HSTS header."""
    max_age = None
    include_subdomains = False
    for directive in value.split(";"):
        name, _, arg = directive.partition("=")
        name = name.strip().lower()
        if name == "max-age":
            arg = arg.strip().strip('"')
            if arg.isdecimal():
                max_age = int(arg)
        elif name == "includesubdomains":
            include_subdomains = True
    return max_age, include_subdomains


def parse_csp(value: str) -> dict[str, list[str]]:
    """Map each CSP directive name to its list of sources."""
    directives: dict[str, list[str]] = {}
    for directive in value.split(";"):
        parts = directive.lower().split()
        # Browsers ignore a repeated directive, so the first one wins.
        if parts and parts[0] not in directives:
            directives[parts[0]] = parts[1:]
    return directives


def allows_unsafe_scripts(csp: dict[str, list[str]]) -> bool:
    """True if the policy lets inline or eval'd scripts run."""
    sources = csp.get("script-src", csp.get("default-src"))
    if sources is None:
        return True
    if "'unsafe-eval'" in sources:
        return True
    # Browsers ignore 'unsafe-inline' when a nonce or hash is present.
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha")) for s in sources)
    return "'unsafe-inline'" in sources and not has_nonce_or_hash


def analyze_headers(headers: httpx.Headers) -> HeadersResult:
    """Turn the homepage's response headers into security facts."""
    hsts_max_age, hsts_include_subdomains = parse_hsts(
        headers.get("strict-transport-security", "")
    )
    csp_header = headers.get("content-security-policy")
    csp = parse_csp(csp_header or "")
    content_type_options = headers.get("x-content-type-options", "").strip().lower()
    frame_options = headers.get("x-frame-options", "").strip().lower()
    referrer_policy = headers.get("referrer-policy")

    return HeadersResult(
        hsts_max_age=hsts_max_age,
        hsts_include_subdomains=hsts_include_subdomains,
        csp_present=csp_header is not None,
        csp_allows_unsafe_scripts=allows_unsafe_scripts(csp),
        nosniff=content_type_options == "nosniff",
        clickjacking_protected=(
            frame_options in ("deny", "sameorigin") or "frame-ancestors" in csp
        ),
        referrer_policy=referrer_policy.strip().lower() if referrer_policy else None,
        permissions_policy_present="permissions-policy" in headers,
        leaked_versions=[
            headers[name]
            for name in VERSION_HEADERS
            if any(char.isdigit() for char in headers.get(name, ""))
        ],
    )

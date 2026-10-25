import asyncio
import logging
from collections.abc import Awaitable

from pydantic import BaseModel

from app.checks.cookies import CookieFlags, analyze_cookies
from app.checks.dns_records import (
    CaaResult,
    DnsLookupError,
    DnssecResult,
    EmailDnsResult,
    check_caa,
    check_dnssec,
    check_email_dns,
)
from app.checks.headers import (
    HeadersResult,
    HomepageFetchError,
    analyze_headers,
    fetch_homepage_headers,
)
from app.checks.redirect import RedirectResult, check_https_redirect
from app.checks.security_txt import (
    SecurityTxtFetchError,
    SecurityTxtResult,
    check_security_txt,
)
from app.checks.tls import (
    CertificateResult,
    OldVersionsResult,
    check_certificate,
    check_old_versions,
)
from app.core.security import IPAddress, resolve_safe_ip

# Above every single network timeout, so the check's own error message wins.
CHECK_TIMEOUT_SECONDS = 15.0
EXPECTED_ERRORS = (HomepageFetchError, DnsLookupError, SecurityTxtFetchError)

logger = logging.getLogger(__name__)


class HomepageResult(BaseModel):
    """Header and cookie facts from one homepage request."""

    headers: HeadersResult
    cookies: list[CookieFlags]


class ScanResult(BaseModel):
    """Every check's result for one domain; None means that check failed."""

    domain: str
    certificate: CertificateResult | None
    old_versions: OldVersionsResult | None
    redirect: RedirectResult | None
    homepage: HomepageResult | None
    email: EmailDnsResult | None
    caa: CaaResult | None
    dnssec: DnssecResult | None
    security_txt: SecurityTxtResult | None
    errors: dict[str, str]


async def check_homepage(domain: str, ip: IPAddress) -> HomepageResult:
    """Fetch the homepage once and analyze both its headers and its cookies."""
    headers = await fetch_homepage_headers(domain, ip)
    return HomepageResult(
        headers=analyze_headers(headers), cookies=analyze_cookies(headers)
    )


async def run_check[T](
    name: str, check: Awaitable[T], errors: dict[str, str]
) -> T | None:
    """Await one check with a time limit; record any failure instead of raising."""
    try:
        async with asyncio.timeout(CHECK_TIMEOUT_SECONDS):
            return await check
    except TimeoutError:
        errors[name] = "Check timed out"
    except EXPECTED_ERRORS as error:
        errors[name] = str(error)
    except Exception:
        # Unexpected means a bug: keep the details in the server log, not the report.
        logger.exception("Check %r crashed", name)
        errors[name] = "Check failed unexpectedly"
    return None


async def run_scan(domain: str) -> ScanResult:
    """Run every check on `domain` at the same time and collect the results.

    Raises UnsafeDomainError if the domain can't be scanned safely.
    """
    ip = await resolve_safe_ip(domain)
    errors: dict[str, str] = {}
    (
        certificate,
        old_versions,
        redirect,
        homepage,
        email,
        caa,
        dnssec,
        security_txt,
    ) = await asyncio.gather(
        run_check("certificate", check_certificate(domain, ip), errors),
        run_check("old_versions", check_old_versions(domain, ip), errors),
        run_check("redirect", check_https_redirect(domain, ip), errors),
        run_check("homepage", check_homepage(domain, ip), errors),
        run_check("email", check_email_dns(domain), errors),
        run_check("caa", check_caa(domain), errors),
        run_check("dnssec", check_dnssec(domain), errors),
        run_check("security_txt", check_security_txt(domain, ip), errors),
    )
    return ScanResult(
        domain=domain,
        certificate=certificate,
        old_versions=old_versions,
        redirect=redirect,
        homepage=homepage,
        email=email,
        caa=caa,
        dnssec=dnssec,
        security_txt=security_txt,
        errors=errors,
    )

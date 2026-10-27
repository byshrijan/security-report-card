from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from app.checks.dns_records import CaaResult, DnssecResult, EmailDnsResult
from app.checks.redirect import RedirectResult
from app.checks.security_txt import SecurityTxtResult
from app.checks.tls import CertificateResult, OldVersionsResult
from app.scanner import HomepageResult, ScanResult

GRADE_THRESHOLDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D")]
EXPIRY_WARNING_DAYS = 30
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


class Status(StrEnum):
    PASS = "pass"  # noqa: S105
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"


class Finding(BaseModel):
    """One graded line of the report."""

    id: str
    category: str
    title: str
    status: Status
    detail: str
    points: int
    max_points: int
    fix: str | None


class Report(BaseModel):
    """The graded result of one scan."""

    domain: str
    score: int
    grade: str
    findings: list[Finding]


def points_for(status: Status, max_points: int) -> int:
    """Full points for a pass, half for a warning, none otherwise."""
    if status is Status.PASS:
        return max_points
    if status is Status.WARN:
        return max_points // 2
    return 0


def grade_for(score: int, critical_failure: bool) -> str:
    """Map a 0-100 score to A-F; a critical failure is always an F."""
    if critical_failure:
        return "F"
    for minimum, grade in GRADE_THRESHOLDS:
        if score >= minimum:
            return grade
    return "F"


type Verdict = tuple[Status, str]


@dataclass(frozen=True)
class Rule:
    """How to grade one finding, and how to fix it when it doesn't pass."""

    id: str
    category: str
    title: str
    max_points: int
    check: str
    score: Callable[[Any], Verdict]
    fix: str
    critical: bool = False


def score_certificate(cert: CertificateResult) -> Verdict:
    if not cert.reachable:
        return Status.FAIL, cert.error or "Could not connect over HTTPS"
    if not cert.trusted:
        return Status.FAIL, f"Certificate is not trusted: {cert.error}"
    days = cert.days_until_expiry
    if days is not None and days < EXPIRY_WARNING_DAYS:
        return Status.WARN, f"Certificate expires in {days} days"
    return Status.PASS, f"Trusted certificate, expires in {days} days"


def score_old_versions(old: OldVersionsResult) -> Verdict:
    if old.tls1_0 or old.tls1_1:
        return Status.FAIL, "Server still accepts TLS 1.0 or 1.1"
    if old.tls1_0 is None or old.tls1_1 is None:
        return Status.ERROR, "Server did not answer the old-version test in time"
    return Status.PASS, "TLS 1.0 and 1.1 are rejected"


def score_redirect(redirect: RedirectResult) -> Verdict:
    if not redirect.reachable:
        return Status.WARN, "Plain HTTP (port 80) is not reachable"
    if redirect.redirects_to_https:
        return Status.PASS, "HTTP requests redirect to HTTPS"
    return Status.FAIL, "HTTP requests are not redirected to HTTPS"


TLS_RULES = [
    Rule(
        id="certificate",
        category="HTTPS",
        title="Trusted TLS certificate",
        max_points=20,
        check="certificate",
        score=score_certificate,
        fix=(
            "Install a certificate from a trusted authority such as Let's Encrypt "
            "that covers this exact domain, and turn on automatic renewal."
        ),
        critical=True,
    ),
    Rule(
        id="old_tls",
        category="HTTPS",
        title="Old TLS versions disabled",
        max_points=10,
        check="old_versions",
        score=score_old_versions,
        fix=(
            "Turn off TLS 1.0 and 1.1 in your web server or CDN settings "
            "and allow only TLS 1.2 and 1.3."
        ),
    ),
    Rule(
        id="https_redirect",
        category="HTTPS",
        title="HTTP redirects to HTTPS",
        max_points=10,
        check="redirect",
        score=score_redirect,
        fix=(
            "Make your web server answer every http:// request with a "
            "301 redirect to the same https:// URL."
        ),
    ),
]


def score_hsts(page: HomepageResult) -> Verdict:
    max_age = page.headers.hsts_max_age
    if max_age is None:
        return Status.FAIL, "No Strict-Transport-Security header"
    if max_age < HSTS_MIN_MAX_AGE:
        return Status.WARN, f"HSTS max-age is {max_age} seconds (under 180 days)"
    return Status.PASS, f"HSTS max-age is {max_age} seconds"


def score_csp(page: HomepageResult) -> Verdict:
    if not page.headers.csp_present:
        return Status.FAIL, "No Content-Security-Policy header"
    if page.headers.csp_allows_unsafe_scripts:
        return Status.WARN, "Content-Security-Policy allows unsafe scripts"
    return Status.PASS, "Content-Security-Policy blocks unsafe scripts"


def score_nosniff(page: HomepageResult) -> Verdict:
    if page.headers.nosniff:
        return Status.PASS, "X-Content-Type-Options is set to nosniff"
    return Status.FAIL, "X-Content-Type-Options: nosniff is missing"


def score_clickjacking(page: HomepageResult) -> Verdict:
    if page.headers.clickjacking_protected:
        return Status.PASS, "Other sites can't load this page in a frame"
    return Status.FAIL, "Any site can load this page in a hidden frame"


def score_cookies(page: HomepageResult) -> Verdict:
    if not page.cookies:
        return Status.PASS, "The homepage sets no cookies"
    insecure = [c.name for c in page.cookies if not c.secure]
    if insecure:
        return Status.FAIL, f"Cookies without Secure: {', '.join(insecure)}"
    weak = [
        c.name for c in page.cookies if not c.http_only or c.same_site in (None, "none")
    ]
    if weak:
        return Status.WARN, f"Cookies missing HttpOnly or SameSite: {', '.join(weak)}"
    return Status.PASS, "Every cookie has Secure, HttpOnly, and SameSite"


def score_referrer_policy(page: HomepageResult) -> Verdict:
    header = page.headers.referrer_policy
    if header is None:
        return Status.WARN, "No Referrer-Policy header; relies on the browser default"
    # With a comma-separated list, browsers use the last policy they understand.
    policy = header.split(",")[-1].strip()
    if policy in SAFE_REFERRER_POLICIES:
        return Status.PASS, f"Referrer-Policy is {policy}"
    return Status.FAIL, f"Referrer-Policy {policy} leaks full URLs to other sites"


def score_permissions_policy(page: HomepageResult) -> Verdict:
    if page.headers.permissions_policy_present:
        return Status.PASS, "Permissions-Policy header is set"
    return Status.FAIL, "No Permissions-Policy header"


def score_version_leak(page: HomepageResult) -> Verdict:
    leaked = page.headers.leaked_versions
    if leaked:
        return Status.FAIL, f"Server software versions shown: {', '.join(leaked)}"
    return Status.PASS, "No server software versions shown"


HEADER_RULES = [
    Rule(
        id="hsts",
        category="Security headers",
        title="Strict-Transport-Security (HSTS)",
        max_points=10,
        check="homepage",
        score=score_hsts,
        fix=(
            "Add the header Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains so browsers always use HTTPS for this site."
        ),
    ),
    Rule(
        id="csp",
        category="Security headers",
        title="Content-Security-Policy",
        max_points=10,
        check="homepage",
        score=score_csp,
        fix=(
            "Add a Content-Security-Policy header that lists where scripts may "
            "load from, starting with default-src 'self', and avoid "
            "'unsafe-inline' and 'unsafe-eval'."
        ),
    ),
    Rule(
        id="nosniff",
        category="Security headers",
        title="X-Content-Type-Options",
        max_points=5,
        check="homepage",
        score=score_nosniff,
        fix="Add the header X-Content-Type-Options: nosniff.",
    ),
    Rule(
        id="clickjacking",
        category="Security headers",
        title="Clickjacking protection",
        max_points=5,
        check="homepage",
        score=score_clickjacking,
        fix=(
            "Add frame-ancestors 'self' to your Content-Security-Policy, "
            "or add the header X-Frame-Options: DENY."
        ),
    ),
    Rule(
        id="cookies",
        category="Security headers",
        title="Cookie security flags",
        max_points=5,
        check="homepage",
        score=score_cookies,
        fix=(
            "Set every cookie with Secure, HttpOnly (unless JavaScript must read "
            "it), and SameSite=Lax or Strict."
        ),
    ),
    Rule(
        id="referrer_policy",
        category="Security headers",
        title="Referrer-Policy",
        max_points=3,
        check="homepage",
        score=score_referrer_policy,
        fix="Add the header Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    Rule(
        id="permissions_policy",
        category="Security headers",
        title="Permissions-Policy",
        max_points=2,
        check="homepage",
        score=score_permissions_policy,
        fix=(
            "Add a Permissions-Policy header that turns off browser features "
            "you don't use, e.g. camera=(), microphone=(), geolocation=()."
        ),
    ),
    Rule(
        id="version_leak",
        category="Security headers",
        title="Server version hidden",
        max_points=2,
        check="homepage",
        score=score_version_leak,
        fix=(
            "Configure your web server to stop sending version numbers in the "
            "Server and X-Powered-By headers (e.g. server_tokens off in nginx)."
        ),
    ),
]


def score_spf(email: EmailDnsResult) -> Verdict:
    spf = email.spf
    if spf.record is None:
        return Status.FAIL, "No SPF record"
    if spf.multiple_records:
        return Status.FAIL, "More than one SPF record, so mail servers ignore them"
    if spf.all_qualifier in ("-", "~"):
        return Status.PASS, f"SPF ends with {spf.all_qualifier}all"
    if spf.all_qualifier == "+":
        return Status.FAIL, "SPF ends with +all, which lets anyone send as this domain"
    return Status.WARN, "SPF doesn't reject mail from unlisted servers"


def score_dmarc(email: EmailDnsResult) -> Verdict:
    dmarc = email.dmarc
    if dmarc.record is None:
        return Status.FAIL, "No DMARC record"
    if dmarc.multiple_records:
        return Status.FAIL, "More than one DMARC record, so mail servers ignore them"
    if dmarc.policy in ("reject", "quarantine"):
        return Status.PASS, f"DMARC policy is {dmarc.policy}"
    if dmarc.policy == "none":
        return Status.WARN, "DMARC policy is none, so spoofed mail is still delivered"
    return Status.FAIL, "DMARC record has no valid policy"


def score_caa(caa: CaaResult) -> Verdict:
    if caa.found_at is None:
        return Status.FAIL, "No CAA record, so any certificate authority may issue"
    return Status.PASS, f"CAA record found at {caa.found_at}"


def score_security_txt(security_txt: SecurityTxtResult) -> Verdict:
    if not security_txt.found:
        return Status.FAIL, "No /.well-known/security.txt file"
    if security_txt.expired:
        return Status.WARN, "security.txt has expired"
    return Status.PASS, "security.txt is published"


def score_dnssec(dnssec: DnssecResult) -> Verdict:
    if dnssec.enabled:
        return Status.PASS, "DNSSEC is enabled"
    return Status.FAIL, "DNSSEC is not enabled"


DNS_RULES = [
    Rule(
        id="spf",
        category="Email & DNS",
        title="SPF record",
        max_points=5,
        check="email",
        score=score_spf,
        fix=(
            "Publish one TXT record starting with v=spf1 that lists your mail "
            "servers and ends with -all, e.g. v=spf1 include:_spf.google.com -all."
        ),
    ),
    Rule(
        id="dmarc",
        category="Email & DNS",
        title="DMARC policy",
        max_points=5,
        check="email",
        score=score_dmarc,
        fix=(
            "Publish a TXT record at _dmarc.<your domain> such as "
            "v=DMARC1; p=quarantine, then move to p=reject once mail looks right."
        ),
    ),
    Rule(
        id="caa",
        category="Email & DNS",
        title="CAA record",
        max_points=3,
        check="caa",
        score=score_caa,
        fix=(
            "Add a CAA record naming the certificate authority you use, "
            'e.g. 0 issue "letsencrypt.org".'
        ),
    ),
    Rule(
        id="security_txt",
        category="Email & DNS",
        title="security.txt",
        max_points=3,
        check="security_txt",
        score=score_security_txt,
        fix=(
            "Publish /.well-known/security.txt with a Contact: line and an "
            "Expires: date less than a year away (see securitytxt.org)."
        ),
    ),
    Rule(
        id="dnssec",
        category="Email & DNS",
        title="DNSSEC",
        max_points=2,
        check="dnssec",
        score=score_dnssec,
        fix=(
            "Turn on DNSSEC at your DNS provider, then add the DS record "
            "it gives you at your domain registrar."
        ),
    ),
]

RULES = TLS_RULES + HEADER_RULES + DNS_RULES


def build_finding(rule: Rule, scan: ScanResult) -> Finding:
    """Grade one rule; a check that failed to run becomes an error finding."""
    result = getattr(scan, rule.check)
    if result is None:
        status, detail = Status.ERROR, scan.errors.get(rule.check, "Check did not run")
    else:
        status, detail = rule.score(result)
    return Finding(
        id=rule.id,
        category=rule.category,
        title=rule.title,
        status=status,
        detail=detail,
        points=points_for(status, rule.max_points),
        max_points=rule.max_points,
        fix=rule.fix if status in (Status.WARN, Status.FAIL) else None,
    )


def build_report(scan: ScanResult) -> Report:
    """Grade every rule against the scan and total the score."""
    findings = [build_finding(rule, scan) for rule in RULES]
    score = sum(finding.points for finding in findings)
    critical_failure = any(
        rule.critical and finding.status is Status.FAIL
        for rule, finding in zip(RULES, findings, strict=True)
    )
    return Report(
        domain=scan.domain,
        score=score,
        grade=grade_for(score, critical_failure),
        findings=findings,
    )

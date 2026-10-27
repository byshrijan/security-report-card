import pytest

from app.checks.cookies import CookieFlags
from app.checks.dns_records import (
    CaaResult,
    DmarcResult,
    DnssecResult,
    EmailDnsResult,
    SpfResult,
)
from app.checks.headers import HeadersResult
from app.checks.redirect import RedirectResult
from app.checks.security_txt import SecurityTxtResult
from app.checks.tls import CertificateResult, OldVersionsResult
from app.scanner import HomepageResult, ScanResult
from app.scoring import RULES, Report, Status, build_report, grade_for, points_for

GOOD_HEADERS = HeadersResult(
    hsts_max_age=31_536_000,
    hsts_include_subdomains=True,
    csp_present=True,
    csp_allows_unsafe_scripts=False,
    nosniff=True,
    clickjacking_protected=True,
    referrer_policy="no-referrer",
    permissions_policy_present=True,
    leaked_versions=[],
)
GOOD_COOKIE = CookieFlags(name="id", secure=True, http_only=True, same_site="lax")
GOOD_SPF = SpfResult(record="v=spf1 -all", multiple_records=False, all_qualifier="-")
GOOD_DMARC = DmarcResult(
    record="v=DMARC1; p=reject", multiple_records=False, policy="reject"
)

PERFECT_SCAN = ScanResult(
    domain="example.com",
    certificate=CertificateResult(reachable=True, trusted=True, days_until_expiry=90),
    old_versions=OldVersionsResult(tls1_0=False, tls1_1=False),
    redirect=RedirectResult(reachable=True, redirects_to_https=True),
    homepage=HomepageResult(headers=GOOD_HEADERS, cookies=[GOOD_COOKIE]),
    email=EmailDnsResult(spf=GOOD_SPF, dmarc=GOOD_DMARC),
    caa=CaaResult(found_at="example.com", issuers=["letsencrypt.org"]),
    dnssec=DnssecResult(enabled=True),
    security_txt=SecurityTxtResult(
        found=True,
        contacts=["mailto:security@example.com"],
        expires=None,
        expired=False,
    ),
    errors={},
)


def change(check: str, **changes: object) -> dict[str, object]:
    """Copy one result from PERFECT_SCAN with some fields changed."""
    return {check: getattr(PERFECT_SCAN, check).model_copy(update=changes)}


def headers(**changes: object) -> dict[str, object]:
    page = HomepageResult(
        headers=GOOD_HEADERS.model_copy(update=changes), cookies=[GOOD_COOKIE]
    )
    return {"homepage": page}


def cookie(**changes: object) -> dict[str, object]:
    page = HomepageResult(
        headers=GOOD_HEADERS, cookies=[GOOD_COOKIE.model_copy(update=changes)]
    )
    return {"homepage": page}


def spf(**changes: object) -> dict[str, object]:
    return {
        "email": EmailDnsResult(
            spf=GOOD_SPF.model_copy(update=changes), dmarc=GOOD_DMARC
        )
    }


def dmarc(**changes: object) -> dict[str, object]:
    return {
        "email": EmailDnsResult(
            spf=GOOD_SPF, dmarc=GOOD_DMARC.model_copy(update=changes)
        )
    }


def report_for(changes: dict[str, object]) -> Report:
    return build_report(PERFECT_SCAN.model_copy(update=changes))


def finding_status(report: Report, rule_id: str) -> Status:
    return next(f.status for f in report.findings if f.id == rule_id)


def test_rules_add_up_to_100_points() -> None:
    assert sum(rule.max_points for rule in RULES) == 100
    assert len({rule.id for rule in RULES}) == len(RULES)


@pytest.mark.parametrize(
    ("score", "critical", "grade"),
    [
        (100, False, "A"),
        (90, False, "A"),
        (89, False, "B"),
        (80, False, "B"),
        (70, False, "C"),
        (60, False, "D"),
        (59, False, "F"),
        (100, True, "F"),
    ],
)
def test_grade_for(score: int, critical: bool, grade: str) -> None:
    assert grade_for(score, critical) == grade


@pytest.mark.parametrize(
    ("status", "points"),
    [(Status.PASS, 5), (Status.WARN, 2), (Status.FAIL, 0), (Status.ERROR, 0)],
)
def test_points_for(status: Status, points: int) -> None:
    assert points_for(status, 5) == points


def test_perfect_scan_gets_100_and_no_fixes() -> None:
    report = build_report(PERFECT_SCAN)

    assert (report.score, report.grade) == (100, "A")
    assert all(f.status is Status.PASS and f.fix is None for f in report.findings)


@pytest.mark.parametrize(
    ("rule_id", "changes", "status"),
    [
        ("certificate", change("certificate", trusted=False), Status.FAIL),
        ("certificate", change("certificate", days_until_expiry=5), Status.WARN),
        ("old_tls", change("old_versions", tls1_0=True), Status.FAIL),
        ("old_tls", change("old_versions", tls1_1=None), Status.ERROR),
        ("https_redirect", change("redirect", redirects_to_https=False), Status.FAIL),
        ("https_redirect", change("redirect", reachable=False), Status.WARN),
        ("hsts", headers(hsts_max_age=None), Status.FAIL),
        ("hsts", headers(hsts_max_age=86_400), Status.WARN),
        ("csp", headers(csp_present=False), Status.FAIL),
        ("csp", headers(csp_allows_unsafe_scripts=True), Status.WARN),
        ("nosniff", headers(nosniff=False), Status.FAIL),
        ("clickjacking", headers(clickjacking_protected=False), Status.FAIL),
        ("cookies", cookie(secure=False), Status.FAIL),
        ("cookies", cookie(same_site="none"), Status.WARN),
        ("referrer_policy", headers(referrer_policy=None), Status.WARN),
        ("referrer_policy", headers(referrer_policy="unsafe-url"), Status.FAIL),
        (
            "referrer_policy",
            headers(referrer_policy="unsafe-url, same-origin"),
            Status.PASS,
        ),
        ("permissions_policy", headers(permissions_policy_present=False), Status.FAIL),
        ("version_leak", headers(leaked_versions=["nginx/1.18.0"]), Status.FAIL),
        ("spf", spf(record=None), Status.FAIL),
        ("spf", spf(all_qualifier="+"), Status.FAIL),
        ("spf", spf(all_qualifier=None), Status.WARN),
        ("dmarc", dmarc(policy="none"), Status.WARN),
        ("dmarc", dmarc(multiple_records=True), Status.FAIL),
        ("caa", change("caa", found_at=None), Status.FAIL),
        ("security_txt", change("security_txt", expired=True), Status.WARN),
        ("dnssec", change("dnssec", enabled=False), Status.FAIL),
    ],
)
def test_one_problem_changes_one_finding(
    rule_id: str, changes: dict[str, object], status: Status
) -> None:
    report = report_for(changes)

    assert finding_status(report, rule_id) is status
    others = [f for f in report.findings if f.id != rule_id]
    assert all(f.status is Status.PASS for f in others)


def test_failed_certificate_caps_grade_at_f() -> None:
    report = report_for(change("certificate", trusted=False))

    assert (report.score, report.grade) == (80, "F")


def test_check_that_did_not_run_becomes_error_findings() -> None:
    report = report_for(
        {"homepage": None, "errors": {"homepage": "Connection timed out"}}
    )

    homepage_findings = [f for f in report.findings if f.category == "Security headers"]
    assert len(homepage_findings) == 8
    for finding in homepage_findings:
        assert finding.status is Status.ERROR
        assert finding.points == 0
        assert finding.detail == "Connection timed out"
        assert finding.fix is None
    assert (report.score, report.grade) == (58, "F")

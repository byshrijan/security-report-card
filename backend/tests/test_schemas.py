import pytest
from pydantic import ValidationError

from app.schemas import ScanRequest, normalize_domain


@pytest.mark.parametrize(
    "domain",
    [
        "example.com",
        "sub.example.co.uk",
        "my-site.io",
        "xn--mnchen-3ya.de",
    ],
)
def test_valid_domain_is_unchanged(domain: str) -> None:
    assert normalize_domain(domain) == domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  example.com  ", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("https://example.com", "example.com"),
        ("http://example.com/page?x=1#top", "example.com"),
        ("example.com/some/path", "example.com"),
        ("www.example.com.", "www.example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
    ],
)
def test_messy_input_is_normalized(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "a" * 3000,
        "not a domain",
        "localhost",
        "10.0.0.1",
        "169.254.169.254",
        "http://[::1]/",
        "127.1",
        "user@example.com",
        "example.com:8080",
        "ftp://example.com",
        "javascript:alert(1)",
        "exa_mple.com",
        "-example.com",
        "a..com",
        "*.example.com",
        "a" * 64 + ".com",
    ],
)
def test_invalid_input_is_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(raw)


def test_scan_request_normalizes_domain() -> None:
    request = ScanRequest(domain="HTTPS://Example.com/page")

    assert request.domain == "example.com"


def test_scan_request_rejects_invalid_domain() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(domain="localhost")


def test_scan_request_rejects_non_string() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(domain=123)

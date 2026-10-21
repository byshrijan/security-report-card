import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest

from app.core.security import UnsafeDomainError, is_public_ip, resolve_safe_ip


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback (localhost)
        "10.0.0.1",  # private network
        "172.16.0.1",  # private network
        "192.168.1.1",  # private network (home routers)
        "169.254.169.254",  # link-local: cloud metadata service
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",  # "this host"  # noqa: S104
        "224.0.1.1",  # multicast
        "::1",  # IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 private
        "::ffff:127.0.0.1",  # IPv4 loopback hidden inside IPv6
        "::ffff:169.254.169.254",  # metadata IP hidden inside IPv6
    ],
)
def test_non_public_ip_is_rejected(address: str) -> None:
    assert is_public_ip(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_public_ip_is_allowed(address: str) -> None:
    assert is_public_ip(ipaddress.ip_address(address)) is True


class FakeRecord:
    """Stands in for one DNS record; our code only reads `.address`."""

    def __init__(self, address: str) -> None:
        self.address = address


def use_fake_dns(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str]]
) -> None:
    """Replace the real DNS lookup with one that answers from `answers`."""

    async def fake_resolve(
        domain: str, record_type: str, lifetime: float
    ) -> list[FakeRecord]:
        if record_type not in answers:
            raise dns.resolver.NoAnswer
        return [FakeRecord(address) for address in answers[record_type]]

    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)


def use_failing_dns(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Replace the real DNS lookup with one that always raises `error`."""

    async def fake_resolve(
        domain: str, record_type: str, lifetime: float
    ) -> list[FakeRecord]:
        raise error

    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)


@pytest.mark.asyncio
async def test_public_domain_returns_its_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_dns(monkeypatch, {"A": ["8.8.8.8"], "AAAA": ["2001:4860:4860::8888"]})
    assert await resolve_safe_ip("example.com") == ipaddress.ip_address("8.8.8.8")


@pytest.mark.asyncio
async def test_ipv6_only_domain_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_dns(monkeypatch, {"AAAA": ["2606:4700:4700::1111"]})
    result = await resolve_safe_ip("example.com")
    assert result == ipaddress.ip_address("2606:4700:4700::1111")


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254"])
async def test_domain_pointing_to_private_ip_is_blocked(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    use_fake_dns(monkeypatch, {"A": [address]})
    with pytest.raises(UnsafeDomainError, match="non-public"):
        await resolve_safe_ip("evil.example")


@pytest.mark.asyncio
async def test_one_private_ip_among_public_ones_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_dns(monkeypatch, {"A": ["8.8.8.8", "10.0.0.1"]})
    with pytest.raises(UnsafeDomainError, match="non-public"):
        await resolve_safe_ip("evil.example")


@pytest.mark.asyncio
async def test_private_ipv6_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_dns(monkeypatch, {"A": ["8.8.8.8"], "AAAA": ["::1"]})
    with pytest.raises(UnsafeDomainError, match="non-public"):
        await resolve_safe_ip("evil.example")


@pytest.mark.asyncio
async def test_domain_with_no_addresses_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_dns(monkeypatch, {})
    with pytest.raises(UnsafeDomainError, match="no IP addresses"):
        await resolve_safe_ip("example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (dns.resolver.NXDOMAIN(), "does not exist"),
        (dns.exception.Timeout(), "timed out"),
        (dns.resolver.NoNameservers(), "lookup failed"),
    ],
)
async def test_dns_errors_become_unsafe_domain_error(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    use_failing_dns(monkeypatch, error)
    with pytest.raises(UnsafeDomainError, match=message):
        await resolve_safe_ip("example.com")

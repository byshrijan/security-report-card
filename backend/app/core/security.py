import ipaddress

import dns.asyncresolver
import dns.exception
import dns.resolver

DNS_TIMEOUT_SECONDS = 5.0

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class UnsafeDomainError(Exception):
    """Raised when a domain can't be scanned safely (or can't be resolved)."""


def is_public_ip(ip: IPAddress) -> bool:
    """Return True only if the address is on the public internet."""
    # An IPv6 address can hide an IPv4 one, e.g. ::ffff:127.0.0.1 is 127.0.0.1.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


async def _lookup(domain: str, record_type: str) -> list[IPAddress]:
    """Return the addresses from one DNS record type ("A" or "AAAA")."""
    try:
        answer = await dns.asyncresolver.resolve(
            domain, record_type, lifetime=DNS_TIMEOUT_SECONDS
        )
    except dns.resolver.NoAnswer:
        return []
    return [ipaddress.ip_address(record.address) for record in answer]


async def resolve_safe_ip(domain: str) -> IPAddress:
    """Look up an already-validated domain once and return a safe IP for it.

    Raises UnsafeDomainError if the lookup fails or if ANY of the domain's
    addresses is not public.
    """
    try:
        addresses = await _lookup(domain, "A") + await _lookup(domain, "AAAA")
    except dns.resolver.NXDOMAIN:
        raise UnsafeDomainError("Domain does not exist") from None
    except dns.exception.Timeout:
        raise UnsafeDomainError("DNS lookup timed out") from None
    except dns.exception.DNSException:
        raise UnsafeDomainError("DNS lookup failed") from None

    if not addresses:
        raise UnsafeDomainError("Domain has no IP addresses")
    for ip in addresses:
        if not is_public_ip(ip):
            raise UnsafeDomainError("Domain points to a non-public IP address")
    return addresses[0]

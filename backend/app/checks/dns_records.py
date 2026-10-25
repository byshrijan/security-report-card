import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import BaseModel

DNS_TIMEOUT_SECONDS = 5.0
SPF_QUALIFIERS = ("+", "-", "~", "?")
DMARC_POLICIES = ("none", "quarantine", "reject")


class DnsLookupError(Exception):
    """Raised when a DNS lookup fails for a reason other than "no record"."""


async def fetch_txt_records(name: str) -> list[str]:
    """Return every TXT record at `name`; empty if there are none."""
    try:
        answer = await dns.asyncresolver.resolve(
            name, "TXT", lifetime=DNS_TIMEOUT_SECONDS
        )
    except dns.resolver.NXDOMAIN, dns.resolver.NoAnswer:
        return []
    except dns.exception.Timeout:
        raise DnsLookupError("DNS lookup timed out") from None
    except dns.exception.DNSException:
        raise DnsLookupError("DNS lookup failed") from None
    # Long TXT records arrive as 255-byte chunks that must be rejoined.
    return [b"".join(record.strings).decode(errors="replace") for record in answer]


class SpfResult(BaseModel):
    """Facts about a domain's SPF record."""

    record: str | None
    multiple_records: bool
    all_qualifier: str | None


def parse_spf(txt_records: list[str]) -> SpfResult:
    """Find the SPF record among a domain's TXT records and read its `all` rule."""
    spf_records = [r for r in txt_records if r.lower().split()[:1] == ["v=spf1"]]
    if not spf_records:
        return SpfResult(record=None, multiple_records=False, all_qualifier=None)

    record = spf_records[0]
    all_qualifier = None
    for term in record.lower().split()[1:]:
        # A term without a qualifier, like "all", means "+all".
        if not term.startswith(SPF_QUALIFIERS):
            term = "+" + term
        if term[1:] == "all":
            all_qualifier = term[0]
            break
    return SpfResult(
        record=record,
        multiple_records=len(spf_records) > 1,
        all_qualifier=all_qualifier,
    )


class DmarcResult(BaseModel):
    """Facts about a domain's DMARC record."""

    record: str | None
    multiple_records: bool
    policy: str | None


def parse_tags(record: str) -> dict[str, str]:
    """Split "v=DMARC1; p=reject" into {"v": "dmarc1", "p": "reject"}."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        name, _, value = part.partition("=")
        tags.setdefault(name.strip().lower(), value.strip().lower())
    return tags


def is_dmarc_record(record: str) -> bool:
    """True if the record's first tag is v=DMARC1, as RFC 7489 requires."""
    first_tag = next(iter(parse_tags(record).items()))
    return first_tag == ("v", "dmarc1")


def parse_dmarc(txt_records: list[str]) -> DmarcResult:
    """Find the DMARC record among the TXT records at _dmarc.<domain>."""
    dmarc_records = [r for r in txt_records if is_dmarc_record(r)]
    if not dmarc_records:
        return DmarcResult(record=None, multiple_records=False, policy=None)

    record = dmarc_records[0]
    policy = parse_tags(record).get("p")
    return DmarcResult(
        record=record,
        multiple_records=len(dmarc_records) > 1,
        policy=policy if policy in DMARC_POLICIES else None,
    )


class EmailDnsResult(BaseModel):
    """SPF and DMARC facts for one domain."""

    spf: SpfResult
    dmarc: DmarcResult


async def check_email_dns(domain: str) -> EmailDnsResult:
    """Look up and parse the SPF and DMARC records for `domain`."""
    spf_records = await fetch_txt_records(domain)
    dmarc_records = await fetch_txt_records(f"_dmarc.{domain}")
    return EmailDnsResult(
        spf=parse_spf(spf_records),
        dmarc=parse_dmarc(dmarc_records),
    )

import dns.asyncresolver
import dns.exception
import dns.resolver
import pytest

from app.checks.dns_records import (
    DnsLookupError,
    check_email_dns,
    fetch_txt_records,
    parse_dmarc,
    parse_spf,
)


class FakeTxtRecord:
    """Stands in for one TXT record; our code only reads `.strings`."""

    def __init__(self, *chunks: bytes) -> None:
        self.strings = chunks


def use_fake_dns(
    monkeypatch: pytest.MonkeyPatch,
    answers: dict[str, list[FakeTxtRecord]] | Exception,
) -> None:
    """Answer TXT lookups from `answers`; unknown names don't exist."""

    async def fake_resolve(
        name: str, record_type: str, lifetime: float
    ) -> list[FakeTxtRecord]:
        if isinstance(answers, Exception):
            raise answers
        if name not in answers:
            raise dns.resolver.NXDOMAIN
        return answers[name]

    monkeypatch.setattr(dns.asyncresolver, "resolve", fake_resolve)


@pytest.mark.parametrize(
    ("records", "found", "multiple", "qualifier"),
    [
        (["v=spf1 include:_spf.google.com -all"], True, False, "-"),
        (["v=spf1 mx ~all"], True, False, "~"),
        (["v=spf1 ?all"], True, False, "?"),
        (["v=spf1 +all"], True, False, "+"),
        (["V=SPF1 A MX ALL"], True, False, "+"),  # bare "all" means "+all"
        (["v=spf1 mx"], True, False, None),  # no "all" rule
        (["google-site-verification=abc", "v=spf1 -all"], True, False, "-"),
        (["v=spf1 -all", "v=spf1 ~all"], True, True, "-"),
        (["v=spf10 -all"], False, False, None),
        ([""], False, False, None),
        ([], False, False, None),
    ],
)
def test_parse_spf(
    records: list[str], found: bool, multiple: bool, qualifier: str | None
) -> None:
    result = parse_spf(records)
    assert (result.record is not None) is found
    assert result.multiple_records is multiple
    assert result.all_qualifier == qualifier


@pytest.mark.parametrize(
    ("records", "found", "multiple", "policy"),
    [
        (["v=DMARC1; p=reject; rua=mailto:a@example.com"], True, False, "reject"),
        (["v=DMARC1;p=quarantine"], True, False, "quarantine"),
        (["v=DMARC1; p=none"], True, False, "none"),
        ([" V = dmarc1 ; P = Reject "], True, False, "reject"),
        (["v=DMARC1; p=reject; p=none"], True, False, "reject"),  # first wins
        (["v=DMARC1; p=bogus"], True, False, None),
        (["v=DMARC1"], True, False, None),
        (["v=DMARC1; p=reject", "v=DMARC1; p=none"], True, True, "reject"),
        (["p=reject; v=DMARC1"], False, False, None),  # v= must come first
        (["v=DMARC10; p=reject"], False, False, None),
        ([""], False, False, None),
        ([], False, False, None),
    ],
)
def test_parse_dmarc(
    records: list[str], found: bool, multiple: bool, policy: str | None
) -> None:
    result = parse_dmarc(records)
    assert (result.record is not None) is found
    assert result.multiple_records is multiple
    assert result.policy == policy


@pytest.mark.asyncio
async def test_long_txt_record_chunks_are_joined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = FakeTxtRecord(b"v=spf1 include:a.example ", b"include:b.example -all")
    use_fake_dns(monkeypatch, {"example.com": [record]})
    assert await fetch_txt_records("example.com") == [
        "v=spf1 include:a.example include:b.example -all"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()])
async def test_missing_txt_records_return_empty_list(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    use_fake_dns(monkeypatch, error)
    assert await fetch_txt_records("example.com") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "message"),
    [
        (dns.exception.Timeout(), "timed out"),
        (dns.resolver.NoNameservers(), "lookup failed"),
    ],
)
async def test_dns_failures_raise_lookup_error(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    use_fake_dns(monkeypatch, error)
    with pytest.raises(DnsLookupError, match=message):
        await fetch_txt_records("example.com")


@pytest.mark.asyncio
async def test_check_email_dns_reads_both_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_dns(
        monkeypatch,
        {
            "example.com": [FakeTxtRecord(b"v=spf1 -all")],
            "_dmarc.example.com": [FakeTxtRecord(b"v=DMARC1; p=reject")],
        },
    )
    result = await check_email_dns("example.com")
    assert result.spf.all_qualifier == "-"
    assert result.dmarc.policy == "reject"


@pytest.mark.asyncio
async def test_check_email_dns_with_no_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    use_fake_dns(monkeypatch, {})
    result = await check_email_dns("example.com")
    assert result.spf.record is None
    assert result.dmarc.record is None

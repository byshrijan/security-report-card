import ipaddress
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, field_validator

MAX_INPUT_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253
LABEL_PATTERN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def normalize_domain(raw: str) -> str:
    """Turn input like 'https://Example.com/page' into 'example.com'.

    Raises ValueError if the input is not a public domain name.
    """
    text = raw.strip()
    if not text:
        raise ValueError("Enter a domain name")
    if len(text) > MAX_INPUT_LENGTH:
        raise ValueError("Input is too long")

    # urlsplit only finds the host when a scheme is present, so add one if missing.
    if "://" not in text:
        text = "https://" + text

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ValueError("Not a valid domain or URL") from None

    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Usernames and passwords are not allowed")
    if port is not None:
        raise ValueError("Ports are not allowed")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise ValueError("Could not find a domain name in the input")

    # Convert international names to ASCII, e.g. münchen.de -> xn--mnchen-3ya.de
    if not host.isascii():
        host = host.encode("idna").decode("ascii")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address")

    if len(host) > MAX_DOMAIN_LENGTH:
        raise ValueError("Domain name is too long")

    labels = host.split(".")
    if len(labels) < 2:
        raise ValueError("Enter a full domain name like example.com")
    for label in labels:
        if not LABEL_PATTERN.fullmatch(label):
            raise ValueError("Not a valid domain name")
    if labels[-1].isdigit():
        raise ValueError("Not a valid domain name")

    return host


class ScanRequest(BaseModel):
    """Body of a scan request: the domain the user wants to check."""

    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return normalize_domain(value)

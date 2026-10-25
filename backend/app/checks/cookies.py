import httpx
from pydantic import BaseModel


class CookieFlags(BaseModel):
    """Security attributes of one cookie. The value is never stored."""

    name: str
    secure: bool
    http_only: bool
    same_site: str | None


def parse_set_cookie(header: str) -> CookieFlags | None:
    """Read one Set-Cookie header value; None if it has no valid name=value pair."""
    name_value, *attributes = header.split(";")
    name, has_equals, _ = name_value.partition("=")
    name = name.strip()
    if not has_equals or not name:
        return None

    flags: dict[str, str] = {}
    for attribute in attributes:
        key, _, value = attribute.partition("=")
        flags[key.strip().lower()] = value.strip().lower()

    return CookieFlags(
        name=name,
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=flags.get("samesite") or None,
    )


def analyze_cookies(headers: httpx.Headers) -> list[CookieFlags]:
    """Return the security attributes of every cookie the homepage sets."""
    cookies = []
    for header in headers.get_list("set-cookie"):
        cookie = parse_set_cookie(header)
        if cookie is not None:
            cookies.append(cookie)
    return cookies

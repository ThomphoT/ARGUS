"""Domain normalization and typosquatting helpers."""

import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    if "://" in candidate:
        candidate = urlparse(candidate).netloc
    candidate = candidate.split("/")[0].split(":")[0].strip(".")
    if not DOMAIN_RE.match(candidate):
        raise ValueError("company_domain must be a valid domain such as example.com")
    return candidate


def typosquat_variants(domain: str, limit: int = 8) -> list[str]:
    stem, _, tld = domain.partition(".")
    variants = {
        f"{stem}-{tld}.com",
        f"{stem}{tld}.com",
        f"{stem}login.{tld}",
        f"{stem}secure.{tld}",
        f"{stem.replace('o', '0')}.{tld}",
        f"{stem.replace('i', '1')}.{tld}",
        f"{stem[:-1]}.{tld}" if len(stem) > 3 else domain,
        f"{stem}support.{tld}",
    }
    return [v for v in variants if v != domain][:limit]

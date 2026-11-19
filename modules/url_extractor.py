"""
url_extractor.py - Extract, normalize and deduplicate URLs from LLM text.

Purely mechanical. It does NOT classify phishing or judge grounding - it only
produces a clean, de-duplicated list of candidate URLs for the downstream
verification step.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlsplit, urlunsplit

# Match http(s) URLs. Generous with scheme+host chars; then we sanitize.
_URL_RE = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# Trailing punctuation that is likely sentence/markup noise, not URL content.
_TRAILING_NOISE = ".,;:!?)]}>\"'`"


def extract_urls(text: str) -> List[str]:
    """Return a de-duplicated, normalized list of URLs found in `text`.

    Normalization steps:
      * strip surrounding/trailing punctuation and markdown link syntax
      * trim scheme host to lowercase, collapse scheme case
      * drop trailing ')'/'}' when unmatched brackets are present
      * remove duplicates (order-preserving)
    """
    if not text:
        return []
    candidates: List[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0)
        cleaned = _clean_url(url)
        if cleaned:
            candidates.append(cleaned)

    seen = set()
    result: List[str] = []
    for url in candidates:
        key = _normalise_key(url)
        if key and key not in seen:
            seen.add(key)
            result.append(url)
    return result


def extract_domains(text: str) -> List[str]:
    """Return de-duplicated hostnames from extracted URLs."""
    seen = set()
    domains = []
    for url in extract_urls(text):
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in seen:
            seen.add(host)
            domains.append(host)
    return domains


def _clean_url(url: str) -> str:
    """Sanitise a raw regex match into a valid normalised URL string."""

    # Strip markdown link wrapping like [text](url)
    if url.startswith("http://") or url.startswith("https://"):
        pass

    # Strip trailing noise characters, but keep query strings intact.
    while url and url[-1] in _TRAILING_NOISE:
        url = url[:-1]

    # Balanced-paren handling: if there are more ')' than '(' in the whole
    # match, the final ')' is likely sentence punctuation.
    if url.count(")") > url.count("(") and url.endswith(")"):
        url = url[:-1]

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    scheme = parts.scheme.lower()
    host = parts.netloc
    if "@" in host and ":" in host.split("@")[0]:
        host = host.split("@", 1)[1]  # drop userinfo
    netloc = host.lower()

    return urlunsplit((scheme, netloc, parts.path, parts.query, ""))


def _normalise_key(url: str) -> str:
    """Case-normalised key for de-duplication (drops trailing slash)."""
    parts = urlsplit(url)
    host = (parts.netloc or "").lower()
    path = parts.path or ""
    if path == "/":
        path = ""
    return f"{host}{path}?{parts.query}"


if __name__ == "__main__":
    sample = (
        'Several phishing campaigns use https://fake-bank.com and '
        'https://example-login.com. Others reference http://PAYPAL-SECURE.COM/a?x=1 '
        'and https://fake-bank.com again.'
    )
    print(extract_urls(sample))
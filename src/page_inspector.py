"""page_inspector.py - read a page's HTML for fake-login signs (no scripts, no forms).

SAFETY: one plain GET with a short timeout and a size cap. No JavaScript runs,
no form is submitted, no credentials are sent. The HTML is parsed as text only.

Signals:
    has_password_field     a password input exists (login page)
    external_form_action   a form posts to a different registrable domain
    redirected_off_domain  the browser ended up on another registrable domain
    title_brand_mismatch   the page title names a brand that is not this domain
A page is "suspicious" when it asks for a password AND one of the other
signals fires. That combination is the classic fake-login pattern.

Turn off with PHISHGUARD_PAGE_CHECK=0 (used by the test suite: no network).
"""

from __future__ import annotations

import logging
import os
from html.parser import HTMLParser
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests

import features as F

logger = logging.getLogger("phishguard.page")

MAX_BYTES = 300_000
TIMEOUT = 8.0
USER_AGENT = "Mozilla/5.0 (PhishGuard-HDV page check; read-only)"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_password = False
        self.form_actions: list[str] = []
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "input" and (a.get("type") or "").lower() == "password":
            self.has_password = True
        elif tag == "form":
            self.form_actions.append(a.get("action") or "")
        elif tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def _registrable(host: str) -> str:
    host = (host or "").lower().split(":")[0]
    if not host:
        return ""
    _, reg, _ = F._split_host(host)
    return reg or host


def analyse_html(html: str, page_url: str, final_url: str) -> Dict:
    """Pure function: signals from HTML text. Easy to test without network."""
    parser = _PageParser()
    try:
        parser.feed(html)
    except Exception:  # malformed HTML must never crash the check
        logger.debug("html parse issue for %s", page_url)

    page_reg = _registrable(urlparse(page_url).netloc)
    final_reg = _registrable(urlparse(final_url).netloc)

    external = False
    for action in parser.form_actions:
        if not action:
            continue
        target = urljoin(final_url, action)
        target_reg = _registrable(urlparse(target).netloc)
        if target_reg and target_reg != final_reg:
            external = True
            break

    title = " ".join(parser.title_parts).strip()
    mismatch = False
    title_l = title.lower()
    for brand, domains in F.BRAND_OFFICIAL_DOMAINS.items():
        if len(brand) >= 4 and brand in title_l and final_reg not in domains:
            mismatch = True
            break

    redirected = bool(final_reg) and bool(page_reg) and final_reg != page_reg

    signals = {
        "has_password_field": parser.has_password,
        "external_form_action": external,
        "redirected_off_domain": redirected,
        "title_brand_mismatch": mismatch,
        "title": title[:120],
    }
    signals["suspicious"] = bool(parser.has_password and (
        external or redirected or mismatch))
    return signals


def inspect_page(url: str) -> Dict:
    """Fetch once (GET only) and analyse. Never raises."""
    if os.getenv("PHISHGUARD_PAGE_CHECK", "1") == "0":
        return {"fetched": False, "suspicious": False, "note": "page check disabled"}
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True,
                            headers={"User-Agent": USER_AGENT}, stream=True)
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "html" not in ctype:
            resp.close()
            return {"fetched": True, "status": resp.status_code, "suspicious": False,
                    "note": "not an HTML page"}
        body = resp.raw.read(MAX_BYTES, decode_content=True) or b""
        resp.close()
        html = body.decode(resp.encoding or "utf-8", errors="replace")
        out = analyse_html(html, url, resp.url or url)
        out.update({"fetched": True, "status": resp.status_code})
        return out
    except requests.RequestException as exc:
        return {"fetched": False, "suspicious": False,
                "note": f"page not fetched: {type(exc).__name__}"}

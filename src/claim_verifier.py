"""
claim_verifier.py - H2 descriptive hallucination: the URL is real, the claim is not.

Stage A answers "does this URL exist". That catches H1 (fabricated links) but
says nothing about the sentence the model wrapped around a real URL. A model
can write

    https://www.maybank2u.com.my is a phishing kit harvesting TAC codes

and Stage A will pass it, because the domain really exists. The *description*
is the hallucination. This module decides whether the claim is supported by
evidence the pipeline already collected (page signals, threat feeds, domain
age, official-domain table). It performs NO network calls of its own, so it
adds no latency and cannot be rate-limited.

Verdict vocabulary (deliberately conservative, same philosophy as risk_scoring)
------------------------------------------------------------------------------
    supported     evidence positively backs the claim
    contradicted  evidence positively shows the claim is wrong
                  (e.g. "official Maybank page" on a domain that is not
                  Maybank's, or "login page" on a page with no password field)
    unsupported   no evidence either way. Absence of a threat-feed match is
                  NOT evidence of safety, so a "this is malicious" claim with
                  zero feed matches is unsupported, never contradicted.
    no_claim      the sentence asserts nothing checkable about this URL

Claim types
-----------
    THREAT       "phishing", "malicious", "scam", "C2", "credential harvest"
    OFFICIAL     "official", "genuine", "the real", "legitimate <brand> page"
    LOGIN        "login page", "sign-in", "credential entry"
    ATTRIBUTION  "according to <source>", "reported by <source>", "per <source>"
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

import features as F

# --- claim detection patterns ---------------------------------------------
_THREAT_RE = re.compile(
    r"\b(phish\w*|malicious|malware|scam\w*|fraud\w*|credential[- ]?harvest\w*|"
    r"harvest\w*|c2|command[- ]and[- ]control|blocklist|block list|blocked|"
    r"steal\w*|fake[- ]?login|spoof\w*|impersonat\w*)\b",
    re.IGNORECASE)

_OFFICIAL_RE = re.compile(
    r"\b(?:official|genuine|legitimate|authentic)\b.{0,80}?"
    r"\b(?:domain|website|web\s+site|site|page|portal|url|address|link|"
    r"homepage|login|prompt)\b"
    r"|\bthe\s+real\s+(?:domain|website|site|page|portal|url|address|link|"
    r"homepage)\b",
    re.IGNORECASE)

# Only the *page type* counts as a login claim. A bare "credential phishing"
# is a threat claim, not an assertion that this URL serves a login form.
_LOGIN_RE = re.compile(
    r"\b(login|log[- ]?in|sign[- ]?in|signin)\s+(page|form|portal|site|screen)\b"
    r"|\bcredential[- ]entry\b"
    r"|\b(harvests?|collects?|asks? for)\s+(the\s+)?(password|credentials|otp|tac)\b",
    re.IGNORECASE)

_ATTRIBUTION_RE = re.compile(
    r"\b(?:according to|reported by|as reported by|per the|sourced from|cited in|"
    r"as stated in|data from|listed by)\s+([^,.;:]{2,50})"
    r"|\b(phishtank|virustotal|urlhaus|mycert|mcmc|abusech|openphish)\b",
    re.IGNORECASE)

_HEDGE_RE = re.compile(
    r"\b(may|might|could|would|possibly|perhaps|reportedly|allegedly|"
    r"typically|usually|often|for example|e\.g\.|such as|illustrative|"
    r"hypothetical|likely|tends? to|commonly|generally)\b",
    re.IGNORECASE)

# Sentence split that keeps URLs intact (they contain '.' and '/', not '. ').
_SENT_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n{1,}")


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in _SENT_SPLIT_RE.split(text or "") if s.strip()]


def sentences_for(text: str, url: str, domain: str) -> List[str]:
    """Sentences that mention this URL or its domain, plus their heading.

    LLMs usually print indicators as a list under a heading. The URL then sits
    on a line of its own and the assertion lives in the line above, so a bare
    URL sentence inherits the previous sentence as context.
    """
    sentences = _sentences(text)
    hits: List[str] = []
    for i, s in enumerate(sentences):
        low = s.lower()
        if not ((url and url.lower() in low)
                or (domain and domain.lower() in low)):
            continue
        body = low.replace(url.lower(), "").replace(domain.lower(), "").strip()
        if i > 0 and len(body.strip(" -:.,|*`()[]")) < 12:
            hits.append(sentences[i - 1] + " " + s)
        else:
            hits.append(s)
    if hits:
        return hits
    # The model may write the domain once and refer to "the link" afterwards.
    return sentences


def _brands_in(sentence: str) -> List[str]:
    low = sentence.lower()
    found = []
    for brand, domains in F.BRAND_OFFICIAL_DOMAINS.items():
        if len(brand) < 4:
            continue
        if re.search(rf"\b{re.escape(brand)}\b", low):
            found.append(brand)
    return found


def _registrable(domain: str) -> str:
    _, reg, _ = F._split_host((domain or "").lower())
    return reg or (domain or "").lower()


def _is_official(domain: str, brand: str) -> bool:
    reg = _registrable(domain)
    return reg in F.BRAND_OFFICIAL_DOMAINS.get(brand, ())


def _source_statuses(sources: Optional[Dict]) -> Dict[str, str]:
    out = {}
    for name, info in (sources or {}).items():
        if isinstance(info, dict):
            out[name] = str(info.get("status") or "")
    return out


# ---------------------------------------------------------------------------
# Individual claim checks
# ---------------------------------------------------------------------------
def _brand_impersonated(domain: str, brand: str) -> bool:
    """True when the brand is fused into a compound hostname it does not own.

    A plain substring test is too loose ("microsoftonline" contains
    "microsoft") and a leading-label test would flag a brand's genuine regional
    domain under another TLD ("cimb.com.sg"). The contradiction therefore needs
    the construction pattern: the brand followed by a hyphen, underscore, or
    digit, as in "paypal-service-update.com" or "maybank2u-secure.top".
    """
    reg = _registrable(domain)
    return re.search(rf"(?:^|[^a-z0-9]){re.escape(brand)}[-_0-9]", reg) is not None


def _check_official(sentence: str, domain: str) -> Optional[Dict]:
    brands = _brands_in(sentence)
    if not brands:
        return None
    brand = brands[0]
    if _is_official(domain, brand):
        return {"type": "OFFICIAL", "verdict": "supported",
                "detail": f"{domain} is an official {brand} domain"}
    # Absence from a non-exhaustive official list is not proof that the claim
    # is false: a brand may own properties the list does not name (single
    # sign-on hosts, regional sites). Only positive evidence of impersonation -
    # the brand's name embedded in a domain the brand does not own - supports a
    # contradiction. Everything else stays unsupported.
    if _brand_impersonated(domain, brand):
        return {"type": "OFFICIAL", "verdict": "contradicted",
                "detail": (f"the sentence calls this an official {brand} page, "
                           f"but {domain} places the brand name in a domain "
                           f"the brand does not own")}
    return {"type": "OFFICIAL", "verdict": "unsupported",
            "detail": (f"{domain} is not in the official {brand} list, and the "
                       f"list is not exhaustive, so the claim cannot be "
                       f"confirmed or refuted from it")}


def _check_threat(sentence: str, sources: Optional[Dict], page: Optional[Dict],
                  reserved: bool) -> Optional[Dict]:
    statuses = _source_statuses(sources)
    positive = [n for n, s in statuses.items() if s == "POSITIVE_MATCH"]
    definite = [n for n, s in statuses.items() if s in ("POSITIVE_MATCH", "NO_MATCH")]

    if positive:
        return {"type": "THREAT", "verdict": "supported",
                "detail": f"feed(s) list this indicator: {', '.join(sorted(positive))}"}
    if page and page.get("suspicious"):
        return {"type": "THREAT", "verdict": "supported",
                "detail": "the page itself shows the fake-login pattern"}

    hedged = bool(_HEDGE_RE.search(sentence))
    if not definite:
        return {"type": "THREAT", "verdict": "unsupported",
                "detail": ("no threat-intelligence source returned a verdict, so "
                           "the malicious claim cannot be checked")}
    return {"type": "THREAT", "verdict": "unsupported",
            "detail": ("no queried feed lists this indicator and the page shows "
                       "no phishing pattern; absence of a match is not proof of "
                       "safety, so the claim stays unsupported"
                       + (" (the sentence is hedged)" if hedged else ""))}


def _check_login(sentence: str, page: Optional[Dict], exists: bool) -> Optional[Dict]:
    if not exists:
        return None
    if not page or not page.get("fetched"):
        return {"type": "LOGIN", "verdict": "unsupported", "blocking": False,
                "detail": "the page could not be fetched, so the login claim is unchecked"}
    if page.get("has_password_field"):
        return {"type": "LOGIN", "verdict": "supported",
                "detail": "the page contains a password field"}
    if page.get("suspicious"):
        return {"type": "LOGIN", "verdict": "supported",
                "detail": "the page shows fake-login signals"}
    # A login form is often injected by JavaScript, so "no password field in
    # the static HTML" is NOT proof that the claim is wrong. Report it as a
    # non-blocking gap, never as a contradiction.
    return {"type": "LOGIN", "verdict": "unsupported", "blocking": False,
            "detail": ("no password field in the static HTML; the form may be "
                       "rendered client-side, so the claim is unconfirmed")}


# Sources this system actually queries. A claim attributed to any other named
# source cannot be checked here and must not be reported as verified.
_QUERYABLE = {"virustotal": "virustotal", "urlhaus": "urlhaus",
              "openphish": "urlhaus", "safe browsing": "safe_browsing",
              "google safe browsing": "safe_browsing"}


def _check_attribution(sentence: str, sources: Optional[Dict]) -> Optional[Dict]:
    """A named source is only checkable if we query it AND it returns a match."""
    match = _ATTRIBUTION_RE.search(sentence)
    if not match:
        return None
    named = (match.group(1) or match.group(2) or "an unnamed source").strip()
    lower = sentence.lower()
    platform = next((p for p in _QUERYABLE if p in lower), None)
    if platform:
        status = _source_statuses(sources).get(_QUERYABLE[platform], "")
        if status == "POSITIVE_MATCH":
            return {"type": "ATTRIBUTION", "verdict": "supported",
                    "detail": f"{platform} independently lists this indicator"}
        if status == "NO_MATCH":
            return {"type": "ATTRIBUTION", "verdict": "unsupported",
                    "detail": (f"the sentence attributes this to {platform}, but "
                               f"{platform} returned no match for it")}
    return {"type": "ATTRIBUTION", "verdict": "unsupported",
            "detail": (f"the sentence attributes the claim to '{named}' but cites "
                       f"no retrievable record, and this system does not query "
                       f"that source")}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def assess_claims(
    text: str,
    url: str,
    domain: str,
    *,
    exists: bool,
    sources: Optional[Dict] = None,
    page: Optional[Dict] = None,
    reserved: bool = False,
) -> Dict:
    """Check every checkable claim made about `url` inside `text`.

    Returns {verdict, claims, notes, sentences} where `verdict` is the worst
    case over the individual claims. Never raises: a malformed answer must not
    take down verification.
    """
    if not text or not str(text).strip():
        return {"verdict": "no_claim", "claims": [], "notes": [],
                "sentences": []}

    try:
        relevant = sentences_for(text, url, domain)
    except Exception:
        return {"verdict": "no_claim", "claims": [], "notes": [],
                "sentences": []}

    claims: List[Dict] = []
    for sentence in relevant:
        if _OFFICIAL_RE.search(sentence):
            c = _check_official(sentence, domain)
            if c:
                claims.append({**c, "sentence": sentence})
        if _THREAT_RE.search(sentence):
            c = _check_threat(sentence, sources, page, reserved)
            if c:
                claims.append({**c, "sentence": sentence})
        if _LOGIN_RE.search(sentence):
            c = _check_login(sentence, page, exists)
            if c:
                claims.append({**c, "sentence": sentence})
        if _ATTRIBUTION_RE.search(sentence):
            c = _check_attribution(sentence, sources)
            if c:
                claims.append({**c, "sentence": sentence})

    if not claims:
        return {"verdict": "no_claim", "claims": [], "notes": [],
                "sentences": relevant}

    order = {"contradicted": 3, "unsupported": 2, "supported": 1}
    blocking = [c for c in claims if c.get("blocking", True)]
    worst = max(blocking or claims, key=lambda c: order.get(c["verdict"], 0))
    return {
        "verdict": worst["verdict"],
        "claims": claims,
        "notes": [f"{c['type']}: {c['verdict']} - {c['detail']}" for c in claims],
        "sentences": relevant,
    }


def summarize(assessment: Dict) -> str:
    """One-line audit string for the verdict reason."""
    v = assessment.get("verdict")
    if v in (None, "no_claim"):
        return ""
    counts = {}
    for c in assessment.get("claims", []):
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
    parts = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    worst = next((c for c in assessment.get("claims", [])
                  if c["verdict"] == v), None)
    tail = f"; {worst['detail']}" if worst else ""
    return f"claim check ({assessment.get('verdict')}): {parts}{tail}"

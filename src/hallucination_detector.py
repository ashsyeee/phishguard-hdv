"""
hallucination_detector.py - Step 3: STAGE A. Existence / grounding check ONLY.

THE ONE QUESTION THIS MODULE ANSWERS
------------------------------------
    "Did the LLM invent this URL, or does it actually exist / is it grounded?"

It deliberately does NOT answer "is this URL malicious?" - that is a Stage B
question (classifiers.py / verification_engine.py) and must never be decided
here. This module has no "safe"/"dangerous"/"phishing" vocabulary at all;
its outputs are `exists`, `grounding_score` and a plain-English `reason`.

EVIDENCE SOURCES (see analyze() for the decision table)
--------------------------------------------------------
1. STRUCTURAL pattern      - reserved RFC-2606 TLDs (.invalid/.test/.example)
                              are NON-ROUTABLE by IANA mandate: the name
                              cannot exist. A literal IP is the opposite: it
                              exists by construction. Both are cheap and need
                              no network.
2. DNS resolution          - dnspython A/AAAA query. NXDOMAIN counts strongly
                              toward exists=False; a live record counts
                              strongly toward exists=True.
3. WHOIS lookup            - python-whois. A definitive "no match" answer
                              counts strongly toward exists=False; a found
                              record with a creation date is positive evidence.
                              Registration age is kept for later stages.
4. RAG-style grounding     - TF-IDF retrieval against the real PhiUSIIL
                              corpus (train split of data/processed) as a
                              reference/knowledge store: "have we ever observed
                              this domain (or a near-copy of it) in real data?"
                              An exact hit is positive grounding; a near-copy
                              only reports similarity - it is NOT an existence
                              verdict (a lookalike that does not resolve is
                              exactly what an LLM hallucinates).

WHY "LOOKUP FAILURE" != "DOES NOT EXIST"
----------------------------------------
WHOIS/DNS errors (timeouts, offline, blocked resolver) are treated as
NEUTRAL - they prove nothing. Only a definitive answer (NXDOMAIN, WHOIS
no-match, reserved pattern) is negative evidence. This keeps the detector
honest when the network is unavailable and keeps the module deterministic
enough for unit tests via injected fake probes (see tests/).

DECISION RULE (priority order, every case has a reason string):
    IP literal                    -> exists=True
    reserved pattern              -> exists=False
    DNS resolved                  -> exists=True
    DNS NXDOMAIN                  -> exists=False
    WHOIS found / not-found       -> exists=True / exists=False
    exact hit in reference store  -> exists=True
    else                          -> grounding_score >= EXIST_THRESHOLD
"""

from __future__ import annotations

import logging
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("phishguard.stage_a")

# Make `from features import ...` resolve no matter how this module is reached
# (script, pytest from repo root, or imported by pipeline/dashboard).
_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
from features import IPV4_RE, normalise_domain

# ---------------------------------------------------------------------------
# Paths + constants (thresholds are configurable, not magic numbers).
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REFERENCE_PATH = ROOT / "data" / "processed" / "train.csv"

RESERVED_TLDS = (".invalid", ".test", ".example")
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# --- evidence weights -----------------------------------------------------
# These decide how much each signal moves the grounding score within [0, 1].
# Rationale:
#   * DNS/WHOIS are direct existence evidence -> the biggest swing.
#   * A reserved-TLD pattern is architecturally conclusive -> strong negative.
#   * Reference-set grounding is a supporting signal only: the corpus is a
#     static snapshot and near-copies are NOT proof of existence.
BASE_SCORE = 0.5
W_IP_LITERAL = 0.50
W_RESERVED_PATTERN = -0.30
W_STRUCTURAL_OK = 0.05
W_MALFORMED = -0.20
W_DNS_RESOLVED = 0.35
W_DNS_NXDOMAIN = -0.40
W_WHOIS_FOUND = 0.25
W_WHOIS_NOTFOUND = -0.25
W_LIVE = 0.05   # positive HTTP answer (2xx/3xx) - mild corroboration
W_DEAD = -0.15  # HTTP 404/410: domain EXISTS but page removed - never 'safe'
W_REF_EXACT = 0.20
W_REF_SIM_SCALE = 0.15  # multiplied by top-similarity (0..1)

EXIST_THRESHOLD = 0.5  # fallback used only when no probe gave conclusive evidence

# WHOIS answer classification: only a definitive "no match" is negative
# evidence; connection/network problems are neutral.
WHOIS_NOT_FOUND_RE = re.compile(
    r"no match for|no data found|not found|no records found|"
    r"no entries|domain name not found|no object found", re.IGNORECASE)
WHOIS_TRANSIENT_RE = re.compile(
    r"timed? ?out|could not connect|connection (refused|reset|closed|error)|"
    r"network (error|is unreachable)|connection timed|whois server|"
    r"[Ee]xceeded|temporarily|unavailable", re.IGNORECASE)


# ===========================================================================
# Output object / return type (Stage A contract)
# ===========================================================================


@dataclass
class StageAResult:
    """The Stage A contract. Existence only - no maliciousness semantics.

    `uncertain` is True when NO probe returned a conclusive answer (offline /
    blocked). The URL is still reported as `exists=False` (it is not
    *confirmed* to exist), but the pipeline must not label it a confident
    "Hallucination" - it has simply not been grounded.
    """
    url: str
    domain: str
    exists: bool
    grounding_score: float
    reason: str
    evidence: Dict = field(default_factory=dict)
    uncertain: bool = False

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "domain": self.domain,
            "stage_reached": "A",
            "exists": self.exists,
            "uncertain": self.uncertain,
            "grounding_score": self.grounding_score,
            "reason": self.reason,
            "evidence": self.evidence,
        }


# ===========================================================================
# Existence probes (pluggable so tests can inject deterministic fakes)
# ===========================================================================


class DnsProbe:
    """Interface: resolve(domain) -> (resolved: bool|None, error: str|None).

    `None` means NO evidence either way (timeout/offline/other error).
    """

    def resolve(self, domain: str):
        raise NotImplementedError


class WhoisProbe:
    """Interface: lookup(domain) -> (found: bool|None, age_days, error).

    `found=None` means no conclusive WHOIS answer (error/offline).
    """

    def lookup(self, domain: str):
        raise NotImplementedError


class NetworkDnsProbe(DnsProbe):
    """Live DNS existence check via dnspython (A then AAAA)."""

    def __init__(self, timeout: float = 5.0, lifetime: float = 8.0):
        import dns.exception
        import dns.resolver

        self._r = dns.resolver.Resolver(configure=True)
        self._r.timeout = timeout
        self._r.lifetime = lifetime

    def resolve(self, domain: str):
        import dns.exception
        import dns.resolver

        for rdtype in ("A", "AAAA"):
            try:
                answers = self._r.resolve(domain, rdtype)
                if len(answers) > 0:
                    return True, None
            except dns.resolver.NXDOMAIN:
                return False, "NXDOMAIN"
            except dns.resolver.NoAnswer:
                continue  # name answers but has no IPs of this type
            except dns.resolver.NoNameservers:
                return None, "no_authoritative_nameservers"
            except (dns.resolver.Timeout, TimeoutError):
                return None, "timeout"
            except dns.exception.DNSException as exc:
                return None, f"dns_error:{type(exc).__name__}"
        # Both rtypes answered without NXDOMAIN -> the name exists in DNS but
        # carries no IP endpoints. That is ambiguous, so stay neutral on it.
        return None, "name_has_no_ip_records"


class NetworkWhoisProbe(WhoisProbe):
    """Live WHOIS existence check + registration age via python-whois."""

    def lookup(self, domain: str):
        import whois

        try:
            w = whois.whois(domain)
        except Exception as exc:  # python-whois raises on many not-found cases
            msg = str(exc)
            if WHOIS_NOT_FOUND_RE.search(msg):
                return False, None, "no registration record"
            if WHOIS_TRANSIENT_RE.search(msg):
                logger.warning("WHOIS transient error for %s: %s", domain, msg[:120])
                return None, None, "transient_error"
            logger.warning("WHOIS lookup failed for %s: %s", domain, msg[:120])
            return None, None, "lookup_error"

        text = str(getattr(w, "text", "") or "")
        if w is None or WHOIS_NOT_FOUND_RE.search(text):
            return False, None, "no registration record"

        cd = w.creation_date
        if isinstance(cd, (list, tuple)):
            cd = cd[0] if cd else None
        age_days = None
        if cd is not None:
            try:
                age_days = max(0, (datetime.now(timezone.utc) - cd).days) \
                    if cd.tzinfo else max(0, (datetime.now() - cd).days)
            except (TypeError, ValueError):
                age_days = None

        # A whois object that actually names the domain / has dates/registrar
        # is a found registration; an empty object is not a record.
        has_record = bool(w.domain) or (cd is not None) \
            or bool(getattr(w, "registrar", None)) or bool(w.expiration_date)
        if has_record:
            return True, age_days, None
        return False, None, "empty whois record"


class RdapProbe:
    """Interface: lookup(domain) -> (found: bool|None, age_days, error).

    RDAP is the structured, JSON successor to WHOIS (IANA bootstrap). Used as a
    FALLBACK when the legacy WHOIS protocol is inconclusive (many registries
    now rate-limit or block port 43).

    `found=None` means no conclusive answer (offline / unsupported TLD).
    """

    def lookup(self, domain: str):
        raise NotImplementedError


class NetworkRdapProbe(RdapProbe):
    """Live RDAP lookup via the IANA bootstrap (no key required)."""

    BOOTSTRAP = "https://data.iana.org/rdap/dns.json"

    def __init__(self, timeout: float = 5.0):
        self._timeout = timeout
        self._bootstrap = None

    def _services(self):
        import requests
        if self._bootstrap is None:
            try:
                r = requests.get(self.BOOTSTRAP, timeout=self._timeout)
                self._bootstrap = r.json().get("services", [])
            except Exception as exc:
                logger.warning("RDAP bootstrap fetch failed: %s", str(exc)[:120])
                self._bootstrap = []
        return self._bootstrap

    def _base_url(self, tld: str):
        for service in self._services():
            if len(service) != 2:
                continue
            tlds, urls = service
            if tld in tlds and urls:
                return urls[0].rstrip("/")
        return None

    def lookup(self, domain: str):
        import requests

        if "." not in domain:
            return None, None, "no_tld"
        tld = domain.rsplit(".", 1)[-1].lower()
        base = self._base_url(tld)
        if not base:
            return None, None, "unsupported_tld"
        try:
            r = requests.get(f"{base}/domain/{domain}", timeout=self._timeout)
        except Exception as exc:
            logger.warning("RDAP request failed for %s: %s", domain, str(exc)[:120])
            return None, None, "transient_error"
        if r.status_code == 404:
            return False, None, "no registration record"
        if r.status_code >= 500:
            return None, None, "rdap_server_error"
        if r.status_code != 200:
            return None, None, f"rdap_status_{r.status_code}"
        try:
            data = r.json()
        except ValueError:
            return None, None, "rdap_bad_json"
        if not data or data.get("errorCode") == 404:
            return False, None, "no registration record"

        age_days = None
        for event in data.get("events", []) or []:
            if event.get("eventAction") == "registration":
                raw = event.get("eventDate")
                if not raw:
                    continue
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc) if dt.tzinfo else datetime.now()
                    age_days = max(0, (now - dt).days)
                except (TypeError, ValueError):
                    age_days = None
                break
        return True, age_days, None


class OfflineDnsProbe(DnsProbe):
    """Deterministic no-evidence probe - used by demo/offline mode."""

    def __init__(self, note: str = "offline_dns"): self._note = note

    def resolve(self, domain):
        return None, self._note


class OfflineWhoisProbe(WhoisProbe):
    def __init__(self, note: str = "offline_whois"): self._note = note

    def lookup(self, domain):
        return None, None, self._note


class OfflineRdapProbe(RdapProbe):
    def __init__(self, note: str = "offline_rdap"): self._note = note

    def lookup(self, domain):
        return None, None, self._note


# ---------------------------------------------------------------------------
# Liveness probe - "does the URL actually answer HTTP?"
# Two distinct failure modes matter here:
#   * a resolving-but-dead page (HTTP 404/410) is a real domain with removed
#     content - must NOT be scored as verified/safe downstream;
#   * a connection-level DNS failure corroborates non-existence when the DNS
#     probe itself returned nothing conclusive.
# ---------------------------------------------------------------------------


class LivenessProbe:
    """Interface: check(url) -> (live: bool|None, status: int|None, error)."""

    def check(self, url: str):
        raise NotImplementedError


class NetworkLivenessProbe(LivenessProbe):
    """HEAD-first, GET-fallback HTTP probe. No auth, bounded timeout."""

    def __init__(self, timeout: float = 6.0):
        self._timeout = timeout

    def _request(self, url: str):
        import requests
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
        try:
            r = requests.head(url, timeout=self._timeout, allow_redirects=True,
                              headers=headers)
            return r.status_code, None, None
        except requests.exceptions.SSLError as exc:
            return None, exc.__class__.__name__, "ssl_error"
        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout, TimeoutError) as exc:
            return None, exc.__class__.__name__, "timeout"
        except requests.exceptions.ConnectionError as exc:
            cls = exc.__class__.__name__
            msg = str(exc).lower()
            if any(k in msg for k in ("getaddrinfo", "name resolution",
                                      "name or service", "failed to resolve")):
                return None, cls, "dns_failed"
            return None, cls, "connection_error"
        except requests.exceptions.RequestException as exc:
            # HEAD unsupported - fall back to a small GET once.
            try:
                r = requests.get(url, timeout=self._timeout, stream=True,
                                 allow_redirects=True)
                return r.status_code, None, None
            except requests.exceptions.RequestException as exc2:
                return None, exc2.__class__.__name__, "request_error"

    def check(self, url: str):
        status, err_cls, tag = self._request(url)
        if status is not None:
            if status in (404, 410):
                return False, status, "page_gone"  # domain exists, content removed
            if status < 500:
                return True, status, None
            return None, status, "http_5xx"  # server up but erroring: ambiguous
        if tag == "dns_failed":
            return False, None, tag  # nothing answers at DNS level either
        return None, None, tag


class OfflineLivenessProbe(LivenessProbe):
    def __init__(self, note: str = "offline_liveness"): self._note = note

    def check(self, url):
        return None, None, self._note


# ===========================================================================
# Structural pattern check (no network required)
# ===========================================================================


def structural_evidence(domain: str) -> Dict:
    """Classify the domain's *structure*: fake-by-construction vs valid.

    Returns {'kind': 'ip'|'reserved'|'valid'|'malformed', 'tld': ..., }.
    Only 'reserved' and 'ip' are conclusive at this level.
    """
    d = domain.strip().lower()
    if IPV4_RE.match(d) or ":" in d:  # IPv4 literal or IPv6-ish
        return {"kind": "ip", "tld": ""}
    for tld in RESERVED_TLDS:
        if d.endswith(tld) and len(d) > len(tld):
            return {"kind": "reserved", "tld": tld}
    if HOSTNAME_RE.match(d):
        return {"kind": "valid", "tld": d.rsplit(".", 1)[-1] if "." in d else ""}
    return {"kind": "malformed", "tld": ""}


# ===========================================================================
# RAG-style grounding store (TF-IDF retrieval over the PhiUSIIL corpus)
# ===========================================================================


class ReferenceStore:
    """Lightweight retrieval store built from the real PhiUSIIL train split.

    Treats the processed corpus as a small "knowledge base": for an input
    domain it reports (a) whether the exact name was ever observed and (b) the
    Top-1 cosine similarity to the nearest known domain (TF-IDF over
    character n-grams, i.e. a fuzzy overlap - the cheap stand-in for an
    embedding model; sentence-transformers can replace TfidfVectorizer without
    touching the rest of the pipeline).
    """

    def __init__(self, path: Optional[Path] = None, cap: int = 250_000):
        self.path = Path(path or DEFAULT_REFERENCE_PATH)
        self.exact: set = set()
        self._tv = None
        self._vects = None
        self._names = ()

        if not self.path.is_file():
            logger.warning("Reference store missing (%s) - grounding will be "
                           "neutral until Step 1 produces data/processed/train.csv",
                           self.path)
            return

        import numpy as np
        import pandas as pd
        from sklearn.feature_extraction.text import TfidfVectorizer

        df = pd.read_csv(self.path, usecols=["domain", "category"])
        # Only ACTUALLY-EXISTING domains belong in the existence reference.
        # hallucinated rows are fake by construction and must not "ground" each
        # other; real_but_misdescribed rows are synthetic example.* domains
        # generated for the Stage B "false claim" story, so they are also
        # excluded - the reference store must contain ONLY domains observed in
        # the real PhiUSIIL corpus.
        df = df[df["category"].isin(("real_legitimate", "real_phishing"))]
        domains = df["domain"].astype(str).str.lower().str.strip()
        domains = domains[domains.str.len() > 0].unique()
        domains = list(domains[:cap])
        self.exact = set(domains)

        if domains:
            self._tv = TfidfVectorizer(
                analyzer="char_wb", ngram_range=(2, 4), lowercase=True,
                sublinear_tf=True)
            self._vects = self._tv.fit_transform(domains)
            self._names = np.asarray(domains, dtype=object)
            logger.info("Reference store: %d real domains (Tf-Idf ready)", len(domains))

    def query(self, domain: str) -> Dict:
        """Return grounding signal: exact_hit, top_similarity, best_match."""
        d = str(domain).strip().lower()
        if d in self.exact:
            return {"exact_hit": True, "top_similarity": 1.0,
                    "best_match": d}
        if self._vects is None:
            return {"exact_hit": False, "top_similarity": 0.0,
                    "best_match": ""}
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        q = self._tv.transform([d])
        sims = cosine_similarity(q, self._vects)[0]
        i = int(np.argmax(sims))
        return {"exact_hit": False, "top_similarity": float(sims[i]),
                "best_match": str(self._names[i])}


@lru_cache(maxsize=2)
def get_reference_store(path: Optional[str] = None) -> ReferenceStore:
    """Cached factory so the expensive TF-IDF fit happens once per process."""
    return ReferenceStore(Path(path) if path else None)


# ===========================================================================
# The Stage A detector
# ===========================================================================


class HallucinationDetector:
    """Sequential Stage A: structure -> DNS -> WHOIS -> RAG grounding.

    NEVER called in parallel with Stage B, and it never emits a
    maliciousness judgment - the pipeline enforces this ordering (pipeline.py).
    """

    def __init__(
        self,
        dns_probe: Optional[DnsProbe] = None,
        whois_probe: Optional[WhoisProbe] = None,
        liveness_probe: Optional[LivenessProbe] = None,
        rdap_probe: Optional[RdapProbe] = None,
        reference_store: Optional[ReferenceStore] = None,
        reference_path: Optional[str] = None,
        exist_threshold: float = EXIST_THRESHOLD,
    ):
        self.dns_probe = dns_probe or NetworkDnsProbe()
        self.whois_probe = whois_probe or NetworkWhoisProbe()
        self.liveness_probe = liveness_probe or NetworkLivenessProbe()
        self.rdap_probe = rdap_probe or NetworkRdapProbe()
        self.store = reference_store or get_reference_store(reference_path)
        self.exist_threshold = exist_threshold

    # -- scoring -----------------------------------------------------------

    def _grounding_score(self, ev: Dict) -> float:
        s = BASE_SCORE
        s += ev["structural"].get("weight", 0.0)
        if ev["dns"]["resolved"] is True:
            s += W_DNS_RESOLVED
        elif ev["dns"]["resolved"] is False:
            s += W_DNS_NXDOMAIN
        if ev["whois"]["found"] is True:
            s += W_WHOIS_FOUND
        elif ev["whois"]["found"] is False:
            s += W_WHOIS_NOTFOUND
        lv = ev["liveness"]
        if lv["live"] is True:
            s += W_LIVE
        elif lv["live"] is False:
            # 'False' here means page_gone (real domain, content removed) or a
            # DNS-level failure. Both INFLATE suspicion downstream, so they move
            # grounding NEGATIVELY even though 'exists' may stay True.
            s += W_DEAD
        if ev["reference"]["exact_hit"]:
            s += W_REF_EXACT
        else:
            s += W_REF_SIM_SCALE * ev["reference"]["top_similarity"]
        return min(max(s, 0.0), 1.0)

    # -- reason string -----------------------------------------------------

    def _build_reason(self, url: str, ev: Dict, exists: bool) -> str:
        parts = []
        st = ev["structural"]
        if st["kind"] == "reserved":
            parts.append(f"domain '{ev['domain']}' uses the reserved, "
                         f"non-routable TLD '{st['tld']}' (RFC-2606) - "
                         f"structurally cannot exist")
        elif st["kind"] == "ip":
            parts.append("URL is a literal IP address - it exists by "
                         "construction")
        elif st["kind"] == "malformed":
            parts.append("input did not contain a parseable domain")

        d = ev["dns"]
        if d["resolved"] is True:
            parts.append("DNS resolves to a live A/AAAA record")
        elif d["resolved"] is False:
            parts.append("DNS returns NXDOMAIN (no such host)")
        if ev["liveness"].get("status") in (404, 410):
            parts.append(f"this exact page returns HTTP {ev['liveness']['status']} "
                         f"(not found) on its site")

        w = ev["whois"]
        src = w.get("source") or "WHOIS"
        if w["found"] is True:
            age = f", age ~{w['age_days']}d" if w.get("age_days") else ""
            parts.append(f"{src} registration confirmed{age}")
        elif w["found"] is False:
            parts.append(f"{src} lookup found no registration record")

        rf = ev["reference"]
        if rf["exact_hit"]:
            parts.append("domain appears verbatim in the PhiUSIIL reference set")
        elif rf["top_similarity"] >= 0.5:
            parts.append(f"closest reference-match '{rf['best_match']}' "
                         f"(similarity {rf['top_similarity']:.2f}) - near-duplicate, "
                         f"not proof of existence")

        lv = ev["liveness"]
        if lv["live"] is True:
            parts.append(f"HTTP probe: page answers ({lv.get('status')})")
        elif lv["live"] is False and lv.get("status"):
            parts.append(f"HTTP probe: page is GONE (status {lv.get('status')}) - "
                         "domain exists but content removed, so never 'safe'")

        verdict = "grounded (exists)" if exists else "likely fabricated"
        conclusive_struct = st["kind"] in ("ip", "reserved")
        if (not conclusive_struct and d["resolved"] is None
                and w["found"] is None and lv["live"] is None):
            parts.append("no live DNS/WHOIS/HTTP evidence available (offline or "
                         "probe failure) - treated as neutral")
        return "; ".join(parts) + f". -> {verdict} (grounding score {ev['grounding_score']:.2f})"

    # -- main entry --------------------------------------------------------

    def analyze(self, url: str) -> StageAResult:
        url_str = str(url or "").strip()
        domain = normalise_domain(url_str)
        if not domain:
            return StageAResult(
                url=url_str, domain="", exists=False, grounding_score=0.0,
                reason="No domain could be extracted from the input.",
                evidence={"structural": {"kind": "malformed"}})

        ev: Dict = {
            "url": url_str,
            "domain": domain,
            "structural": {},
            "dns": {"resolved": None, "error": None},
            "whois": {"found": None, "age_days": None, "error": None},
            "rdap": {"found": None, "age_days": None, "error": None},
            "liveness": {"live": None, "status": None, "error": None},
            "reference": {},
        }

        st = structural_evidence(domain)
        ev["structural"] = st
        if st["kind"] == "reserved":
            st["weight"] = W_RESERVED_PATTERN
        elif st["kind"] == "ip":
            st["weight"] = W_IP_LITERAL
        elif st["kind"] == "valid":
            st["weight"] = W_STRUCTURAL_OK
        else:
            st["weight"] = W_MALFORMED

        # Direct existence proof short-circuits the expensive lookups: if the
        # structure already says 'can never exist' or 'IP', no DNS/WHOIS needed.
        ev["reference"] = self.store.query(domain)

        if st["kind"] == "ip":
            exists = True
            score = self._grounding_score(ev)
            ev["grounding_score"] = score
            return StageAResult(url_str, domain, exists, score,
                                self._build_reason(url_str, ev, exists), ev)

        if st["kind"] == "reserved":
            # Detect a reserved TLD without touching the network. DNS/WHOIS
            # are still attempted so the evidence pack is complete for the
            # dashboard, but the verdict is already decided.
            try:
                ev["dns"] = dict(zip(("resolved", "error"),
                                     self.dns_probe.resolve(domain)))
            except Exception as exc:
                ev["dns"] = {"resolved": None, "error": f"probe_error:{type(exc).__name__}"}
        else:
            ev["dns"] = dict(zip(("resolved", "error"),
                                 self.dns_probe.resolve(domain)))
            # DNS resolved proves existence, but domain AGE is still needed by
            # the verified-clean rule, so WHOIS runs for age only. A WHOIS
            # "not found" cannot overturn a resolving domain, so it is cleared.
            if ev["dns"]["resolved"] is True:
                w = dict(zip(("found", "age_days", "error"),
                             self.whois_probe.lookup(domain)))
                if w["found"] is False:
                    w["found"] = None
                ev["whois"] = w
                if w["age_days"] is None:
                    try:
                        rdap = dict(zip(("found", "age_days", "error"),
                                        self.rdap_probe.lookup(domain)))
                    except Exception as exc:
                        rdap = {"found": None, "age_days": None,
                                "error": f"rdap_probe_error:{type(exc).__name__}"}
                    ev["rdap"] = rdap
            else:
                ev["whois"] = dict(zip(("found", "age_days", "error"),
                                       self.whois_probe.lookup(domain)))
                # If legacy WHOIS is inconclusive (blocked/rate-limited/error),
                # fall back to RDAP - the structured successor. RDAP can rescue
                # a definitive answer and restore existence evidence.
                if ev["whois"]["found"] is None:
                    try:
                        rdap = dict(zip(("found", "age_days", "error"),
                                        self.rdap_probe.lookup(domain)))
                    except Exception as exc:
                        rdap = {"found": None, "age_days": None,
                                "error": f"rdap_probe_error:{type(exc).__name__}"}
                    ev["rdap"] = rdap
                    if rdap["found"] is not None:
                        ev["whois"] = {
                            "found": rdap["found"],
                            "age_days": rdap["age_days"],
                            "error": None,
                            "source": "rdap",
                        }

        # Liveness - only meaningful for structurally-valid, non-IP hosts.
        # page_gone (404/410) keeps exists=True but must keep grounding low so
        # Stage B can never certify a removed page; dns_failed corroborates
        # non-existence when the resolver was inconclusive.
        if st["kind"] == "valid":
            try:
                ev["liveness"] = dict(zip(("live", "status", "error"),
                                          self.liveness_probe.check(
                                              self._as_http_url(url_str, domain))))
            except Exception as exc:
                ev["liveness"] = {"live": None, "status": None,
                                  "error": f"probe_error:{type(exc).__name__}"}
            if ev["liveness"]["live"] is False:
                ev["liveness"]["error"] = ev["liveness"].get("error") or "page_gone"

        score = self._grounding_score(ev)

        # Decision table - strict priority, see module docstring.
        exists = self._decide(ev, score)
        uncertain = self.has_no_evidence(ev)
        ev["grounding_score"] = score
        ev["uncertain"] = uncertain
        return StageAResult(url_str, domain, exists, score,
                            self._build_reason(url_str, ev, exists), ev,
                            uncertain=uncertain)

    def _decide(self, ev: Dict, score: float) -> bool:
        st = ev["structural"]["kind"]
        if st == "ip":
            return True
        if st == "reserved":
            return False
        # The exact address answers "not found": it does not exist, even when
        # the domain itself is real. (A made-up page on a real site is a
        # hallucinated URL.)
        if ev["liveness"].get("status") in (404, 410):
            return False
        if ev["dns"]["resolved"] is True:
            return True
        if ev["dns"]["resolved"] is False:
            return False
        if ev["whois"]["found"] is True:
            return True
        if ev["whois"]["found"] is False:
            return False
        if ev["reference"]["exact_hit"]:
            return True
        # HTTP-level DNS failure (resolver could not even name-resolve) is a
        # second, independent negative signal - flip to fabricated.
        if ev["liveness"].get("error") == "dns_failed":
            return False

        # FIXED: previously this fell back to `score >= exist_threshold`, and
        # because BASE_SCORE == EXIST_THRESHOLD == 0.5, a URL with NO evidence
        # at all (offline / every probe failed) defaulted to exists=True. That
        # silently absolves an unverifiable LLM URL - the exact failure this
        # module exists to catch. We now mark such cases UNCERTAIN (see
        # `has_no_evidence`) instead of asserting existence; the pipeline
        # treats uncertain URLs as not-grounded but does NOT label them a
        # clean "Hallucination" with a confident reason.
        if self.has_no_evidence(ev):
            return False
        return score >= self.exist_threshold

    @staticmethod
    def has_no_evidence(ev: Dict) -> bool:
        """True when NOT ONE probe produced a conclusive answer.

        A URL whose structure is valid but which could not be resolved by DNS,
        WHOIS or HTTP is 'unknown', not 'fabricated' and not 'grounded'. The
        pipeline uses this to avoid confidently calling an offline/blocked URL
        a hallucination.
        """
        return (
            ev["structural"]["kind"] not in ("ip", "reserved", "malformed")
            and ev["dns"]["resolved"] is None
            and ev["whois"]["found"] is None
            and ev["liveness"]["live"] is None
            and not ev["reference"]["exact_hit"]
        )

    @staticmethod
    def _as_http_url(url: str, domain: str) -> str:
        """Give the liveness probe a scheme it can socket to."""
        u = (url or "").strip()
        if "://" in u:
            return u
        return f"http://{u or domain}"

    def analyze_batch(self, urls: List[str], delay: float = 0.0) -> List[StageAResult]:
        """Sequential batch (parallelism would smash WHOIS rate limits)."""
        out = []
        for u in urls:
            out.append(self.analyze(u))
            if delay:
                time.sleep(delay)
        return out
"""Stage A existence semantics: positive evidence vs 'no evidence = uncertain'.

Regression for the BASE_SCORE==0.5 default that previously made every
unverifiable URL default to exists=True. Now a URL with NO conclusive probe
answer must be reported as uncertain (exists=False) rather than grounded.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from hallucination_detector import (HallucinationDetector, OfflineDnsProbe,
                                    OfflineLivenessProbe, OfflineRdapProbe,
                                    OfflineWhoisProbe)


class _EmptyStore:
    def query(self, domain):
        return {"exact_hit": False, "top_similarity": 0.0, "best_match": ""}


class _Dns:
    def __init__(self, resolved): self._r = resolved
    def resolve(self, domain): return self._r, None


class _Whois:
    def __init__(self, found): self._f = found
    def lookup(self, domain): return self._f, None, None


class _Live:
    def __init__(self, live): self._l = live
    def check(self, url): return self._l, (200 if self._l else None), None


def _det(dns=None, whois=None, live=None, rdap=None):
    return HallucinationDetector(
        dns_probe=dns or OfflineDnsProbe(),
        whois_probe=whois or OfflineWhoisProbe(),
        liveness_probe=live or OfflineLivenessProbe(),
        rdap_probe=rdap or OfflineRdapProbe(),
        reference_store=_EmptyStore(),
    )


def test_no_evidence_at_all_is_uncertain_not_grounded():
    r = _det().analyze("https://unknown-brand-new.com/login")
    assert r.exists is False
    assert r.uncertain is True
    assert r.to_dict()["uncertain"] is True


def test_dns_resolved_is_confident_existence():
    r = _det(dns=_Dns(True)).analyze("https://real-thing.com")
    assert r.exists is True
    assert r.uncertain is False


def test_dns_nxdomain_is_confident_non_existence():
    r = _det(dns=_Dns(False)).analyze("https://madeup-thing.com")
    assert r.exists is False
    assert r.uncertain is False


def test_whois_found_grounds_even_when_dns_blocked():
    r = _det(whois=_Whois(True)).analyze("https://registered.com")
    assert r.exists is True
    assert r.uncertain is False


def test_reserved_tld_never_uncertain():
    r = _det().analyze("https://evil.example/login")
    assert r.exists is False
    assert r.uncertain is False


class _Rdap:
    def __init__(self, found): self._f = found

    def lookup(self, domain):
        return self._f, None, None


def test_rdap_rescues_existence_when_whois_inconclusive():
    # WHOIS offline (None) but RDAP definitively finds the registration.
    r = _det(whois=OfflineWhoisProbe(), rdap=_Rdap(True)).analyze(
        "https://registered-only-in-rdap.com")
    assert r.exists is True
    assert r.uncertain is False
    assert r.evidence["whois"].get("source") == "rdap"

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


class _LiveStatus:
    def __init__(self, live, status, error=None):
        self._live, self._status, self._error = live, status, error

    def check(self, url): return self._live, self._status, self._error


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


def test_waf_404_on_site_root_is_blocked_not_missing():
    # www.ftc.gov answers scripted clients with a generic Akamai 404 even
    # though the site is real. That is a block, not a missing page.
    r = _det(dns=_Dns(True), whois=_Whois(True),
             live=_LiveStatus(None, 404, "blocked_by_host")).analyze(
        "https://www.ftc.gov/")
    assert r.exists is True
    assert r.uncertain is False
    assert "bot-protection" in r.reason


def test_real_404_on_a_page_path_is_still_missing():
    r = _det(dns=_Dns(True), whois=_Whois(True),
             live=_LiveStatus(False, 404, "page_gone")).analyze(
        "https://www.ftc.gov/no-such-page")
    assert r.exists is False
    assert r.uncertain is False


def test_whois_registry_text_saying_object_does_not_exist_is_not_a_record():
    from hallucination_detector import WHOIS_NOT_FOUND_RE

    text = "The queried object does not exist: touchngo-my.top"
    assert WHOIS_NOT_FOUND_RE.search(text)
    assert not WHOIS_NOT_FOUND_RE.search("Registrar: MarkMonitor Inc.")


def _doh_probe(answers, system=(None, None)):
    from hallucination_detector import NetworkDnsProbe

    probe = NetworkDnsProbe()
    probe._doh_answer = lambda name, base, domain: answers[name]
    probe._system_resolve = lambda domain: system
    return probe


def test_two_public_nxdomain_overrides_a_local_hijack():
    # A Malaysian ISP answers blocked phishing domains with a block-page
    # address. The public resolvers are the neutral witnesses.
    probe = _doh_probe({"google": (False, "google:NXDOMAIN"),
                        "cloudflare": (False, "cloudflare:NXDOMAIN")},
                       system=(True, None))
    resolved, error, detail = probe.resolve("touchngo-my.top")
    assert resolved is False
    assert error == "NXDOMAIN"


def test_single_public_negative_defers_to_a_local_positive_answer():
    # One resolver unreachable, one says NXDOMAIN, the local resolver resolves:
    # a single negative is too weak to accuse the model of fabrication.
    probe = _doh_probe({"google": (False, "google:NXDOMAIN"),
                        "cloudflare": (None, "cloudflare:unreachable")},
                       system=(True, None))
    resolved, _, detail = probe.resolve("maybe-blocked.com")
    assert resolved is True
    assert "system:answer" in detail


def test_doh_unreachable_falls_back_to_the_system_resolver():
    probe = _doh_probe({"google": (None, "google:unreachable"),
                        "cloudflare": (None, "cloudflare:unreachable")},
                       system=(False, "NXDOMAIN"))
    resolved, error, detail = probe.resolve("made-up-host.com")
    assert resolved is False
    assert "system_fallback" in detail


def test_blocked_root_detector_only_matches_generic_waf_pages():
    from hallucination_detector import NetworkLivenessProbe

    akamai = ("<h1>Page Not Found</h1><p>No additional information is "
              "available with regards to this resource.</p>")
    assert NetworkLivenessProbe._looks_like_blocked_root(
        "https://www.ftc.gov/", 404, akamai, "AkamaiGHost")

    # A normal site 404 is content removal, not a block.
    assert not NetworkLivenessProbe._looks_like_blocked_root(
        "https://example.com/", 404, "<h1>Page not found</h1>", "nginx")
    # A missing sub-page is checked as a page, not as the site root.
    assert not NetworkLivenessProbe._looks_like_blocked_root(
        "https://www.ftc.gov/missing", 404, akamai, "AkamaiGHost")


class _DnsDetail:
    def __init__(self, resolved, error, detail):
        self._r = (resolved, error, detail)

    def resolve(self, domain): return self._r


def test_public_nodata_is_never_fabrication_even_if_local_says_nxdomain():
    # affinbank.com.my: both public resolvers answer NOERROR with no address
    # record. The name exists, so a local NXDOMAIN must not accuse it.
    probe = _doh_probe({"google": (None, "google:no_ip_answer"),
                        "cloudflare": (None, "cloudflare:no_ip_answer")},
                       system=(False, "NXDOMAIN"))
    resolved, _, _ = probe.resolve("affinbank.com.my")
    assert resolved is None


def test_reason_claims_public_nxdomain_only_when_both_public_said_it():
    det = _det(dns=_DnsDetail(False, "NXDOMAIN",
                              "google:NXDOMAIN+cloudflare:unreachable+system_fallback"))
    reason = det.analyze("https://made-up-name-x.com").reason
    assert "both public resolvers" not in reason

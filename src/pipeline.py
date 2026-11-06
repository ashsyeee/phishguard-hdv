"""
pipeline.py - Step 7: Orchestration. STAGE A, then STAGE B, strictly SEQUENTIAL.

THE ORDERING IS THE DESIGN (evidence for the viva, FYP Chapter 3):

    analyze_url() ALWAYS runs Stage A first and, when Stage A says the URL is
    fabricated, STOPS IMMEDIATELY. The classifier and verification engine are
    simply never constructed-as-called on that input - the short-circuit is
    structural, not just a preference:

        * Stage A answers ONLY "does it exist / is it grounded?"
        * Stage B answers ONLY "given it exists, is it malicious?"

    A fabricated URL cannot be "not malicious" - classifying it would give a
    false safety verdict, which is exactly the failure mode of plain phishing
    detectors on LLM output. Short-circuiting builds the distinction into the
    control flow itself.

Every returned dict carries `stage_reached` ("A" or "B") so the dashboard and
reader can SEE which question was answered - the audit trail for the viva.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("phishguard.pipeline")

_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import features as F
from classifiers import StageBClassifier
from hallucination_detector import HallucinationDetector
from risk_scoring import apply_clean_rule, build_reason, compute_risk, final_label
from verification_engine import VerificationEngine
from page_inspector import inspect_page


def _domain_age_days(evidence: Optional[Dict]) -> Optional[int]:
    """Best known domain age from WHOIS or RDAP (None when neither answered)."""
    ages = []
    for key in ("whois", "rdap"):
        age = ((evidence or {}).get(key) or {}).get("age_days")
        if age is not None:
            ages.append(int(age))
    return max(ages) if ages else None


class PhishGuardPipeline:
    """Sequential Stage A -> Stage B. Never parallel, always short-circuits."""

    def __init__(
        self,
        stage_a: Optional[HallucinationDetector] = None,
        classifier: Optional[StageBClassifier] = None,
        verifier: Optional[VerificationEngine] = None,
        page_inspector=None,
    ):
        self.stage_a = stage_a or HallucinationDetector()
        self.classifier = classifier or StageBClassifier()
        self.verifier = verifier or VerificationEngine()
        self.page_inspector = page_inspector or inspect_page

    # ------------------------------------------------------------------
    # Single URL
    # ------------------------------------------------------------------
    def analyze_url(
        self,
        url: str,
        url_label: Optional[str] = None,
        source: Optional[str] = None,
        llm_model: Optional[str] = None,
        original_user_question: Optional[str] = None,
    ) -> Dict:
        """Full sequential analysis. Short-circuits at A if fabricate.

        Provenance (CHANGE 15) is optional: `source` ("LLM_GENERATED"),
        `llm_model` and `original_user_question` are carried through to the
        result so the LLM origin of an indicator is never lost.
        """
        url = str(url).strip()

        # ===== STAGE A =====
        a = self.stage_a.analyze(url)
        grounding_score = float(a.grounding_score)

        # "Uncertain" = every probe was inconclusive (offline/blocked). We must
        # NOT short-circuit those to a confident "Hallucination": proceed to
        # Stage B so external evidence (VirusTotal/Google Safe Browsing + the ML model)
        # can still speak, and flag the uncertainty in the reason.
        if not a.exists and not getattr(a, "uncertain", False):
            # Classifier, verification and Stage B risk are NOT invoked -
            # structural short-circuit (CHANGE 2). Every Stage B field is null.
            result = {
                "url": url,
                "domain": a.domain,
                "stage_reached": "A",
                "exists": False,
                "grounding_score": grounding_score,
                # --- Stage B fields: skipped, must be null ---------------
                "rf_probability": None,
                "xgb_probability": None,
                "classifier_confidence": None,
                "model_disagreement": None,
                "verification_result": None,
                "verification_offline": None,
                "verification_detail": None,
                "classifier_detail": None,
                "virustotal_result": None,
                "safe_browsing_result": None,
                "threat_risk_score": None,
                "risk_score": None,
                # ---------------------------------------------------------
                "final_label": "Hallucination",
                "reason": (f"{a.reason}. -> labeled Hallucination "
                           f"[existence FAILED: stopped at Stage A; Random "
                           f"Forest, XGBoost, VirusTotal and Google Safe Browsing were "
                           f"NOT run (CHANGE 2).]"),
                "evidence_stage_a": a.evidence,
                "ground_truth_category": url_label,
                "source": source,
                "llm_model": llm_model,
                "original_user_question": original_user_question,
            }
            logger.info("Stage A -> HALLUCINATION (%s)", url)
            return result

        # ===== STAGE B ===== (reached when exists=True, OR when existence was
        # simply unverifiable - `uncertain` - so external evidence can decide)
        uncertain = bool(getattr(a, "uncertain", False))
        feats = F.extract_features(url)
        breakdown = self.classifier.predict_breakdown(feats, url=url)
        is_known_legit = bool(breakdown.get("known_legit_override"))
        rf_probability = breakdown["rf_probability"]
        xgb_probability = breakdown["xgb_probability"]
        classifier_confidence = float(breakdown["classifier_confidence"])
        model_disagreement = breakdown["model_disagreement"]

        v = self.verifier.verify(url)
        verification_result = float(v.verification_result)
        coverage = float(getattr(v, "coverage", 0.0))
        vd = v.to_dict()
        sources = vd.get("sources") or {}
        virustotal_result = (sources.get("virustotal") or {}).get("status")
        urlhaus_result = (sources.get("urlhaus") or {}).get("status")
        safe_browsing_result = (sources.get("safe_browsing") or {}).get("status")
        urlscan_result = (sources.get("urlscan") or {}).get("status")
        page = self.page_inspector(url) if not is_known_legit else {"suspicious": False}

        fused = compute_risk(verification_result, classifier_confidence)
        threat_risk_score = fused["threat_risk_score"]
        label = final_label(threat_risk_score, exists=True,
                            verification_result=verification_result,
                            coverage=coverage)
        age_days = _domain_age_days(a.evidence)
        if age_days is None and hasattr(self.verifier, "domain_age_days"):
            age_days = self.verifier.domain_age_days(a.domain or url)
        genuine = sum(1 for s in sources.values()
                      if s.get("status") in ("POSITIVE_MATCH", "NO_MATCH"))
        positive = sum(1 for s in sources.values()
                       if s.get("status") == "POSITIVE_MATCH")
        # The allowlist only promotes an official domain when no feed reports
        # it. Real feed results are kept as-is - nothing is overwritten.
        allowlisted_clean = is_known_legit and positive == 0
        # The allowlist covers the DOMAIN. "Likely Safe" also needs this exact
        # page to answer (HTTP 2xx/3xx); otherwise the page is unconfirmed.
        lv_status = (a.evidence.get("liveness") or {}).get("status")
        page_confirmed = lv_status is not None and 200 <= int(lv_status) < 400
        clean_note = ""
        if allowlisted_clean and page_confirmed:
            label = "Likely Safe"
        elif allowlisted_clean:
            label = "Unverified"
            clean_note = ("official domain, but this exact page could not be "
                          "confirmed (site blocked or unreachable)")
        else:
            label, clean_note = apply_clean_rule(
                label,
                genuine_sources=genuine,
                positive_sources=positive,
                ml_confidence=classifier_confidence,
                age_days=age_days,
                existence_uncertain=uncertain,
                brand_impersonation=bool(F.brand_profile(url).get("impersonation")),
                page_suspicious=bool(page.get("suspicious")),
            )
            if uncertain and label == "Likely Safe":
                # Existence could not be confirmed: never present an
                # unverifiable URL as "Likely Safe".
                label = "Suspicious (unverified existence)"
        if allowlisted_clean and page_confirmed:
            reason = (
                f"Official domain (exact allowlist match). Verified as legitimate "
                f"for {F.brand_profile(url).get('official_brand') or 'curated'} brand "
                f"- ML override applied; third-party feeds not required. "
                f"[Stage A: {a.reason}]"
            )
        elif allowlisted_clean:
            reason = (f"Official domain, but this exact page could not be confirmed "
                      f"(HTTP status: {lv_status or 'no answer'}). [Stage A: {a.reason}]")
        else:
            reason = (
                build_reason(
                    threat_risk_score, label,
                    verification_result, classifier_confidence,
                    verification_note=v.reason,
                    classifier_breakdown=breakdown,
                    coverage=coverage,
                    warnings=list(getattr(v, "warnings", [])),
                )
                + (f" [Clean check: {clean_note}]" if clean_note else "")
                + f" [Stage A: {a.reason}]"
            )

        result = {
            "url": url,
            "domain": a.domain,
            "stage_reached": "B",
            "exists": True,
            "existence_uncertain": uncertain,
            "grounding_score": grounding_score,
            "known_legit_override": bool(is_known_legit),
            # --- Stage B fields -----------------------------------------
            "rf_probability": rf_probability,
            "xgb_probability": xgb_probability,
            "classifier_confidence": classifier_confidence,
            "model_disagreement": model_disagreement,
            "verification_result": verification_result,
            "verification_offline": bool(v.offline),
            "verification_detail": vd,
            "classifier_detail": breakdown,
            "virustotal_result": virustotal_result,
            "urlhaus_result": urlhaus_result,
            "safe_browsing_result": safe_browsing_result,
            "urlscan_result": urlscan_result,
            "page_signals": page,
            "domain_age_days": age_days,
            "threat_risk_score": threat_risk_score,
            "risk_score": threat_risk_score,  # named alias kept for old feeds
            # -------------------------------------------------------------
            "final_label": label,
            "reason": reason,
            "evidence_stage_a": a.evidence,
            "ground_truth_category": url_label,
            "source": source,
            "llm_model": llm_model,
            "original_user_question": original_user_question,
        }
        logger.info("Stage B -> %s (threat %.3f, url=%s)", label,
                    threat_risk_score, url)
        return result

    # ------------------------------------------------------------------
    # Batch / CSV
    # ------------------------------------------------------------------
    def analyze_batch(self, urls: List[str], delay: float = 0.0) -> List[Dict]:
        """Sequential batch - no parallelism, so vendor rate limits survive."""
        out = []
        for u in urls:
            out.append(self.analyze_url(u))
            if delay:
                time.sleep(delay)
        return out

    def analyze_csv(self, csv_path: str, out_path: Optional[str] = None,
                    delay: float = 0.0) -> "pd.DataFrame":
        """Analyse every row of a csv (uses its 'url' column)."""
        import pandas as pd
        df = pd.read_csv(csv_path)
        if "url" not in df.columns:
            raise ValueError(f"'url' column not found in {csv_path}")
        results = self.analyze_batch(df["url"].tolist(), delay)
        out = pd.DataFrame(results).copy()
        if out_path:
            out.to_csv(out_path, index=False)
            logger.info("Batch results -> %s", out_path)
        return out


def analyze_url(url: str, **kw) -> Dict:
    """Module-level convenience for scripts/dashboard."""
    return PhishGuardPipeline(**kw).analyze_url(url)
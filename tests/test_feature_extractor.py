"""Tests for modules/feature_extractor.py (canonical ML features + heuristics)."""
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    heuristic_score,
    build_feature_matrix,
)


def test_feature_names_stable():
    feats = extract_features("https://example.com")
    assert list(feats.keys()) == list(FEATURE_NAMES)
    # Delegated to src/features.py - count must match the canonical vector and
    # the models trained on it (currently 30).
    assert len(FEATURE_NAMES) == len(feats)
    assert len(FEATURE_NAMES) == 30


def test_features_numeric():
    feats = extract_features("https://example.com")
    assert all(isinstance(v, (int, float)) for v in feats.values())


def test_ip_based_url():
    feats = extract_features("http://192.168.0.1/login.php")
    assert feats["has_ip_address"] == 1.0


def test_lookalike_detected():
    feats = extract_features("https://paypa1-secure-login.com/verify")
    assert feats["near_legit_lookalike"] == 1.0
    assert feats["segment_lookalike_count"] >= 1
    assert feats["character_substitution_flagged"] == 1.0


def test_legit_domain_not_lookalike():
    feats = extract_features("https://www.paypal.com/signin")
    assert feats["best_match_is_legit"] == 1.0
    assert feats["near_legit_lookalike"] == 0.0


def test_suspicious_keywords():
    feats = extract_features("https://bank.example/account/verify-token")
    assert feats["suspicious_keyword_present"] == 1.0


def test_matrix_order_preserved():
    df = pd.DataFrame({"url": ["https://a.com", "https://b.com"]})
    m = build_feature_matrix(df)
    assert list(m.columns) == list(FEATURE_NAMES)
    assert len(m) == 2


# ---------- heuristics ----------


def test_heuristic_range():
    for url in ["https://example.com", "http://192.168.0.1/",
                "https://secure-login-paypa1.bank.xyz/verify?x=1"]:
        s = heuristic_score(url)["score"]
        assert 0.0 <= s <= 1.0


def test_heuristic_ip_address_high():
    s = heuristic_score("http://192.168.0.1/accounts/login")["score"]
    s2 = heuristic_score("https://example.com")["score"]
    assert s > s2


def test_heuristic_components_documented():
    r = heuristic_score("https://x.com")
    assert set(r["components"].keys()) == set(r["weights"].keys())
    assert abs(sum(r["weights"].values()) - 1.0) < 1e-9
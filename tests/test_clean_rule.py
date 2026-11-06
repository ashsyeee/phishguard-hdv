"""Verified-clean rule: "Unverified" becomes "Likely Safe" only with proof."""
import pytest

from risk_scoring import apply_clean_rule


def _run(label="Unverified", genuine=2, positive=0, ml=0.05, age=400,
         uncertain=False):
    return apply_clean_rule(
        label,
        genuine_sources=genuine,
        positive_sources=positive,
        ml_confidence=ml,
        age_days=age,
        existence_uncertain=uncertain,
    )


def test_old_domain_clean_intel_and_low_ml_is_verified_clean():
    label, note = _run()
    assert label == "Likely Safe"
    assert "verified clean" in note


def test_single_feed_is_not_enough_for_verified_clean():
    label, note = _run(genuine=1)
    assert label == "Unverified"
    assert "need 2" in note


def test_unknown_age_is_not_verified_clean():
    label, _ = _run(age=None)
    assert label == "Unverified"


def test_young_domain_under_180_days_stays_unverified():
    label, note = _run(age=90)
    assert label == "Unverified"
    assert "need 180" in note


def test_new_domain_under_30_days_is_suspicious_even_when_clean():
    label, note = _run(age=5)
    assert label == "Suspicious"
    assert "5 day" in note


def test_high_ml_blocks_verified_clean():
    label, _ = _run(ml=0.9)
    assert label == "Unverified"


def test_any_positive_feed_blocks_promotion():
    label, _ = _run(positive=1)
    assert label == "Unverified"


def test_uncertain_existence_blocks_verified_clean():
    label, _ = _run(uncertain=True)
    assert label == "Unverified"


def test_brand_impersonation_blocks_promotion_even_when_old_and_clean():
    label, note = apply_clean_rule(
        "Unverified", genuine_sources=2, positive_sources=0, ml_confidence=0.002,
        age_days=4539, existence_uncertain=False, brand_impersonation=True)
    assert label == "Suspicious"
    assert "official domain" in note


@pytest.mark.parametrize("label", ["Malicious", "Suspicious", "Hallucination"])
def test_strong_labels_pass_through_untouched(label):
    assert _run(label=label, age=5)[0] == label

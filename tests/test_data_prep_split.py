"""Data-leakage regression tests for the domain-grouped split (Step 1).

The original pipeline de-duplicated on the full URL only, so a phishing
campaign's DOMAIN could appear in both training and the held-out test split
(different paths). That inflated held-out metrics. These tests lock in the fix:
every registrable domain must land in exactly ONE split.
"""
import pandas as pd
import pytest

from data_prep import (clean_and_merge, stratified_split,
                       _assert_no_domain_overlap)


def _synthetic_df():
    """Two categories x several domains, each domain with 2 URL paths."""
    rows = []
    for i in range(40):
        for path in ("/", "/login"):
            rows.append({
                "url": f"https://legit{i}.com{path}",
                "domain": f"legit{i}.com",
                "category": "real_legitimate",
                "source": "test",
                "exists_ground_truth": True,
                "is_phishing": False,
                "note": "",
            })
            rows.append({
                "url": f"https://phish{i}.com{path}",
                "domain": f"phish{i}.com",
                "category": "real_phishing",
                "source": "test",
                "exists_ground_truth": True,
                "is_phishing": True,
                "note": "",
            })
    return pd.DataFrame(rows)


def test_domain_dedup_collapses_multiple_paths():
    df = _synthetic_df()
    merged = clean_and_merge(df, pd.DataFrame(), domain_dedup=True)
    # 80 domains, one row each (paths collapsed).
    assert merged["domain"].nunique() == merged.shape[0]


def test_url_only_dedup_keeps_domain_duplicate_rows():
    df = _synthetic_df()
    merged = clean_and_merge(df, pd.DataFrame(), domain_dedup=False)
    # URL-level dedup alone leaves both paths -> domains repeat.
    assert merged["domain"].nunique() < merged.shape[0]


def test_split_has_no_domain_overlap():
    df = clean_and_merge(_synthetic_df(), pd.DataFrame(), domain_dedup=True)
    train, val, test = stratified_split(df, seed=42)
    tr, va, te = (set(train["domain"]), set(val["domain"]), set(test["domain"]))
    assert not (tr & va), "domain leaked between train and val"
    assert not (tr & te), "domain leaked between train and test"
    assert not (va & te), "domain leaked between val and test"


def test_assert_no_domain_overlap_raises():
    df = pd.DataFrame({
        "url": ["https://a.com", "https://a.com/x"],
        "domain": ["a.com", "a.com"],
        "category": ["real_legitimate", "real_phishing"],
        "is_phishing": [False, True],
    })
    with pytest.raises(ValueError, match="leakage"):
        _assert_no_domain_overlap(df, df, df, "domain")


def test_split_keeps_every_category_present():
    df = clean_and_merge(_synthetic_df(), pd.DataFrame(), domain_dedup=True)
    train, val, test = stratified_split(df, seed=42)
    for part in (train, val, test):
        assert {"real_legitimate", "real_phishing"} <= set(part["category"])

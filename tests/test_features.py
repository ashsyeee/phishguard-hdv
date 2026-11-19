"""Step 2 tests: feature extraction sanity + lookalike determinism."""
import numpy as np
import pandas as pd
import pytest

from features import (FEATURE_NAMES, _split_host, build_feature_matrix,
                      domain_similarity, extract_features, levenshtein)


def test_malaysian_two_part_tld_parsed_correctly():
    # "maybank2u.com.my" -> suffix "com.my", registrable "maybank2u.com.my",
    # no subdomain. Previously missing from TWO_PART_TLDS, so it was parsed as
    # registrable "com.my" with "maybank2u" wrongly counted as a subdomain.
    suffix, registrable, sub = _split_host("maybank2u.com.my")
    assert suffix == "com.my"
    assert registrable == "maybank2u.com.my"
    assert sub == ""

    for tld in ("gov.my", "org.my", "edu.my", "mil.my", "net.my"):
        suffix, registrable, _ = _split_host(f"portal.{tld}")
        assert suffix == tld, tld
        assert registrable == f"portal.{tld}", tld


def test_digit_bearing_legit_brand_not_flagged_as_substitution():
    # maybank2u / touchngo are legit brands that contain digits; they must not
    # trip the character-substitution heuristic.
    for u in ["https://www.maybank2u.com.my/login",
              "https://maybank2u.com.my"]:
        assert extract_features(u)["character_substitution_flagged"] == 0, u


def test_feature_names_match_extracted_keys():
    feats = extract_features("https://www.paypal.com/signin")
    assert set(FEATURE_NAMES) == set(feats.keys())
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))  # no duplicates


def test_all_features_are_numeric():
    for u in ["https://paypa1-secure.invalid", "no scheme here",
              "http://192.168.0.1/login.php", ""]:
        feats = extract_features(u)
        for name, val in feats.items():
            assert isinstance(val, (int, float)), (u, name, type(val))
            assert np.isfinite(val) or val != val, (u, name, val)


def test_legit_domain_not_marked_as_lookalike():
    for u in ["https://www.paypal.com/signin", "https://login.paypal.com/",
              "https://accounts.google.com"]:
        f = extract_features(u)
        assert f["best_match_is_legit"] == 1, u
        assert f["near_legit_lookalike"] == 0, u
        assert f["segment_lookalike_count"] == 0, u


def test_character_substitution_lookalikes_flagged():
    for u in ["https://paypa1-secure-login.invalid/account/verify",
              "https://go0gle.example/update",
              "https://app1e-verify.test/signin", "https://paypa1.com/login"]:
        f = extract_features(u)
        assert f["near_legit_lookalike"] == 1, u
        assert f["segment_lookalike_count"] >= 1, u
        assert f["character_substitution_flagged"] == 1, u
        assert f["best_match_is_legit"] == 0, u


def test_brand_fingerprint_in_reserved_lookalike():
    f = extract_features("https://paypal-secure.account.invalid")
    assert f["hostname_brand_hits"] >= 1        # 'paypal' inside host
    assert f["near_legit_lookalike"] == 1
    assert f["best_match_is_legit"] == 0


def test_ip_literal_detected():
    f = extract_features("http://192.168.5.4/login.php")
    assert f["has_ip_address"] == 1
    assert f["is_https"] == 0


def test_suspicious_keywords_counted():
    f = extract_features("https://secure-login.verify-billing.com/signin/account")
    assert f["suspicious_keyword_present"] == 1
    assert f["suspicious_keyword_count"] >= 4


def test_zero_suspicious_keywords_clean_url():
    f = extract_features("https://example.com/blog/post-1")
    assert f["suspicious_keyword_present"] == 0


def test_levenshtein_basics():
    assert levenshtein("paypal", "paypa1") == 1      # one substitution
    assert levenshtein("cat", "cats") == 1           # one insertion
    assert levenshtein("", "") == 0
    assert levenshtein("abc", "") == 3
    assert levenshtein("kitten", "sitting") == 3     # classic
    assert levenshtein("paypal", "paypa1", cap=1) == 1
    assert levenshtein("abcdef", "zzzzzz", cap=2) == 3  # capped -> cap+1


def test_domain_similarity_best_match():
    r = domain_similarity("https://paypa1-secure.invalid")
    assert r["best_match_domain"] == "paypal.com"
    assert 0.0 < r["max_domain_similarity"] <= 1.0


def test_build_feature_matrix_preserves_order():
    df = pd.DataFrame({"url": ["https://paypal.com", "https://example.com"]})
    m = build_feature_matrix(df)
    assert m.shape == (2, len(FEATURE_NAMES))
    assert list(m.columns) == list(FEATURE_NAMES)
    assert m["near_legit_lookalike"].tolist() == [0, 0]
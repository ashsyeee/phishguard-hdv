"""Official-domain allowlist: exact registrable matches only."""
import pytest

import features as F


@pytest.mark.parametrize("url", [
    "https://www.wikipedia.org/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.youtube.com/watch?v=x",
    "https://x.com/home",
    "https://www.maybank2u.com.my/",
])
def test_official_domains_are_allowlisted(url):
    assert F.is_known_legit_domain(url)


@pytest.mark.parametrize("url", [
    "https://www.bnm.gov.my/",
    "https://www.imi.gov.my/",
    "https://www.bankrakyat.com.my/",
    "https://www.uob.com.my/",
    "https://www.hsbc.com.my/",
    "https://www.ambankspot.com/",
])
def test_verified_malaysian_official_sites_are_allowlisted(url):
    assert F.is_known_legit_domain(url)


@pytest.mark.parametrize("url", [
    "https://wikipedia-login.com/",
    "https://wikipedia.org.evil.net/",
    "https://youtube-verify.xyz/signin",
    "https://maybank2u-secure-login.com/",
    "https://bnm.gov.my.secure-login.xyz/",
    "https://uob-login-verify.com/",
])
def test_lookalikes_are_not_allowlisted(url):
    assert not F.is_known_legit_domain(url)


def test_lookalike_of_new_brand_is_flagged_as_impersonation():
    prof = F.brand_profile("https://wikipedia-login.com/")
    assert prof["impersonation"] == 1
    assert prof["official_match"] is False

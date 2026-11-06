"""Page inspection: fake-login signals from HTML text (no network)."""
from page_inspector import analyse_html

LOGIN_OWN = """<html><head><title>Sign in to your account</title></head>
<body><form action="/login"><input type="text" name="u">
<input type="password" name="p"></form></body></html>"""

LOGIN_EXTERNAL = """<html><head><title>Sign in</title></head>
<body><form action="https://collect-data.example.net/post">
<input type="password" name="p"></form></body></html>"""

NO_PASSWORD = """<html><head><title>Weather today</title></head>
<body><p>Sunny</p></body></html>"""


def test_login_posting_to_another_site_is_suspicious():
    out = analyse_html(LOGIN_EXTERNAL, "https://shop.example.com/",
                       "https://shop.example.com/")
    assert out["has_password_field"] is True
    assert out["external_form_action"] is True
    assert out["suspicious"] is True


def test_login_posting_to_own_site_is_not_suspicious_by_itself():
    out = analyse_html(LOGIN_OWN, "https://www.example.com/",
                       "https://www.example.com/")
    assert out["has_password_field"] is True
    assert out["external_form_action"] is False
    assert out["suspicious"] is False


def test_page_without_password_is_never_suspicious_on_form_alone():
    out = analyse_html(NO_PASSWORD, "https://www.example.com/",
                       "https://www.example.com/")
    assert out["has_password_field"] is False
    assert out["suspicious"] is False


def test_redirect_off_domain_with_password_is_suspicious():
    out = analyse_html(LOGIN_OWN, "https://promo.example.com/",
                       "https://landing.other-site.org/")
    assert out["redirected_off_domain"] is True
    assert out["suspicious"] is True


def test_title_naming_another_brand_with_password_is_suspicious():
    html = ("<html><head><title>AmBank Online Banking</title></head>"
            "<body><form action='/x'><input type='password'></form></body></html>")
    out = analyse_html(html, "https://ambank-helpdesk.xyz/",
                       "https://ambank-helpdesk.xyz/")
    assert out["title_brand_mismatch"] is True
    assert out["suspicious"] is True


def test_malformed_html_does_not_crash():
    out = analyse_html("<<<not html<form action=", "https://a.example/",
                       "https://a.example/")
    assert "suspicious" in out

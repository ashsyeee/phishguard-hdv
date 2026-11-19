"""Tests for modules/url_extractor.py"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.url_extractor import extract_domains, extract_urls


def test_one_url():
    assert extract_urls("Visit https://example.com now.") == ["https://example.com"]


def test_multiple_urls():
    txt = "See https://a.com and https://b.org/report."
    assert extract_urls(txt) == ["https://a.com", "https://b.org/report"]


def test_duplicates_removed_order_preserved():
    txt = "https://dup.com https://dup.com/path https://dup.com"
    assert extract_urls(txt) == ["https://dup.com", "https://dup.com/path"]


def test_no_url():
    assert extract_urls("No links here") == []
    assert extract_urls("") == []


def test_trailing_punctuation_stripped():
    assert extract_urls("go to https://a.com.") == ["https://a.com"]
    assert extract_urls("(https://a.com)") == ["https://a.com"]


def test_markdown_link():
    assert extract_urls("[site](https://a.com)") == ["https://a.com"]


def test_host_case_normalised():
    assert extract_urls("HTTP://EXAMPLE.com/X") == ["http://example.com/X"]


def test_extract_domains():
    assert extract_domains("One: https://a.com Two: https://b.org/x") == ["a.com", "b.org"]
"""ML hostname model and the rules added alongside it."""

import pytest

from src.analysis.url_analysis import analyze_url
from src.classification.scorer import label_for_score
from src.core.config import model_path
from src.model.classifier import normalize_host, predict_phishing_probability

needs_model = pytest.mark.skipif(not model_path().is_file(), reason="Model not trained: python -m src.model.train")


def test_normalize_host_strips_www_port_and_path():
    assert normalize_host("https://WWW.Example.com:8443/login?x=1") == "example.com"
    assert normalize_host("paypa1.com/login") == "paypa1.com"


def test_host_keywords_rule():
    result = analyze_url("https://secure-verify-account-update.com/")
    ids = [r.rule_id for r in result.rules]
    assert "host_keywords" in ids


def test_free_hosting_rule():
    result = analyze_url("https://docusign-files-portal.netlify.app/")
    ids = [r.rule_id for r in result.rules]
    assert "free_hosting" in ids


@needs_model
def test_model_separates_obvious_cases():
    assert predict_phishing_probability("https://login-microsoftonline.support-auth.xyz/") >= 0.9
    assert predict_phishing_probability("https://www.bbc.co.uk/news") < 0.5


@needs_model
@pytest.mark.parametrize(
    "url",
    [
        "https://mail.google.com/mail/u/0/",
        "https://web.whatsapp.com/",
        "https://www.amazon.in/gp/cart",
        "https://github.com/opencv/opencv/issues",
        "https://docs.python.org/3/library/re.html",
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://www.irctc.co.in/nget/train-search",
        "https://en.wikipedia.org/wiki/Phishing",
    ],
)
def test_popular_legit_sites_stay_safe(url):
    assert label_for_score(analyze_url(url).score) == "Safe"


@needs_model
@pytest.mark.parametrize(
    "url",
    [
        "https://secure-verify-account-update.com/login",
        "https://hdfc-kyc-update.online/verify",
        "https://netflix-billing-update.com/pay",
        "https://docusign-files-portal.netlify.app/",
    ],
)
def test_realistic_phishing_flagged(url):
    assert label_for_score(analyze_url(url).score) != "Safe"


@pytest.fixture
def fake_blocklist(monkeypatch):
    import src.analysis.url_analysis as ua

    monkeypatch.setattr(
        ua,
        "load_blocklist",
        lambda: {"https://espacesecu-tehna.com/index.php", "https://docs.google.com/forms/d/phish123/viewform"},
    )
    ua._blocklist_index.cache_clear()
    yield
    ua._blocklist_index.cache_clear()


def test_blocklisted_url_is_high_risk(fake_blocklist):
    # Scheme, www. and trailing slash differences still match.
    result = analyze_url("http://www.espacesecu-tehna.com/index.php/")
    assert "blocklist" in [r.rule_id for r in result.rules]
    assert label_for_score(result.score) == "High-Risk Phishing"


def test_blocklisted_host_matches_other_paths(fake_blocklist):
    result = analyze_url("https://espacesecu-tehna.com/login")
    assert "blocklist" in [r.rule_id for r in result.rules]


def test_blocklist_does_not_flag_whole_trusted_domain(fake_blocklist):
    exact = analyze_url("https://docs.google.com/forms/d/phish123/viewform")
    other = analyze_url("https://docs.google.com/document/d/abc/edit")
    assert "blocklist" in [r.rule_id for r in exact.rules]
    assert "blocklist" not in [r.rule_id for r in other.rules]
    assert label_for_score(other.score) == "Safe"

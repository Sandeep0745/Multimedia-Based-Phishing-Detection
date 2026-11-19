"""URL heuristic analysis tests (no Tesseract required)."""

from src.analysis.url_analysis import analyze_url, levenshtein, registrable_domain
from src.classification.scorer import label_for_score


def test_levenshtein_typo():
    assert levenshtein("paypal", "paypa1") == 1


def test_registrable_domain():
    assert registrable_domain("secure.login.paypal.com") == "paypal.com"
    assert registrable_domain("foo.co.uk") == "foo.co.uk"


def test_legit_brand_stays_low():
    result = analyze_url("https://www.microsoft.com/")
    assert result.score < 35
    assert label_for_score(result.score) == "Safe"


def test_typosquat_high():
    # Rules alone give 68 (Suspicious); the ML model (not in git, see .gitignore) lifts it past 70.
    from src.core.config import model_path

    result = analyze_url("http://paypa1.com/login")
    assert result.score >= (70 if model_path().is_file() else 35)


def test_brand_chain_high():
    result = analyze_url("https://secure-login.paypal.com.evil.example/verify")
    assert result.score >= 70


def test_suspicious_tld_and_typo():
    result = analyze_url("https://amaz0n-prize.tk/claim")
    assert result.score >= 70


def test_shortener_suspicious_or_higher():
    result = analyze_url("https://bit.ly/3demoCheck")
    assert result.score >= 35


def test_userinfo_trick():
    result = analyze_url("https://paypal.com@evil.example/login")
    assert result.score >= 35

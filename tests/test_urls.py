"""Unit tests for URL extraction helpers."""

from src.extraction.urls import extract_urls, rejoin_broken_urls, undfang


def test_extract_full_url():
    text = "Visit https://www.microsoft.com for docs."
    urls = extract_urls(text)
    assert any("microsoft.com" in u for u in urls)


def test_extract_bare_domain():
    urls = extract_urls("Go to paypa1.com/login now")
    assert any("paypa1.com" in u for u in urls)


def test_undfang_hxxp():
    assert undfang("hxxps://evil.example/path").startswith("https://")


def test_rejoin_newline_split():
    text = "https://paypa1.\ncom/login"
    joined = rejoin_broken_urls(text)
    assert "paypa1.com" in joined.replace(" ", "")


def test_blank_line_does_not_glue_next_sentence():
    # Regression: OCR of benign_microsoft_notice.png produced "microsoft.comNoaction".
    text = "https://www.microsoft.com\n\nNo action is required on your account."
    assert extract_urls(text)[0] == "https://www.microsoft.com"


def test_complete_url_not_glued_to_following_word():
    urls = extract_urls("Visit https://www.microsoft.com for docs.")
    assert urls[0] == "https://www.microsoft.com"
    assert not any("comfor" in u.lower() for u in urls)


def test_sentence_period_not_joined():
    urls = extract_urls("Go to https://www.microsoft.com. Then sign in.")
    assert urls[0] == "https://www.microsoft.com"


def test_space_inside_host_rejoined():
    urls = extract_urls("Login at https://paypa1 .com/login now")
    assert urls[0] == "https://paypa1.com/login"


def test_path_split_across_line_rejoined():
    text = "https://evil.example/secure-\nupdate/verify"
    assert extract_urls(text)[0] == "https://evil.example/secure-update/verify"

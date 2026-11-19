"""Threat scorer combination tests."""

from src.classification.scorer import combine, label_for_score
from src.core.models import ComponentResult, FiredRule


def test_label_bands():
    assert label_for_score(0) == "Safe"
    assert label_for_score(34) == "Safe"
    assert label_for_score(35) == "Suspicious"
    assert label_for_score(69) == "Suspicious"
    assert label_for_score(70) == "High-Risk Phishing"


def test_worst_signal_wins():
    url = ComponentResult(
        name="url",
        score=85,
        rules=[FiredRule("typo", "typosquat", 40, "paypa1.com")],
    )
    text = ComponentResult(name="text", score=5, rules=[])
    result = combine(
        source_path="x.png",
        extracted_text="hello",
        ocr_confidence=80,
        urls=["http://paypa1.com/login"],
        qr_payloads=[],
        url_component=url,
        text_component=text,
    )
    assert result.threat_score >= 70
    assert result.classification == "High-Risk Phishing"


def test_no_indicators():
    result = combine(
        source_path="blank.png",
        extracted_text="",
        ocr_confidence=0,
        urls=[],
        qr_payloads=[],
        url_component=ComponentResult(name="url", score=0, rules=[]),
        text_component=ComponentResult(name="text", score=0, rules=[]),
    )
    assert result.classification == "Safe"
    assert "no_indicators" in result.reasons


def _combine_with(urls, qr_payloads, url_score):
    url = ComponentResult(
        name="url",
        score=url_score,
        rules=[FiredRule("typo", "typosquat", url_score, urls[0])],
        details={"worst_url": urls[0]},
    )
    return combine(
        source_path="x.png",
        extracted_text="some text",
        ocr_confidence=80,
        urls=urls,
        qr_payloads=qr_payloads,
        url_component=url,
        text_component=ComponentResult(name="text", score=0, rules=[]),
    )


def test_clean_qr_not_blamed_for_risky_ocr_url():
    # Risky URL came from OCR text; the QR itself points at the real brand domain.
    result = _combine_with(
        ["http://paypa1.com/login", "https://www.microsoft.com"],
        ["https://www.microsoft.com"],
        url_score=80,
    )
    qr_ids = [r.rule_id for r in result.qr_component.rules]
    assert "qr_high_risk_url" not in qr_ids
    assert result.qr_component.score < 35
    # The OCR URL still drives the overall verdict.
    assert result.classification == "High-Risk Phishing"


def test_risky_qr_url_still_flagged():
    risky = "https://secure-login.paypal.com.evil.example/verify"
    result = _combine_with([risky], [risky], url_score=80)
    qr_ids = [r.rule_id for r in result.qr_component.rules]
    assert "qr_high_risk_url" in qr_ids
    assert result.qr_component.score >= 70

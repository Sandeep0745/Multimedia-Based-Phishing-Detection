"""Text analysis tests."""

import pytest

from src.analysis.text_analysis import analyze_text


def test_urgency_and_credential():
    text = "SECURITY ALERT. Immediate action required. Update your account."
    result = analyze_text(text)
    assert result.score >= 40
    assert any(r.rule_id.startswith("text_") for r in result.rules)


def test_gift_card():
    text = "Congratulations you have won a gift card. Claim your prize now!"
    result = analyze_text(text)
    assert result.score >= 30


def test_benign_notice_low():
    text = "Class notice. Please review documentation. No action is required."
    result = analyze_text(text)
    assert result.score < 25


def test_empty_text():
    result = analyze_text("")
    assert result.score == 0


def test_awareness_camouflage_does_not_discount_a_call_request():
    plain = analyze_text("Power will be disconnected tonight. Call officer 9876543210")
    camouflaged = analyze_text("Power will be disconnected tonight. Call officer 9876543210. Beware of fraud, stay safe.")
    assert camouflaged.score >= 35
    reduction = next(r.weight for r in camouflaged.rules if r.rule_id == "awareness_context")
    callback = next(r.weight for r in camouflaged.rules if r.rule_id == "callback_number")
    # Only the scam wording is halved; the concrete "call this number" request keeps full weight.
    assert -reduction == pytest.approx((plain.score - callback) / 2)


def test_real_awareness_poster_still_halved():
    result = analyze_text("Beware: scammers say your account will be blocked. Never share your OTP. Stay safe.")
    assert result.score < 35
    assert "awareness_context" in [r.rule_id for r in result.rules]

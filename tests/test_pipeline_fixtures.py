"""End-to-end fixture evaluation (requires generated samples; OCR optional)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.config import resolve_tesseract_cmd
from src.core.pipeline import analyze_file

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"
LABELS = SAMPLES / "labels.json"


@pytest.fixture(scope="module")
def labels():
    if not LABELS.is_file():
        pytest.skip("Run: python data/samples/generate_samples.py")
    return json.loads(LABELS.read_text(encoding="utf-8"))


def _allowed(expected):
    return expected if isinstance(expected, list) else [expected]


def test_qr_only_fixture(labels):
    name = "phishing_qr_lookalike.png"
    result = analyze_file(SAMPLES / name)
    assert result.classification in _allowed(labels[name])
    assert result.threat_score >= 70


@pytest.mark.skipif(resolve_tesseract_cmd() is None, reason="Tesseract not installed (blank image is then Inconclusive)")
def test_blank_fixture(labels):
    name = "blank_no_content.png"
    result = analyze_file(SAMPLES / name)
    assert result.classification in _allowed(labels[name])
    assert "no_indicators" in result.reasons or result.threat_score == 0


def test_shortener_fixture(labels):
    name = "suspicious_shortener_qr.png"
    result = analyze_file(SAMPLES / name)
    assert result.classification in _allowed(labels[name])


@pytest.mark.skipif(resolve_tesseract_cmd() is None, reason="Tesseract not installed")
def test_ocr_phishing_alert(labels):
    name = "phishing_security_alert.png"
    result = analyze_file(SAMPLES / name)
    assert result.classification in _allowed(labels[name])


@pytest.mark.skipif(resolve_tesseract_cmd() is None, reason="Tesseract not installed")
def test_ocr_benign_notice(labels):
    name = "benign_microsoft_notice.png"
    result = analyze_file(SAMPLES / name)
    assert result.classification in _allowed(labels[name])

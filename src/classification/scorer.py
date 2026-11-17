"""Combine URL, text, and QR component scores into a final verdict."""

from __future__ import annotations

import re

from src.analysis.url_analysis import analyze_urls
from src.core.config import load_scoring, score_band
from src.core.models import AnalysisResult, ComponentResult, FiredRule
from src.extraction.urls import urls_from_qr_payloads


def label_for_score(score: float) -> str:
    """Safe / Suspicious / High-Risk Phishing for a 0-100 score (bands in scoring.json)."""
    return load_scoring()["labels"][score_band(score)]


def status_label(status: str) -> str:
    """Label for results that could not be fully analysed (never "Safe")."""
    labels = load_scoring()["labels"]
    return labels.get(status, status.title())


def _weight(rule_id: str) -> float:
    return float(load_scoring()["qr_rules"][rule_id])


# Structured QR formats that carry no link: Wi-Fi login, contact card, location, calendar.
_STRUCTURED_PREFIXES = ("wifi:", "begin:vcard", "mecard:", "geo:", "begin:vevent", "begin:vcalendar", "matmsg:")
# Schemes that run code or launch apps directly.
_DANGEROUS_SCHEMES = ("javascript:", "data:", "intent:", "file:", "vbscript:")
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]{1,20}:")
# Wording that promises money to the person scanning; a UPI QR always takes money.
_RECEIVE_MONEY_RE = re.compile(
    r"\b(receive|refund|cash ?back|prize|reward|won|win|claim|lottery|get paid|credited|bonus)\b", re.I
)



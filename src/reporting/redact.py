"""Mask personal data in reports: phone numbers, OTPs, account numbers, e-mail / UPI ids, Wi-Fi passwords."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from src.core.models import AnalysisResult, ComponentResult

# P:<password> inside a Wi-Fi QR payload ("WIFI:S:Cafe;T:WPA;P:secret;;"); "\;" escapes a semicolon.
_WIFI_PASSWORD_RE = re.compile(r"(?i)(WIFI:[^\n]*?\bP:)((?:\\;|[^;\n])*)")
# Local part of e-mail addresses and UPI ids (name@domain.com, name@ybl), and URL userinfo.
_ID_RE = re.compile(r"(?<![\w.+\-])([\w.+\-])[\w.+\-]*@(?=[\w\-])")
# Values of URL query parameters (tokens, e-mail addresses, session ids).
_QUERY_VALUE_RE = re.compile(r"([?&][^=&#\s]+=)[^&#\s]+")
# Four or more digits, allowing single spaces or dashes between groups ("+91 98765 43210", card numbers).
_LONG_NUMBER_RE = re.compile(r"\d(?:[ \-]?\d){3,}")


def _mask_number(match: re.Match) -> str:
    """Replace every digit except the last two with '*', keeping spaces and dashes."""
    value = match.group(0)
    total = sum(c.isdigit() for c in value)
    seen = 0
    out = []
    for c in value:
        if c.isdigit():
            seen += 1
            out.append(c if seen > total - 2 else "*")
        else:
            out.append(c)
    return "".join(out)


def redact_text(text: str) -> str:
    """Mask personal data in one string. Hostnames are kept so the evidence stays readable."""
    if not text:
        return text
    text = _WIFI_PASSWORD_RE.sub(lambda m: m.group(1) + "***", text)
    text = _ID_RE.sub(lambda m: m.group(1) + "***@", text)
    text = _QUERY_VALUE_RE.sub(lambda m: m.group(1) + "***", text)
    return _LONG_NUMBER_RE.sub(_mask_number, text)



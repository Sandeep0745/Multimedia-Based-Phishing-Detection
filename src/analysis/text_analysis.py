"""Text / linguistic phishing cue analysis."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from src.analysis.domains import registrable_domain
from src.core.config import brand_aliases, brand_names, load_brands, load_keywords, load_scoring
from src.core.models import ComponentResult, FiredRule

# Phrase categories scored from keywords.json, in report order.
CATEGORIES = ("urgency", "threat", "credential", "kyc_otp", "payment", "reward", "scam_offer", "impersonation")
# Categories that count as pressure / lure language for the brand-proximity rule.
LURE_CATEGORIES = {"urgency", "threat", "credential", "kyc_otp", "payment", "impersonation"}
# Concrete requests to send money or call a number. Scammers add awareness phrases ("stay safe",
# "beware of fraud") as camouflage, so these keep their full weight in awareness-style text.
ACTION_RULES = {"upi_money_request", "callback_number"}

# UPI payment address (VPA): name@bank-handle, e.g. help.pay@ybl, shop@okaxis.
_UPI_ID_RE = re.compile(
    r"\b[\w.\-]{2,}@(?:ybl|ibl|axl|okaxis|okhdfcbank|okicici|oksbi|paytm|ptyes|ptsbi|upi|apl|yapl|axisbank|"
    r"icici|sbi|hdfcbank|kotak|federal|airtel|jio|freecharge|naviaxis|waaxis|wasbi|wahdfcbank|abfspay)\b",
    re.I,
)
_MONEY_ASK_RE = re.compile(r"\b(send|pay|transfer|need|deposit)\b.{0,40}?(\brs\.?|₹|inr|\bupi\b|\d{3,})", re.I | re.S)
# Indian mobile number, optionally with +91.
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_CALL_RE = re.compile(r"\b(call|contact|whatsapp|dial|ring)\b", re.I)
# A form that asks for secrets: a secret field plus a sign-in / submit action.
_SECRET_FIELD_RE = re.compile(r"\b(password|passcode|upi pin|atm pin|mpin|cvv|card number|expiry date)\b", re.I)
_SIGN_IN_RE = re.compile(r"\b(log ?in|sign ?in|submit|verify|continue)\b", re.I)

# A phrase preceded by one of these (within a few words) is advice, not a lure: "never share your OTP".
_NEGATION_RE = re.compile(r"\b(never|not|don'?t|do not|no one|nobody|avoid|beware of)\b[\w\s,'/-]{0,25}$", re.I)
_QUOTES = "'\"‘’“”`«»"


def _weight(rule_id: str) -> float:
    return float(load_scoring()["text_rules"][rule_id])


def _phrase_re(phrase: str) -> re.Pattern:
    # Whole-word match; tolerate OCR turning spaces into line breaks.
    body = r"\s+".join(re.escape(part) for part in phrase.lower().split())
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.I)


def _word_re(word: str) -> re.Pattern:
    return re.compile(rf"(?<![\w]){re.escape(word)}(?![\w])", re.I)


@lru_cache(maxsize=1)
def _lexicon() -> tuple[tuple[str, str, re.Pattern, float], ...]:
    """(category, phrase, compiled pattern, weight) for every keywords.json entry, compiled once."""
    keywords = load_keywords()
    entries = []
    for category in CATEGORIES:
        for item in keywords.get(category, []):
            if "pattern" in item:
                phrase = item.get("label", item["pattern"])
                matcher = re.compile(item["pattern"], re.I | re.S)
            else:
                phrase = item["phrase"].lower()
                matcher = _phrase_re(phrase)
            entries.append((category, phrase, matcher, float(item["weight"])))
    return tuple(entries)


@lru_cache(maxsize=1)
def _brand_patterns() -> tuple[tuple[dict[str, Any], tuple[re.Pattern, ...]], ...]:
    """Each brand with whole-word patterns for its name and aliases ("SBI", "State Bank of India")."""
    return tuple(
        (brand, tuple(_word_re(word) for word in [brand["name"]] + brand.get("aliases", [])))
        for brand in load_brands()
    )


@lru_cache(maxsize=1)
def _brand_word_patterns() -> tuple[tuple[str, re.Pattern], ...]:
    """Every brand name and short form with its whole-word pattern, for the proximity rule."""
    return tuple((word, _word_re(word)) for word in dict.fromkeys(brand_names() + brand_aliases()))


def _is_quoted(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 2):start].strip()
    after = text[end:end + 2].strip()
    return bool(before) and bool(after) and before[-1] in _QUOTES and after[0] in _QUOTES


def _is_negated(text: str, start: int) -> bool:
    return bool(_NEGATION_RE.search(text[max(0, start - 40):start]))



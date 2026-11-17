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


def _mentioned_brands(text: str) -> list[dict[str, Any]]:
    """Brands named in the text by name or alias, as whole words ("SBI", "State Bank of India", "PayPal")."""
    return [brand for brand, patterns in _brand_patterns() if any(p.search(text) for p in patterns)]


def brand_mismatch_rule(text: str, link_hosts: list[str]) -> FiredRule | None:
    """
    The message claims to come from a brand, but none of its links or sender addresses
    belong to that brand (e.g. "PayPal" text with a link to paypa1-security.com).
    """
    if not link_hosts:
        return None
    regs = {registrable_domain(h) for h in link_hosts if h}
    hosts = {h.lower() for h in link_hosts}
    for brand in _mentioned_brands(text):
        official = {d.lower() for d in brand.get("domains", [])}
        official_regs = {registrable_domain(d) for d in official}
        if not (regs & official_regs or hosts & official):
            return FiredRule(
                "brand_link_mismatch",
                "Message names a brand but its links / sender belong to someone else",
                _weight("brand_link_mismatch"),
                evidence=f"{brand['name']} -> {', '.join(sorted(regs))[:80]}",
            )
    return None


def analyze_text(text: str, link_hosts: list[str] | None = None) -> ComponentResult:
    """
    Score extracted OCR text for phishing language patterns.

    `link_hosts` are the hostnames of URLs and e-mail addresses found in the same image,
    used to spot a brand named in the text whose links point somewhere else.
    """
    rules: list[FiredRule] = []
    if not text or not text.strip():
        return ComponentResult(
            name="text",
            score=0.0,
            rules=[],
            details={"empty": True},
        )

    lower = text.lower()
    score = 0.0
    keywords = load_keywords()
    lure_hits: list[tuple[str, int]] = []  # (phrase, position) of counted urgency/threat phrases

    def fire(rule_id: str, description: str, evidence: str) -> None:
        nonlocal score
        w = _weight(rule_id)
        score += w
        rules.append(FiredRule(rule_id, description, w, evidence=evidence))

    for category, phrase, matcher, weight in _lexicon():
        for match in matcher.finditer(text):
            if _is_quoted(text, match.start(), match.end()) or _is_negated(text, match.start()):
                continue
            score += weight
            rules.append(FiredRule(f"text_{category}", f"Phishing lexicon hit ({category})", weight, evidence=phrase))
            if category in LURE_CATEGORIES:
                lure_hits.append((phrase, match.start()))
            break  # Count each phrase once.

    # Money requested to a UPI id ("send Rs 20000 to help.pay@ybl").
    upi = _UPI_ID_RE.search(text)
    if upi and _MONEY_ASK_RE.search(text):
        fire("upi_money_request", "Asks to send money to a UPI id", upi.group(0))

    # Callback scams: pressure language plus "call this number".
    phone = _PHONE_RE.search(text)
    if phone and lure_hits and _CALL_RE.search(text):
        fire("callback_number", "Pressure message asks you to call a phone number", phone.group(0))

    # Login / card form: asks for a secret and has a sign-in or submit action.
    secret = _SECRET_FIELD_RE.search(text)
    if secret and _SIGN_IN_RE.search(text) and not _is_negated(text, secret.start()):
        fire("credential_form", "Screen asks for a password / PIN / card details", secret.group(0).lower())

    letters = [c for c in text if c.isalpha()]
    if letters:
        caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if caps_ratio >= 0.45 and len(letters) >= 20:
            fire("high_caps_ratio", "High uppercase ratio (shouting / alarm style)", f"{caps_ratio:.2f}")

    bangs = text.count("!")
    if bangs >= 3:
        fire("excessive_exclamation", "Excessive exclamation marks", str(bangs))

    # Brand name (or short form like SBI / HDFC) close to urgency or threat language.
    if lure_hits:
        for brand, brand_re in _brand_word_patterns():
            near = next(
                (
                    phrase
                    for m in brand_re.finditer(text)
                    for phrase, pos in lure_hits
                    if abs(m.start() - pos) <= 60
                ),
                None,
            )
            if near:
                fire("brand_near_urgency", "Brand name adjacent to urgency language", f"{brand} ~ {near}")
                break

    mismatch = brand_mismatch_rule(text, link_hosts or [])
    if mismatch:
        score += mismatch.weight
        rules.append(mismatch)

    # Security-awareness material quotes scam wording to teach people, so that wording counts
    # at reduced weight. Concrete money / call requests (ACTION_RULES) keep their full weight.
    markers = [m for m in keywords.get("awareness_markers", []) if m in lower]
    discountable = score - sum(r.weight for r in rules if r.rule_id in ACTION_RULES)
    if markers and discountable > 0:
        reduction = discountable * (1.0 - _weight("awareness_factor"))
        score -= reduction
        rules.append(
            FiredRule(
                "awareness_context",
                f"Reads like security-awareness advice; scam-wording score reduced by {1 - _weight('awareness_factor'):.0%}",
                -reduction,
                evidence=", ".join(markers[:3]),
            )
        )

    return ComponentResult(
        name="text",
        score=max(0.0, min(score, 100.0)),
        rules=rules,
        details={"length": len(text), "preview": text[:300]},
    )

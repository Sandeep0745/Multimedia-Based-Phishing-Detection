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


def analyze_qr_payloads(
    payloads: list[str], text: str = "", url_cache: dict[str, ComponentResult] | None = None
) -> ComponentResult:
    """
    QR-specific scoring.

    URLs carried by the QR payloads are scored on their own, so a risky URL
    found only in the OCR text is never attributed to a clean QR code.
    `text` is the OCR text around the code, used to spot "scan to receive money" UPI scams.
    `url_cache` reuses URL results already computed for the same image.
    """
    rules: list[FiredRule] = []
    score = 0.0

    if not payloads:
        return ComponentResult(name="qr", score=0.0, rules=[], details={"payloads": []})

    def fire(rule_id: str, description: str, evidence: str, weight: float | None = None) -> None:
        nonlocal score
        w = _weight(rule_id) if weight is None else weight
        score = max(score, w)
        rules.append(FiredRule(rule_id, description, w, evidence=evidence[:120]))

    for payload in payloads:
        lower = payload.strip().lower()
        if lower.startswith(("http://", "https://", "hxxp", "www.")):
            continue  # Scored by the URL engine below.
        if lower.startswith(_STRUCTURED_PREFIXES):
            fire("qr_structured_data", "QR holds Wi-Fi / contact / location / calendar data", payload)
        elif lower.startswith("upi:"):
            if _RECEIVE_MONEY_RE.search(text or ""):
                fire(
                    "qr_upi_receive_scam",
                    "UPI QR offered as a way to receive money (scanning a UPI QR always sends money)",
                    payload,
                )
            else:
                fire("qr_upi_payment", "QR starts a UPI payment", payload)
        elif lower.startswith(_DANGEROUS_SCHEMES):
            fire("qr_dangerous_scheme", "QR payload runs code or launches an app", payload)
        elif lower.startswith(("sms:", "smsto:", "tel:", "mailto:")):
            fire("qr_non_http_scheme", "QR payload uses sms/tel/mailto scheme", payload)
        elif _SCHEME_RE.match(lower):
            fire("qr_custom_scheme", "QR payload uses a custom application scheme", payload)
        elif urls_from_qr_payloads([payload]):
            continue  # A link without http:// (evil.site/login); scored by the URL engine below.
        else:
            fire("qr_opaque_payload", "QR payload is non-URL opaque data", payload)

    # Score only the URLs this QR actually decodes to.
    url_component = analyze_urls(urls_from_qr_payloads(payloads), cache=url_cache)
    worst_url = str(url_component.details.get("worst_url") or "")
    band = score_band(url_component.score)
    if band == "high_risk":
        fire("qr_high_risk_url", "QR decoded to a high-risk URL", worst_url, weight=url_component.score)
    elif band == "suspicious":
        weight = url_component.score * _weight("qr_suspicious_url_factor")
        fire("qr_suspicious_url", "QR decoded to a suspicious URL", worst_url, weight=weight)

    if payloads and score == 0.0:
        # Benign informational QR — tiny presence weight only if nothing else.
        fire("qr_present", "QR code present", f"{len(payloads)} payload(s)")

    return ComponentResult(
        name="qr",
        score=min(score, 100.0),
        rules=rules,
        details={"payloads": payloads},
    )


def combine(
    *,
    source_path: str,
    extracted_text: str,
    ocr_confidence: float | None,
    urls: list[str],
    qr_payloads: list[str],
    url_component: ComponentResult,
    text_component: ComponentResult,
    errors: list[str] | None = None,
    status: str = "ok",
    email_domains: list[str] | None = None,
    url_cache: dict[str, ComponentResult] | None = None,
    frames: int = 1,
) -> AnalysisResult:
    """
    Final score = max(weighted blend, strongest component): the worst signal wins.

    With the default weights (each set sums to 1) the blend can never exceed the
    strongest component, so the final score equals the highest component score; one
    malicious QR or link is never diluted by harmless text around it. Weights that sum
    to more than 1 would turn the blend into a bonus when several components agree.
    """
    cfg = load_scoring()
    has_qr = bool(qr_payloads)
    weights = cfg["weights_with_qr"] if has_qr else cfg["weights_without_qr"]

    qr_component = analyze_qr_payloads(qr_payloads, extracted_text, url_cache=url_cache)

    url_s = url_component.score
    text_s = text_component.score
    qr_s = qr_component.score if has_qr else 0.0

    blended = (
        weights["url"] * url_s
        + weights["text"] * text_s
        + weights["qr"] * qr_s
    )

    components = [url_s, text_s] + ([qr_s] if has_qr else [])
    max_comp = max(components) if components else 0.0
    # Worst signal wins: never let a blend dilute the strongest component.
    final = max(blended, max_comp)

    # Empty media with no signals.
    reasons: list[str] = []
    if not extracted_text.strip() and not urls and not qr_payloads and status == "ok":
        reasons.append("no_indicators")
        final = 0.0

    classification = label_for_score(final)
    if status == "error":
        classification = status_label("error")
    elif status == "inconclusive" and score_band(final) == "safe":
        # Nothing could be read, so "Safe" would be a guess. Real signals still win.
        classification = status_label("inconclusive")

    for comp in (url_component, text_component, qr_component):
        for rule in comp.rules:
            reasons.append(f"[{comp.name}] {rule.description}: {rule.evidence} ({rule.weight:+.0f})")

    if not reasons and status == "ok":
        reasons.append("no_indicators")

    return AnalysisResult(
        source_path=source_path,
        classification=classification,
        threat_score=round(float(final), 2),
        extracted_text=extracted_text,
        ocr_confidence=ocr_confidence,
        urls=urls,
        qr_payloads=qr_payloads,
        email_domains=email_domains or [],
        url_component=url_component,
        text_component=text_component,
        qr_component=qr_component,
        reasons=reasons,
        errors=errors or [],
        status=status,
        frames=frames,
    )

"""End-to-end analysis pipeline for one multimedia file."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import numpy as np

from src.analysis.text_analysis import analyze_text
from src.analysis.url_analysis import analyze_urls
from src.classification.scorer import combine, status_label
from src.core.models import AnalysisResult, ComponentResult
from src.extraction.ocr import extract_text
from src.extraction.preprocess import SUPPORTED_EXTENSIONS, load_frames, preprocess, read_image_info
from src.extraction.qr import decode_qr
from src.extraction.urls import extract_email_domains, extract_urls, safe_urlparse, url_key, urls_from_qr_payloads
from src.model.classifier import model_warning

# Refuse absurdly large images (decompression bombs) before heavy processing.
MAX_PIXELS = 50_000_000
# Refuse larger files before reading them into memory.
MAX_FILE_BYTES = 200 * 1024 * 1024
# Below this mean Tesseract confidence, the report warns that text may be misread.
LOW_OCR_CONFIDENCE = 60.0


def error_result(source: str, message: str) -> AnalysisResult:
    """A file that could not be analysed is reported as an error, never as Safe."""
    return AnalysisResult(
        source_path=source,
        classification=status_label("error"),
        threat_score=0.0,
        status="error",
        errors=[message],
        reasons=["error"],
    )


def _analyze_frames(frames: list[np.ndarray], source: str) -> AnalysisResult:
    """Extract text and QR codes from every frame, then analyse them together as one message."""
    errors: list[str] = []
    texts: list[str] = []
    confidences: list[float] = []
    payloads: list[str] = []
    ocr_complete = True
    qr_undecoded = False
    many = len(frames) > 1

    for number, bgr in enumerate(frames, 1):
        prefix = f"Frame {number}: " if many else ""
        bundle = preprocess(bgr)

        ocr = extract_text(bundle)
        if ocr.error:
            errors.append(prefix + ocr.error)
        elif ocr.text.strip() and ocr.mean_confidence < LOW_OCR_CONFIDENCE:
            errors.append(
                f"{prefix}Low OCR confidence ({ocr.mean_confidence:.0f}); text may be misread, check the extracted text"
            )
        if not ocr.available:
            ocr_complete = False
        elif not many or ocr.text.strip():
            texts.append(ocr.text)
            confidences.append(ocr.mean_confidence)

        qr = decode_qr(bundle)
        errors.extend(prefix + e for e in qr.errors)
        payloads.extend(p for p in qr.payloads if p not in payloads)
        qr_undecoded = qr_undecoded or qr.undecoded

    # A blank line between frames keeps the URL re-joining from gluing text across frames.
    text = "\n\n".join(texts)
    ocr_confidence = (sum(confidences) / len(confidences) if confidences else 0.0) if ocr_complete or texts else None

    # Merge text and QR URLs, unique by host + path (http/https copies count once).
    all_urls: list[str] = []
    seen: set[str] = set()
    for u in extract_urls(text) + urls_from_qr_payloads(payloads):
        key = url_key(u)
        if key not in seen:
            seen.add(key)
            all_urls.append(u)

    link_hosts: list[str] = []
    for u in all_urls:
        parsed = safe_urlparse(u if "://" in u else "http://" + u)
        if parsed and parsed.hostname:
            link_hosts.append(parsed.hostname.lower())

    # Sender / contact e-mail domains are judged like links (service@paypa1-security.com).
    email_domains = [d for d in extract_email_domains(text + "\n" + "\n".join(payloads)) if d not in link_hosts]
    # URL and QR scoring share one result per URL, so each URL (and its ML check) runs once.
    url_cache: dict[str, ComponentResult] = {}
    url_component = analyze_urls(all_urls + [f"http://{d}/" for d in email_domains], cache=url_cache)
    text_component = analyze_text(text, link_hosts=link_hosts + email_domains)
    ml_problem = model_warning()
    if ml_problem:
        errors.append(ml_problem)

    status = "ok"
    if not ocr_complete:
        # Text could not be read, so a "Safe" verdict would rest on part of the image only.
        status = "inconclusive"
        if not payloads and not text.strip():
            errors.append("No text or QR content recovered")
        else:
            errors.append("Text in the image could not be read (OCR unavailable), so it was only partly checked")
    elif qr_undecoded and not payloads:
        # A QR code is visibly there but its link is unknown, so the image is not fully checked.
        status = "inconclusive"

    return combine(
        source_path=source,
        extracted_text=text,
        ocr_confidence=ocr_confidence,
        urls=all_urls,
        qr_payloads=payloads,
        url_component=url_component,
        text_component=text_component,
        errors=errors,
        status=status,
        email_domains=email_domains,
        url_cache=url_cache,
        frames=len(frames),
    )



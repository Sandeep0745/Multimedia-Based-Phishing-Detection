"""Text, JSON and batch-summary (CSV / JSONL) report generation."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from src.core.models import AnalysisResult
from src.reporting.redact import redact_result

SUMMARY_FIELDS = ("source_path", "status", "classification", "threat_score", "urls", "qr_payloads", "top_reasons", "errors")
# A spreadsheet treats a cell starting with one of these as a formula; QR payloads and
# URLs are attacker-controlled, so such cells are written with a leading apostrophe.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def format_text_report(result: AnalysisResult, redact: bool = False) -> str:
    if redact:
        result = redact_result(result)
    lines = [
        "=" * 64,
        "Multimedia-Based Phishing Detection - Report",
        "=" * 64,
        f"Source:          {result.source_path}",
        f"Status:          {result.status}",
        f"Classification:  {result.classification}",
        f"Threat score:    {result.threat_score} / 100",
    ]
    if result.frames > 1:
        lines.append(f"Frames analysed: {result.frames}")
    if result.ocr_confidence is not None:
        lines.append(f"OCR confidence:  {result.ocr_confidence:.1f}")
    lines.append("")
    lines.append("Extracted URLs:")
    if result.urls:
        for u in result.urls:
            lines.append(f"  - {u}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("QR payloads:")
    if result.qr_payloads:
        for p in result.qr_payloads:
            lines.append(f"  - {p}")
    else:
        lines.append("  (none)")
    lines.append("")
    if result.email_domains:
        lines.append("E-mail sender / contact domains:")
        for d in result.email_domains:
            lines.append(f"  - {d}")
        lines.append("")
    lines.append("Extracted text (preview):")
    preview = (result.extracted_text or "").strip()
    if preview:
        lines.append(preview[:800] + ("..." if len(preview) > 800 else ""))
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Component scores:")
    for comp in (result.url_component, result.text_component, result.qr_component):
        if comp is None:
            continue
        lines.append(f"  - {comp.name}: {comp.score:.1f}")
    lines.append("")
    lines.append("Reasons:")
    for reason in result.reasons:
        lines.append(f"  * {reason}")
    if result.errors:
        lines.append("")
        lines.append("Errors / warnings:")
        for err in result.errors:
            lines.append(f"  ! {err}")
    lines.append("=" * 64)
    return "\n".join(lines)



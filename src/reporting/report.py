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


def write_report(result: AnalysisResult, output: Path | None, as_json: bool, redact: bool = False) -> str:
    """Return report body and optionally write to disk. `redact` masks personal data."""
    if redact:
        result = redact_result(result)
    if as_json:
        body = json.dumps(result.to_dict(), indent=2)
    else:
        body = format_text_report(result)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body, encoding="utf-8")
    return body


def _cell(value: object) -> str:
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def write_summary(results: list[AnalysisResult], path: Path, redact: bool = False) -> None:
    """
    One line per analysed file: a .jsonl path gets one JSON object per line, any other
    path (normally .csv) a spreadsheet with the columns in SUMMARY_FIELDS.
    """
    rows = [redact_result(r) if redact else r for r in results]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".jsonl":
        with path.open("w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
        return
    # utf-8-sig: Excel then shows non-ASCII text (homoglyph links, Rs symbol) correctly.
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(SUMMARY_FIELDS)
        for r in rows:
            writer.writerow(
                _cell(v)
                for v in (
                    r.source_path,
                    r.status,
                    r.classification,
                    r.threat_score,
                    " ".join(r.urls),
                    " | ".join(r.qr_payloads),
                    " | ".join(r.reasons[:3]),
                    " | ".join(r.errors),
                )
            )

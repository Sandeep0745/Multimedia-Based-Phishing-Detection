"""Tesseract OCR wrapper with multi-variant selection."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pytesseract

from src.core.config import resolve_tesseract_cmd
from src.extraction.preprocess import PreprocessBundle, rotation_candidates, variants_for_ocr
from src.extraction.urls import extract_urls


# Upper limit for one Tesseract run; a stuck process is killed and that variant skipped.
OCR_TIMEOUT_SECONDS = 60


@dataclass
class OCRResult:
    text: str
    mean_confidence: float
    variant: str
    available: bool
    error: str | None = None


def configure_tesseract() -> str | None:
    """Point pytesseract at the installed binary. Returns path or None."""
    cmd = resolve_tesseract_cmd()
    if cmd:
        pytesseract.pytesseract.tesseract_cmd = cmd
    return cmd


def _run_ocr(image: np.ndarray) -> tuple[str, float]:
    """
    One Tesseract run: the recognised text and the mean word confidence.

    The text is rebuilt from the word table with Tesseract's own layout (words joined by
    spaces, lines by newlines, a blank line between paragraphs), which the URL re-joining
    relies on. This matches image_to_string exactly while running Tesseract once, not twice.
    """
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT, timeout=OCR_TIMEOUT_SECONDS)
    paragraphs: list[list[list[str]]] = []
    confs: list[float] = []
    current_par: tuple[int, int] | None = None
    current_line: tuple[int, int, int] | None = None
    for i, text in enumerate(data.get("text", [])):
        try:
            c = float(data["conf"][i])
        except (TypeError, ValueError, KeyError, IndexError):
            continue
        if c < 0:
            continue
        token = (text or "").strip()
        if not token:
            continue
        par = (int(data["block_num"][i]), int(data["par_num"][i]))
        line = (*par, int(data["line_num"][i]))
        if par != current_par:
            paragraphs.append([])
            current_par, current_line = par, None
        if line != current_line:
            paragraphs[-1].append([])
            current_line = line
        paragraphs[-1][-1].append(token)
        confs.append(c)
    joined = "\n\n".join("\n".join(" ".join(words) for words in par) for par in paragraphs)
    mean_conf = float(sum(confs) / len(confs)) if confs else 0.0
    return joined, mean_conf



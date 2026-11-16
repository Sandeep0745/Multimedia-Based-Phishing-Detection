"""Shared dataclasses for pipeline results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FiredRule:
    """A single detection rule that contributed to a score."""

    rule_id: str
    description: str
    weight: float
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentResult:
    """Score and reasons from one analysis component."""

    name: str
    score: float
    rules: list[FiredRule] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "rules": [r.to_dict() for r in self.rules],
            "details": self.details,
        }


@dataclass
class AnalysisResult:
    """Full pipeline output for one multimedia input."""

    source_path: str
    classification: str
    threat_score: float
    extracted_text: str = ""
    ocr_confidence: float | None = None
    urls: list[str] = field(default_factory=list)
    qr_payloads: list[str] = field(default_factory=list)
    email_domains: list[str] = field(default_factory=list)
    url_component: ComponentResult | None = None
    text_component: ComponentResult | None = None
    qr_component: ComponentResult | None = None
    reasons: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    status: str = "ok"  # ok | error | inconclusive
    frames: int = 1  # frames analysed (animated GIF / WebP, multi-page TIFF)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "status": self.status,
            "classification": self.classification,
            "threat_score": self.threat_score,
            "frames": self.frames,
            "extracted_text": self.extracted_text,
            "ocr_confidence": self.ocr_confidence,
            "urls": self.urls,
            "qr_payloads": self.qr_payloads,
            "email_domains": self.email_domains,
            "url_component": self.url_component.to_dict() if self.url_component else None,
            "text_component": self.text_component.to_dict() if self.text_component else None,
            "qr_component": self.qr_component.to_dict() if self.qr_component else None,
            "reasons": self.reasons,
            "errors": self.errors,
        }

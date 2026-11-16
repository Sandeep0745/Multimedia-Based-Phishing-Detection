"""QR code detection and decoding (OpenCV, optional pyzbar)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import cv2
import numpy as np

from src.extraction.preprocess import PreprocessBundle


@dataclass
class QRResult:
    payloads: list[str] = field(default_factory=list)
    engine: str = "opencv"
    errors: list[str] = field(default_factory=list)
    # A QR code was located but none could be decoded (damaged, covered, too blurry).
    undecoded: bool = False


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        cleaned = (item or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def _decode_opencv(image: np.ndarray, detector: Any = None) -> list[str]:
    detector = detector if detector is not None else cv2.QRCodeDetector()
    payloads: list[str] = []
    # Multi-code API (OpenCV 4.x)
    try:
        ok, infos, _points, _ = detector.detectAndDecodeMulti(image)
        if ok and infos:
            payloads.extend([i for i in infos if i])
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        pass
    # Single-code fallback
    try:
        data, _points, _ = detector.detectAndDecode(image)
        if data:
            payloads.append(data)
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        pass
    return payloads


def _decode_pyzbar(image: np.ndarray) -> list[str]:
    try:
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        return []
    payloads: list[str] = []
    try:
        # pyzbar expects RGB or grayscale
        if len(image.shape) == 3:
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        else:
            rgb = image
        for obj in zbar_decode(rgb):
            try:
                payloads.append(obj.data.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
                continue
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        return []
    return payloads


def decode_qr(bundle: PreprocessBundle) -> QRResult:
    """
    Detect and decode QR payloads from original and processed variants.
    OpenCV is primary; pyzbar merges extras when the DLL is available.
    """
    images: list[np.ndarray] = [bundle.original_bgr, bundle.upscaled_gray, bundle.thresholded]
    if bundle.deskewed is not None:
        images.append(bundle.deskewed)
    if bundle.warped is not None:
        images.append(bundle.warped)

    payloads: list[str] = []
    engines: list[str] = ["opencv"]
    errors: list[str] = []

    for img in images:
        payloads.extend(_decode_opencv(img))
    if not payloads:
        # The ArUco-based detector reads some clean codes the classic one misses (seen with
        # "javascript:..." payloads), so results no longer depend on pyzbar being installed.
        aruco = _aruco_detector()
        if aruco is not None:
            for img in images[:2]:
                payloads.extend(_decode_opencv(img, aruco))
            if payloads:
                engines.append("opencv-aruco")

    pyz = _decode_pyzbar(bundle.original_bgr)
    if pyz:
        payloads.extend(pyz)
        engines.append("pyzbar")

    payloads = _unique(payloads)
    undecoded = not payloads and any(_qr_located(img) for img in images[:2])
    if undecoded:
        errors.append("A QR code was detected but could not be decoded (damaged, covered or blurred)")
    return QRResult(payloads=payloads, engine="+".join(engines), errors=errors, undecoded=undecoded)


def _aruco_detector() -> Any:
    """cv2.QRCodeDetectorAruco (OpenCV 4.8+), or None on older OpenCV builds."""
    factory = getattr(cv2, "QRCodeDetectorAruco", None)
    if factory is None:
        return None
    try:
        return factory()
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        return None


def _qr_located(image: np.ndarray) -> bool:
    """
    True when OpenCV finds a plausible QR outline (square-ish, not tiny) without decoding it.

    Uses the ArUco-based detector: the classic QRCodeDetector.detect() reports
    "QR codes" in rotated or low-resolution text, which would make clean screenshots inconclusive.
    """
    try:
        ok, points = cv2.QRCodeDetectorAruco().detect(image)
    except Exception:  # noqa: BLE001 — OpenCV / pyzbar errors must not stop the scan
        return False
    if not ok or points is None:
        return False
    quad = np.asarray(points, dtype=np.float32).reshape(-1, 2)
    if len(quad) != 4:
        return False
    area = cv2.contourArea(quad)
    sides = [np.linalg.norm(quad[i] - quad[(i + 1) % 4]) for i in range(4)]
    h, w = image.shape[:2]
    return bool(area >= 0.002 * h * w and min(sides) > 0 and max(sides) / min(sides) < 2.0)

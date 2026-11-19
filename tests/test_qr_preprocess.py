"""QR decoding and preprocessing smoke tests."""

from pathlib import Path

import numpy as np
import pytest

from src.extraction.preprocess import preprocess
from src.extraction.qr import decode_qr


def test_preprocess_shapes():
    img = np.full((200, 300, 3), 200, dtype=np.uint8)
    bundle = preprocess(img)
    assert bundle.upscaled_gray.ndim == 2
    assert bundle.thresholded.ndim == 2


def test_qr_decode_from_fixture():
    sample = Path(__file__).resolve().parents[1] / "data" / "samples" / "phishing_qr_lookalike.png"
    if not sample.is_file():
        pytest.skip("Sample fixtures not generated yet")
    import cv2

    bgr = cv2.imread(str(sample))
    assert bgr is not None
    bundle = preprocess(bgr)
    result = decode_qr(bundle)
    assert result.payloads
    assert any("paypal.com.evil.example" in p for p in result.payloads)

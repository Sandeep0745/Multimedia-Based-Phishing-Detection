"""
Generate labeled local detection fixtures (benign + phishing-style images).

These images stay on disk for self-tests. They are not meant to be sent to anyone.

Usage:
  python data/samples/generate_samples.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
import qrcode

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _font(size: int = 20):
    for name in (
        "arial.ttf",
        "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _draw_multiline(draw: ImageDraw.ImageDraw, lines: list[str], xy: tuple[int, int], fill, font) -> None:
    x, y = xy
    for line in lines:
        draw.text((x, y), line, fill=fill, font=font)
        y += getattr(font, "size", 16) + 8


def _qr_image(payload: str, box_size: int = 4) -> Image.Image:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box_size, border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")


def make_benign_notice() -> Path:
    img = Image.new("RGB", (900, 360), color=(245, 248, 252))
    draw = ImageDraw.Draw(img)
    font = _font(22)
    _draw_multiline(
        draw,
        [
            "Class notice — Office hours reminder",
            "Please review documentation at:",
            "https://www.microsoft.com",
            "No action is required on your account.",
        ],
        (40, 60),
        fill=(20, 20, 20),
        font=font,
    )
    # Benign QR to the same legitimate domain (should stay Safe).
    qr = _qr_image("https://www.microsoft.com", box_size=3)
    img.paste(qr, (700, 200))
    path = OUT / "benign_microsoft_notice.png"
    img.save(path)
    return path


def make_security_alert_screenshot() -> Path:
    img = Image.new("RGB", (900, 420), color=(255, 250, 240))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 900, 70], fill=(180, 30, 30))
    title_font = _font(28)
    body = _font(22)
    draw.text((30, 18), "SECURITY ALERT", fill=(255, 255, 255), font=title_font)
    _draw_multiline(
        draw,
        [
            "Immediate action required.",
            "Update your account to avoid suspension.",
            "Verify here: http://paypa1.com/login",
        ],
        (40, 100),
        fill=(30, 30, 30),
        font=body,
    )
    # QR backup so evaluation works even without Tesseract OCR.
    qr = _qr_image("http://paypa1.com/login", box_size=4)
    img.paste(qr, (680, 200))
    path = OUT / "phishing_security_alert.png"
    img.save(path)
    return path


def make_gift_card_ad() -> Path:
    img = Image.new("RGB", (900, 400), color=(255, 245, 230))
    draw = ImageDraw.Draw(img)
    font = _font(24)
    _draw_multiline(
        draw,
        [
            "Congratulations! Claim your prize",
            "You have won a $500 gift card",
            "Limited time offer — claim now:",
            "https://amaz0n-prize.tk/claim",
        ],
        (40, 70),
        fill=(40, 20, 0),
        font=font,
    )
    qr = _qr_image("https://amaz0n-prize.tk/claim", box_size=4)
    img.paste(qr, (680, 180))
    path = OUT / "phishing_gift_card_ad.png"
    img.save(path)
    return path


def make_qr_only_lookalike() -> Path:
    payload = "https://secure-login.paypal.com.evil.example/verify"
    qr_img = _qr_image(payload, box_size=8)
    canvas = Image.new("RGB", (500, 520), color=(255, 255, 255))
    canvas.paste(qr_img, (50, 40))
    path = OUT / "phishing_qr_lookalike.png"
    canvas.save(path)
    return path


def make_shortener_qr() -> Path:
    payload = "https://bit.ly/3demoCheck"
    qr_img = _qr_image(payload, box_size=8)
    canvas = Image.new("RGB", (480, 500), color=(250, 250, 250))
    canvas.paste(qr_img, (40, 30))
    draw = ImageDraw.Draw(canvas)
    draw.text((40, 440), "Scan for details", fill=(80, 80, 80), font=_font(18))
    path = OUT / "suspicious_shortener_qr.png"
    canvas.save(path)
    return path


def make_blank() -> Path:
    img = Image.new("RGB", (400, 300), color=(240, 240, 240))
    path = OUT / "blank_no_content.png"
    img.save(path)
    return path


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    make_benign_notice()
    make_security_alert_screenshot()
    make_gift_card_ad()
    make_qr_only_lookalike()
    make_shortener_qr()
    make_blank()
    labels = {
        "benign_microsoft_notice.png": "Safe",
        "phishing_security_alert.png": "High-Risk Phishing",
        "phishing_gift_card_ad.png": "High-Risk Phishing",
        "phishing_qr_lookalike.png": "High-Risk Phishing",
        "suspicious_shortener_qr.png": ["Suspicious", "High-Risk Phishing"],
        "blank_no_content.png": "Safe",
    }
    (OUT / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    print(f"Wrote {len(labels)} fixtures to {OUT}")
    for name, label in labels.items():
        print(f"  {name} -> {label}")


if __name__ == "__main__":
    main()

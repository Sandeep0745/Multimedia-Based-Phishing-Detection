"""
Red Team generator: fake SMS / WhatsApp / e-mail screenshots, fake login pages,
advertisements, QR posters and social posts, plus evasion variants.

Usage:
  python make_test_images.py                 # -> data/test_images/ (+ labels.json)
  python make_test_images.py --out somewhere

Blue Team then runs:
  python -m src.cli batch data/test_images
  python -m src.cli evaluate data/test_images

LAB USE ONLY. Every link uses a look-alike or made-up domain that is not
contacted; nothing here is meant to be sent to real people.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import cv2
import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFont

PHISH = ["Suspicious", "High-Risk Phishing"]
SAFE = "Safe"
ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = ROOT / "data" / "test_images"

_FONT_DIRS = ["C:/Windows/Fonts", "/usr/share/fonts/truetype/dejavu", "/Library/Fonts"]
_FONT_FILES = {"regular": ["arial.ttf", "DejaVuSans.ttf", "Arial.ttf"], "bold": ["arialbd.ttf", "DejaVuSans-Bold.ttf", "Arial Bold.ttf"]}


def font(size: int, weight: str = "regular") -> ImageFont.ImageFont:
    for folder in _FONT_DIRS:
        for name in _FONT_FILES[weight]:
            path = Path(folder) / name
            if path.is_file():
                return ImageFont.truetype(str(path), size)
    return ImageFont.load_default()


def wrap(draw: ImageDraw.ImageDraw, text: str, fnt, width: int) -> list[str]:
    lines: list[str] = []
    for para in text.split("\n"):
        line = ""
        for word in para.split(" "):
            trial = f"{line} {word}".strip()
            if draw.textlength(trial, font=fnt) <= width:
                line = trial
            else:
                lines.append(line)
                line = word
        lines.append(line)
    return lines


def qr_image(payload: str, box: int = 6) -> Image.Image:
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=2)
    q.add_data(payload)
    q.make(fit=True)
    return q.make_image(fill_color="black", back_color="white").convert("RGB")


# ---------------------------------------------------------------- layouts

def sms_screen(sender: str, messages: list[str], dark: bool = False) -> Image.Image:
    bg, fg, bubble = ((18, 18, 18), (235, 235, 235), (48, 48, 52)) if dark else ((255, 255, 255), (20, 20, 20), (233, 233, 238))
    img = Image.new("RGB", (720, 1000), bg)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 720, 110], fill=(30, 30, 34) if dark else (245, 245, 247))
    d.text((40, 38), sender, fill=fg, font=font(32, "bold"))
    y = 150
    for msg in messages:
        lines = wrap(d, msg, font(28), 560)
        h = len(lines) * 38 + 30
        d.rounded_rectangle([30, y, 640, y + h], radius=22, fill=bubble)
        for i, line in enumerate(lines):
            d.text((55, y + 15 + i * 38), line, fill=fg, font=font(28))
        y += h + 30
    return img


def chat_screen(contact: str, messages: list[str]) -> Image.Image:
    img = Image.new("RGB", (720, 1000), (236, 229, 221))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 720, 110], fill=(7, 94, 84))
    d.text((40, 38), contact, fill="white", font=font(32, "bold"))
    y = 150
    for msg in messages:
        lines = wrap(d, msg, font(28), 560)
        h = len(lines) * 38 + 30
        d.rounded_rectangle([30, y, 640, y + h], radius=16, fill="white")
        for i, line in enumerate(lines):
            d.text((55, y + 15 + i * 38), line, fill=(20, 20, 20), font=font(28))
        y += h + 30
    return img


def email_screen(sender: str, subject: str, body: str, button: str | None = None) -> Image.Image:
    img = Image.new("RGB", (1100, 760), "white")
    d = ImageDraw.Draw(img)
    d.text((50, 40), subject, fill=(20, 20, 20), font=font(34, "bold"))
    d.text((50, 100), f"From: {sender}", fill=(70, 70, 70), font=font(26))
    d.text((50, 140), "To: me", fill=(70, 70, 70), font=font(26))
    d.line([50, 190, 1050, 190], fill=(210, 210, 210), width=2)
    y = 220
    for line in wrap(d, body, font(28), 1000):
        d.text((50, y), line, fill=(30, 30, 30), font=font(28))
        y += 42
    if button:
        d.rounded_rectangle([50, y + 30, 50 + 40 + int(d.textlength(button, font=font(28, "bold"))), y + 95], radius=8, fill=(0, 103, 184))
        d.text((70, y + 47), button, fill="white", font=font(28, "bold"))
    return img


def login_screen(address: str, brand: str, fields: list[str], button: str) -> Image.Image:
    img = Image.new("RGB", (1100, 820), (246, 247, 249))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 1100, 80], fill=(222, 225, 230))
    d.rounded_rectangle([40, 18, 1060, 62], radius=20, fill="white")
    d.text((70, 26), address, fill=(40, 40, 40), font=font(26))
    d.text((380, 150), brand, fill=(0, 48, 135), font=font(48, "bold"))
    y = 260
    for field in fields:
        d.text((300, y), field, fill=(60, 60, 60), font=font(26))
        d.rounded_rectangle([300, y + 38, 800, y + 98], radius=6, outline=(160, 160, 160), width=2, fill="white")
        y += 140
    d.rounded_rectangle([300, y + 10, 800, y + 80], radius=30, fill=(0, 112, 186))
    d.text((520 - int(d.textlength(button, font=font(30, "bold")) / 2) + 30, y + 27), button, fill="white", font=font(30, "bold"))
    return img


def ad_banner(headline: str, lines: list[str], bg=(255, 214, 0), fg=(20, 20, 20)) -> Image.Image:
    img = Image.new("RGB", (1200, 628), bg)
    d = ImageDraw.Draw(img)
    y = 60
    for line in wrap(d, headline, font(52, "bold"), 1100):
        d.text((50, y), line, fill=fg, font=font(52, "bold"))
        y += 66
    y += 20
    for line in lines:
        for wl in wrap(d, line, font(34), 1100):
            d.text((50, y), wl, fill=fg, font=font(34))
            y += 48
    return img


def qr_poster(title: str, lines: list[str], payload: str) -> Image.Image:
    q = qr_image(payload, box=7)
    img = Image.new("RGB", (900, 560 + q.height), "white")
    d = ImageDraw.Draw(img)
    d.text((50, 40), title, fill=(20, 20, 20), font=font(44, "bold"))
    y = 120
    for line in lines:
        d.text((50, y), line, fill=(40, 40, 40), font=font(30))
        y += 46
    img.paste(q, ((900 - q.width) // 2, y + 30))
    return img


def social_post(account: str, text: str) -> Image.Image:
    img = Image.new("RGB", (900, 700), "white")
    d = ImageDraw.Draw(img)
    d.ellipse([40, 40, 110, 110], fill=(193, 53, 132))
    d.text((130, 55), account, fill=(20, 20, 20), font=font(30, "bold"))
    y = 150
    for line in wrap(d, text, font(30), 820):
        d.text((40, y), line, fill=(20, 20, 20), font=font(30))
        y += 44
    return img


# ---------------------------------------------------------------- evasion transforms

def rotated(img: Image.Image, angle: float) -> Image.Image:
    return img.rotate(angle, expand=True, fillcolor=img.getpixel((5, 5)))


def low_res(img: Image.Image, scale: float = 0.45) -> Image.Image:
    return img.resize((int(img.width * scale), int(img.height * scale)), Image.LANCZOS)


def phone_photo(img: Image.Image) -> Image.Image:
    """Screen photographed at an angle: perspective, blur, sensor noise, JPEG-like softness."""
    src = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    h, w = src.shape[:2]
    canvas_w, canvas_h = int(w * 1.3), int(h * 1.3)
    bg = np.random.default_rng(7).integers(70, 120, (canvas_h, canvas_w, 3)).astype(np.uint8)
    bg = cv2.GaussianBlur(bg, (15, 15), 0)
    dst = np.float32([[w * 0.12, h * 0.08], [w * 1.18, h * 0.14], [w * 1.14, h * 1.2], [w * 0.16, h * 1.16]])
    m = cv2.getPerspectiveTransform(np.float32([[0, 0], [w, 0], [w, h], [0, h]]), dst)
    warped = cv2.warpPerspective(src, m, (canvas_w, canvas_h))
    mask = cv2.warpPerspective(np.full((h, w), 255, np.uint8), m, (canvas_w, canvas_h))
    bg[mask > 0] = warped[mask > 0]
    noisy = cv2.GaussianBlur(bg, (3, 3), 0).astype(np.int16) + np.random.default_rng(8).normal(0, 8, bg.shape).astype(np.int16)
    return Image.fromarray(cv2.cvtColor(np.clip(noisy, 0, 255).astype(np.uint8), cv2.COLOR_BGR2RGB))


# ---------------------------------------------------------------- attack set

def build() -> list[tuple[str, Image.Image, object, str]]:
    """(file name, image, expected label, technique) for every sample."""
    s: list[tuple[str, Image.Image, object, str]] = []

    # SMS scams
    sms_kyc = sms_screen("VK-SBIINB", ["Dear SBI user, your YONO account will be blocked today. Update your PAN/KYC immediately: sbi-kyc-update.in/verify"])
    s.append(("sms_sbi_kyc.png", sms_kyc, PHISH, "KYC scam SMS, bank short name, link without http://"))
    s.append(("sms_electricity_callback.png", sms_screen("AD-EBILL", ["Dear consumer, your electricity power will be disconnected tonight at 9:30 pm because your previous month bill was not updated. Please call electricity officer 9876543210 immediately."]), PHISH, "Callback scam: threat + phone number, no link"))
    s.append(("sms_parcel_held.png", sms_screen("IndiaPost", ["IndiaPost: Your parcel is held at our warehouse due to incomplete address. Update within 12 hours or it will be returned: indiapost-redelivery.top/track"]), PHISH, "Delivery scam, high-abuse TLD"))
    sms_tax = sms_screen("IT-DEPT", ["Income Tax Department: A refund of Rs 15,490 has been approved for you. Submit your bank details to receive it: incometax-refund.gov.in.claim-now.com"])
    s.append(("sms_tax_refund.png", sms_tax, PHISH, "Tax refund scam, gov.in domain chain"))
    s.append(("sms_otp_request.png", sms_screen("AX-AMZSUP", ["Your Amazon order #402-118 is on hold. To cancel the unauthorised order, share the OTP sent to your mobile with our executive when they call."]), PHISH, "OTP-sharing scam, no link"))
    s.append(("legit_sms_otp.png", sms_screen("AD-HDFCBK", ["482913 is your OTP for login to HDFC Bank NetBanking. Do not share it with anyone. Bank never asks for OTP. -HDFC Bank"]), SAFE, "Genuine OTP message (false-alarm test)"))
    s.append(("legit_sms_delivery.png", sms_screen("AX-AMAZON", ["Your Amazon order has been delivered. Track or return it at https://www.amazon.in/gp/your-account/order-history"]), SAFE, "Genuine delivery message"))

    # WhatsApp chats
    s.append(("whatsapp_job_scam.png", chat_screen("+91 98XXX XXX21", ["Hello! Part time job offer from home.", "Earn Rs 5000 daily just by liking YouTube videos. Daily payment guaranteed.", "Contact our HR on Telegram to start: t.me/earn_daily_hr"]), PHISH, "Task / job scam on WhatsApp"))
    s.append(("whatsapp_investment.png", chat_screen("VIP Stock Tips", ["Join our VIP trading group.", "Guaranteed 300% returns in 7 days with our expert tips!", "Register now: stockvip-profits.online/join"]), PHISH, "Investment scam, guaranteed returns"))
    s.append(("whatsapp_family_emergency.png", chat_screen("+91 70XXX XXX88", ["Hi Mom, this is my new number, my phone broke.", "I need Rs 20000 urgently for a hospital bill. Please send it to this UPI id: help.pay2026@ybl and don't tell dad."]), PHISH, "'Hi Mum' impersonation, UPI id"))
    s.append(("legit_whatsapp_class.png", chat_screen("CS Batch 2026", ["Class is shifted to Room 204 tomorrow at 10 AM.", "Slides are uploaded here: https://github.com/opencv/opencv"]), SAFE, "Genuine group message"))

    # E-mails
    email_pp = email_screen("PayPal Security <service@paypa1-security.com>", "Your account has been limited",
                            "Dear customer, we noticed unusual activity on your PayPal account. Your account access has been limited. Click here to verify your account within 24 hours: https://paypa1-security.com/verify", "Verify account")
    s.append(("email_paypal_limited.png", email_pp, PHISH, "Spoofed sender + typosquat link"))
    s.append(("email_mailbox_full.png", email_screen("Microsoft 365 <no-reply@m365-mailbox-alerts.com>", "Mailbox storage full",
                                                    "Your mailbox storage is full. New messages will be deleted. Sign in to keep your mail and increase your storage.", "Keep my mail"), PHISH, "Sender-domain only, no visible link"))
    s.append(("legit_email_course.png", email_screen("Coursera <no-reply@coursera.org>", "Your weekly learning summary",
                                                     "Great job this week! You completed 3 lessons in Python for Everybody. Continue learning at https://www.coursera.org/learn/python"), SAFE, "Genuine newsletter"))

    # Fake login pages
    login_pp = login_screen("paypa1-login.com/signin", "PayPal", ["Email or mobile number", "Password"], "Log In")
    s.append(("login_fake_paypal.png", login_pp, PHISH, "Fake login page, typosquat address bar"))
    s.append(("login_fake_sbi.png", login_screen("onlinesbi-secure.co/login", "State Bank of India", ["Username", "Password"], "Login"), PHISH, "Fake bank login, brand in deceptive domain"))
    s.append(("legit_login_sbi.png", login_screen("https://www.onlinesbi.sbi/", "State Bank of India", ["Username", "Password"], "Login"), SAFE, "Genuine bank login page"))

    # Advertisements
    s.append(("ad_iphone_giveaway.png", ad_banner("CONGRATULATIONS! You have won an iPhone 16 Pro", ["Pay only Rs 99 shipping charge.", "Claim your prize now: apple-giveaway-india.shop"]), PHISH, "Prize scam ad"))
    s.append(("ad_instant_loan.png", ad_banner("Instant personal loan in 5 minutes!", ["No CIBIL check. 0% interest. No documents needed.", "Apply now: quickloan-approve.xyz"], bg=(0, 153, 102), fg=(255, 255, 255)), PHISH, "Loan app scam ad"))
    s.append(("ad_crypto_doubler.png", ad_banner("Bitcoin Giveaway - Double your crypto!", ["Send 0.1 BTC and get 0.2 BTC back instantly.", "Limited time offer: tesla-btc-x2.com"], bg=(20, 20, 40), fg=(255, 215, 0)), PHISH, "Crypto doubling scam ad"))
    s.append(("legit_ad_sale.png", ad_banner("Big Billion Days Sale", ["Up to 70% off on electronics and fashion.", "Shop on the Flipkart app or at www.flipkart.com"], bg=(40, 116, 240), fg=(255, 255, 255)), SAFE, "Genuine sale ad"))

    # QR posters
    s.append(("poster_upi_refund.png", qr_poster("Refund Desk", ["Scan to receive your Rs 4999 refund", "Amount is credited instantly"], "upi://pay?pa=refund.desk@ybl&pn=Refund%20Desk&am=4999"), PHISH, "UPI 'scan to receive' scam"))
    s.append(("poster_parking_qr.png", qr_poster("Smart Parking", ["Scan to pay parking fee"], "http://smartpark-pay.top/pay"), PHISH, "Fake parking-meter QR"))
    s.append(("poster_bare_domain_qr.png", qr_poster("HDFC NetBanking", ["Scan to update KYC"], "hdfc-netbanking.site/login"), PHISH, "QR link without http://"))
    s.append(("legit_poster_wifi.png", qr_poster("Campus Wi-Fi", ["Scan to connect to the student network"], "WIFI:S:IIITK-Student;T:WPA;P:welcome2026;;"), SAFE, "Genuine Wi-Fi QR"))
    s.append(("legit_poster_irctc.png", qr_poster("Book train tickets", ["Scan to open IRCTC"], "https://www.irctc.co.in/nget/train-search"), SAFE, "Genuine website QR"))

    # Social media
    s.append(("social_insta_giveaway.png", social_post("instagram.giveaway.official", "We are giving away 50 iPhones to our followers! Log in with your Instagram account to enter the lucky draw: instagram-giveaway.live/login"), PHISH, "Fake brand giveaway post"))

    # Evasion variants of the attacks above
    s.append(("evasion_rotated_sms.png", rotated(sms_kyc, 25), PHISH, "Rotated 25 degrees"))
    s.append(("evasion_lowres_email.png", low_res(email_pp), PHISH, "Low resolution (45%)"))
    s.append(("evasion_photo_login.jpg", phone_photo(login_pp), PHISH, "Photo of a screen at an angle"))
    s.append(("evasion_darkmode_sms.png", sms_screen("IT-DEPT", ["Income Tax Department: A refund of Rs 15,490 has been approved for you. Submit your bank details to receive it: incometax-refund.gov.in.claim-now.com"], dark=True), PHISH, "Dark mode"))
    s.append(("evasion_defanged_link.png", sms_screen("VM-HDFCBK", ["Your HDFC account will be suspended. Complete KYC now at hxxps://hdfc-kyc-update[.]online/verify"]), PHISH, "Defanged link"))
    s.append(("evasion_awareness_camouflage.png", sms_screen("VK-SBIINB", ["SBI cares: never share your OTP with anyone.", "Your YONO account will be blocked today. Update PAN/KYC: sbi-kyc-update.in/verify"]), PHISH, "Lure hidden behind safety advice"))
    return s


def generate(out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    labels: dict[str, object] = {}
    techniques: dict[str, str] = {}
    for name, img, label, technique in build():
        img.save(out_dir / name, quality=80) if name.endswith(".jpg") else img.save(out_dir / name)
        labels[name] = label
        techniques[name] = technique
    (out_dir / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    (out_dir / "techniques.json").write_text(json.dumps(techniques, indent=2), encoding="utf-8")
    return labels


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Red Team phishing screenshots, ads and posters.")
    parser.add_argument("--out", help="Output folder (default: data/test_images next to this script)")
    args = parser.parse_args()
    out = Path(args.out) if args.out else DEFAULT_OUT
    labels = generate(out)
    phishing = sum(1 for v in labels.values() if v != SAFE)
    shown = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
    print(f"Saved {len(labels)} images to {shown} ({phishing} phishing, {len(labels) - phishing} safe) + labels.json")


if __name__ == "__main__":
    main()

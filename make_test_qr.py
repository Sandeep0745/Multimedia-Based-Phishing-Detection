"""
Red Team QR generator: one QR code per attack payload, plus labels.json for scoring.

Usage:
  python make_test_qr.py
  python -m src.cli batch data/test_qr        # Blue Team: scan
  python -m src.cli evaluate data/test_qr     # Blue Team: score against labels.json

LAB USE ONLY: payloads use look-alike / reserved domains, or reported phishing URLs
copied as text from PhishTank / OpenPhish (never opened).
"""

import json
from pathlib import Path

import qrcode

PHISH = ["Suspicious", "High-Risk Phishing"]
SAFE = "Safe"
ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "data" / "test_qr"

# name: (payload, expected verdict)
tests = {
    "typosquat":      ("http://paypa1.com/login", PHISH),
    "brand_chain":    ("https://paypal.com.secure-verify.example/login", PHISH),
    "bad_tld":        ("https://amaz0n-rewards.tk/claim", PHISH),
    "shortener":      ("https://bit.ly/abc123", PHISH),
    "ip_host":        ("http://192.168.10.5/bank/verify", PHISH),
    "at_trick":       ("https://google.com@evil.example/login", PHISH),
    "sms_scam":       ("SMSTO:+10000000000:Your account is locked, reply YES", PHISH),
    "legit":          ("https://www.microsoft.com", SAFE),
    "PhishTank1":     ("https://espacesecu-tehna.com/index.php", PHISH),
    # More variety
    "no_scheme":      ("hdfc-netbanking.site/login", PHISH),
    "punycode":       ("https://xn--pypal-4ve.com/signin", PHISH),
    "free_hosting":   ("https://hdfc-login.web.app/verify", PHISH),
    "open_redirect":  ("https://www.google.com/url?q=http://paypa1.com/login", PHISH),
    "google_sites":   ("https://sites.google.com/view/hdfc-kyc-update", PHISH),
    "defanged":       ("http://paypa1[.]com/login", PHISH),
    "javascript":     ("javascript:alert(document.cookie)", PHISH),
    "sms_kyc":        ("SMSTO:+910000000000:KYC expired. Reply with OTP to avoid account block", PHISH),
    "legit_wifi":     ("WIFI:S:CafeGuest;T:WPA;P:coffee123;;", SAFE),
    "legit_vcard":    ("BEGIN:VCARD\nVERSION:3.0\nFN:Asha Menon\nTEL:+910000000000\nEND:VCARD", SAFE),
    "legit_irctc":    ("https://www.irctc.co.in/nget/train-search", SAFE),
    "legit_upi_shop": ("upi://pay?pa=chaistall@okaxis&pn=Chai%20Stall", SAFE),
}


def main() -> None:
    # Always next to this script, whichever folder it is run from.
    out = OUT_DIR
    out.mkdir(parents=True, exist_ok=True)
    labels = {}
    for name, (payload, expected) in tests.items():
        with (out / f"{name}.png").open("wb") as stream:
            qrcode.make(payload).save(stream)
        labels[f"{name}.png"] = expected
    (out / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    shown = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
    print(f"Saved {len(tests)} QR codes + labels.json to {shown}")


if __name__ == "__main__":
    main()

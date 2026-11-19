"""
Download the real-world training data: python -m src.model.download_data

- PhiUSIIL Phishing URL Dataset (UCI, 235,795 labelled URLs) -> data/datasets/
- Tranco top-sites list -> data/config/top_domains.txt (known-popular domains
  that the ML model is not applied to, minus free hosting platforms)
- OpenPhish community feed -> data/config/openphish_feed.txt (currently active
  phishing URLs, used as a blocklist; re-run to refresh, it changes daily)
- Public Suffix List (publicsuffix.org) -> data/config/public_suffix_list.dat
  (offline domain parsing: which part of a hostname is the owner's domain)

Only these public research files are fetched; URLs inside them are never visited.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import urllib.request
import zipfile
from datetime import date

from src.core.config import CONFIG_DIR, DATA_DIR

PHIUSIIL_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
PHIUSIIL_CSV = "PhiUSIIL_Phishing_URL_Dataset.csv"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
OPENPHISH_URL = "https://openphish.com/feed.txt"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
DATASETS_DIR = DATA_DIR / "datasets"


def _fetch(url: str) -> bytes:
    print(f"Downloading {url} ...")
    req = urllib.request.Request(url, headers={"User-Agent": "phishing-detector-research"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def download_phiusiil(force: bool = False) -> None:
    target = DATASETS_DIR / PHIUSIIL_CSV
    if target.is_file() and not force:
        print(f"Dataset already present: {target}")
        return
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(_fetch(PHIUSIIL_URL))) as zf:
        zf.extract(PHIUSIIL_CSV, DATASETS_DIR)
    print(f"Saved {target}")


def build_top_domains(top_n: int = 30000) -> None:
    platforms = set(json.loads((CONFIG_DIR / "hosting_platforms.json").read_text(encoding="utf-8"))["platforms"])
    with zipfile.ZipFile(io.BytesIO(_fetch(TRANCO_URL))) as zf:
        name = zf.namelist()[0]
        rows = csv.reader(io.TextIOWrapper(zf.open(name), encoding="utf-8"))
        domains: list[str] = []
        holdout: list[str] = []
        for row in rows:
            if len(row) != 2 or not row[0].strip().isdigit():
                continue  # Skip a header or malformed line rather than abort the download.
            rank, domain = row
            r = int(rank)
            if r > top_n + 1000:
                break
            if r > top_n:
                # Legitimate sites just below the trusted list, for real-world evaluation.
                holdout.append(domain.lower())
            elif domain.lower() not in platforms:
                domains.append(domain.lower())
    out = CONFIG_DIR / "top_domains.txt"
    header = f"# Tranco top {top_n} (tranco-list.eu), fetched {date.today()}, hosting platforms removed\n"
    out.write_text(header + "\n".join(domains) + "\n", encoding="utf-8")
    print(f"Saved {len(domains)} domains to {out}")
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    hold = DATASETS_DIR / "legit_holdout.txt"
    hold.write_text("\n".join(holdout) + "\n", encoding="utf-8")
    print(f"Saved {len(holdout)} held-out legitimate domains to {hold}")


def download_openphish() -> None:
    urls = [u.strip() for u in _fetch(OPENPHISH_URL).decode("utf-8", errors="replace").splitlines() if u.strip()]
    out = CONFIG_DIR / "openphish_feed.txt"
    header = f"# OpenPhish community feed (openphish.com), fetched {date.today()}\n"
    out.write_text(header + "\n".join(urls) + "\n", encoding="utf-8")
    print(f"Saved {len(urls)} phishing URLs to {out}")


def download_public_suffix_list() -> None:
    out = CONFIG_DIR / "public_suffix_list.dat"
    out.write_bytes(_fetch(PSL_URL))
    print(f"Saved {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="Re-download the dataset even if present")
    parser.add_argument("--top", type=int, default=30000, help="How many Tranco domains to keep")
    args = parser.parse_args()
    download_phiusiil(force=args.force)
    build_top_domains(args.top)
    download_public_suffix_list()
    try:
        download_openphish()
    except Exception as exc:  # noqa: BLE001 — the feed is optional
        print(f"OpenPhish feed skipped: {exc}")


if __name__ == "__main__":
    main()

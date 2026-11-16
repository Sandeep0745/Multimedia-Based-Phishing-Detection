"""Project paths and loaded JSON configuration."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


# src/core/config.py -> parents: core, src, project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = DATA_DIR / "config"
MODEL_DIR = DATA_DIR / "model"
SAMPLES_DIR = DATA_DIR / "samples"


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def load_brands() -> list[dict[str, Any]]:
    return _load_json(CONFIG_DIR / "brands.json")["brands"]


@lru_cache(maxsize=1)
def load_suspicious_tlds() -> set[str]:
    return {t.lower().lstrip(".") for t in _load_json(CONFIG_DIR / "suspicious_tlds.json")["tlds"]}


@lru_cache(maxsize=1)
def load_keywords() -> dict[str, Any]:
    return _load_json(CONFIG_DIR / "keywords.json")


@lru_cache(maxsize=1)
def load_scoring() -> dict[str, Any]:
    return _load_json(CONFIG_DIR / "scoring.json")


def score_band(score: float) -> str:
    """"safe", "suspicious" or "high_risk" for a 0-100 score, using the bands in scoring.json."""
    bands = load_scoring()["bands"]
    if score <= bands["safe_max"]:
        return "safe"
    if score <= bands["suspicious_max"]:
        return "suspicious"
    return "high_risk"


@lru_cache(maxsize=1)
def load_hosting_platforms() -> set[str]:
    """Free hosting platforms (anyone can publish on them)."""
    return {p.lower() for p in _load_json(CONFIG_DIR / "hosting_platforms.json")["platforms"]}


@lru_cache(maxsize=1)
def load_top_domains() -> set[str]:
    """Known-popular registrable domains (Tranco); empty if the list was not built."""
    path = CONFIG_DIR / "top_domains.txt"
    if not path.is_file():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {d.strip().lower() for d in lines if d.strip() and not d.startswith("#")} - load_hosting_platforms()


@lru_cache(maxsize=1)
def load_public_suffixes() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """
    ICANN section of the Public Suffix List as (rules, wildcard parents, exceptions).

    Private-section entries (github.io, netlify.app, ...) are left out on purpose so
    those platforms stay the registrable domain and keep matching hosting_platforms.json.
    Returns empty sets if the list was not downloaded.
    """
    path = CONFIG_DIR / "public_suffix_list.dat"
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    if not path.is_file():
        return frozenset(), frozenset(), frozenset()
    in_icann = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if "===BEGIN ICANN DOMAINS===" in line:
            in_icann = True
        elif "===END ICANN DOMAINS===" in line:
            break
        if not in_icann or not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcards.add(rule[2:])
        else:
            rules.add(rule)
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


@lru_cache(maxsize=1)
def load_tlds() -> frozenset[str]:
    """Every top-level domain in the Public Suffix List (com, in, online, site, ai, ...)."""
    rules, wildcards, _ = load_public_suffixes()
    return frozenset(r.rsplit(".", 1)[-1] for r in rules | wildcards)


@lru_cache(maxsize=1)
def load_blocklist() -> set[str]:
    """
    Known phishing URLs: data/config/blocklist.txt (your own reports, e.g. from
    PhishTank) plus data/config/openphish_feed.txt (python -m src.model.download_data).
    """
    entries: set[str] = set()
    for name in ("blocklist.txt", "openphish_feed.txt"):
        path = CONFIG_DIR / name
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line)
    return entries


@lru_cache(maxsize=1)
def load_allowlist() -> frozenset[str]:
    """
    Domains your organisation trusts (data/config/allowlist.txt), one per line.

    An entry is a hostname or registrable domain ("intranet.example.com", "example.com");
    a pasted URL is reduced to its hostname. Lines starting with # are comments.
    """
    path = CONFIG_DIR / "allowlist.txt"
    if not path.is_file():
        return frozenset()
    entries: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if "://" in line:
            line = line.split("://", 1)[1]
        line = line.split("/", 1)[0].split(":", 1)[0].rstrip(".")
        if line.startswith("www."):
            line = line[4:]
        if line:
            entries.add(line)
    return frozenset(entries)


def brand_domain_set() -> set[str]:
    """Return known-legitimate brand domains (lowercase)."""
    domains: set[str] = set()
    for brand in load_brands():
        for d in brand.get("domains", []):
            domains.add(d.lower())
    return domains


def brand_aliases() -> list[str]:
    """Short brand forms (hdfc, sbi, icici) matched only as whole words / hostname tokens."""
    return [a.lower() for b in load_brands() for a in b.get("aliases", [])]


@lru_cache(maxsize=1)
def load_user_content_prefixes() -> tuple[str, ...]:
    """Host or host/path prefixes where anyone can publish a page (Google Sites, Forms, ...)."""
    return tuple(p.lower() for p in _load_json(CONFIG_DIR / "hosting_platforms.json").get("user_content", []))


def brand_names() -> list[str]:
    return [b["name"].lower() for b in load_brands()]


def resolve_tesseract_cmd() -> str | None:
    """
    Locate tesseract.exe on Windows or unix PATH.

    Order: TESSERACT_CMD env, shutil.which, common Program Files paths.
    """
    env = os.environ.get("TESSERACT_CMD")
    if env and Path(env).is_file():
        return env

    import shutil

    found = shutil.which("tesseract")
    if found:
        return found

    candidates = [
        Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
        Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
        Path("/usr/bin/tesseract"),
        Path("/usr/local/bin/tesseract"),
        Path("/opt/homebrew/bin/tesseract"),
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def model_path() -> Path:
    return MODEL_DIR / "url_model.joblib"


def dataset_path() -> Path:
    return DATA_DIR / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"

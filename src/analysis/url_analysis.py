"""Heuristic URL phishing analysis (offline, no network fetches)."""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from urllib.parse import parse_qsl, unquote

from src.analysis.domains import is_ip_host, registrable_domain
from src.core.config import (
    brand_aliases,
    brand_domain_set,
    brand_names,
    load_allowlist,
    load_blocklist,
    load_brands,
    load_hosting_platforms,
    load_keywords,
    load_scoring,
    load_suspicious_tlds,
    load_top_domains,
    load_user_content_prefixes,
    score_band,
)
from src.core.models import ComponentResult, FiredRule
from src.extraction.urls import extract_urls, repair_ocr_homoglyphs, safe_urlparse, url_key

# DNS limits (RFC 1035). Longer names cannot be real hosts; checking them first also keeps
# the brand look-alike search below fast for attacker-made multi-kilobyte QR payloads.
MAX_HOST_LENGTH = 253
MAX_LABEL_LENGTH = 63
# Redirect targets followed per URL (?url=..&next=..); the first few are enough to judge it.
MAX_REDIRECT_TARGETS = 5
# Brand names and keywords this short only count at the start of a hostname token, so words
# that merely end in one ("purchase" / chase, "pineapple" / apple, "hotpot" / otp) are ignored.
SHORT_BRAND_LENGTH = 5
SHORT_KEYWORD_LENGTH = 3

# Query parameters commonly used to forward a visitor to another site.
_REDIRECT_PARAMS = {
    "url", "u", "q", "r", "to", "out", "goto", "link", "next", "target", "dest", "destination",
    "continue", "return", "returnurl", "return_url", "redirect", "redirect_url", "redirect_uri",
    "redirecturl", "redir", "site",
}

# Cyrillic / Greek / other letters that look like Latin ones (subset of Unicode TR39 confusables).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ո": "n", "ѕ": "s", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ɡ": "g",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ɩ": "i", "ı": "i", "ｏ": "o", "０": "0",
})

# Unicode scripts (first word of the character name) with letters that look like Latin ones.
_LOOKALIKE_SCRIPTS = {"CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "FULLWIDTH"}

# What each rule means; the weights are in data/config/scoring.json ("url_rules").
RULES = {
    "malformed_url": "Malformed URL that cannot be parsed (evasion trick)",
    "overlong_host": "Hostname longer than DNS allows (evasion trick)",
    "blocklist": "Reported phishing URL (threat-feed / blocklist match)",
    "redirect_to_risky_url": "Redirects to a risky URL",
    "redirect_param": "URL forwards the visitor to another site",
    "user_content_platform": "User-created page on a trusted platform",
    "user_content_brand_or_credential": "Brand or login words on a user-created page",
    "legit_brand_sensitive_path": "Known brand domain with sensitive path keywords",
    "allowlisted_domain": "Domain is on your allowlist (data/config/allowlist.txt)",
    "userinfo_trick": "URL contains @ / userinfo redirect trick",
    "ip_host": "Host is a raw IP address",
    "punycode": "Punycode (xn--) hostname",
    "homoglyph_brand": "Unicode look-alike letters spell a brand name",
    "homoglyph_scripts": "Mixed-script / homoglyph hostname",
    "suspicious_tld": "Unusual / high-abuse TLD",
    "excessive_subdomains": "Excessive subdomain depth",
    "many_subdomains": "Multiple subdomains",
    "hyphenated_host": "Multiple hyphens in hostname",
    "url_shortener": "Known URL shortener host",
    "brand_name_in_domain": "Brand name used in a domain that is not on the brand's official list",
    "typosquat_distance_1": "Hostname is 1 edit from a known brand",
    "typosquat_distance_2": "Hostname is 2 edits from a known brand",
    "brand_in_deceptive_host": "Brand name appears in a non-official hostname",
    "brand_domain_chain": "Brand-looking domain used as subdomain of another domain",
    "lookalike_credential_path": "Brand lookalike combined with a login / verify style path",
    "path_keywords": "Suspicious keywords in path/query",
    "host_keywords": "Sensitive keywords in hostname",
    "free_hosting": "Page hosted on a free website-hosting platform",
    "long_url": "Unusually long URL",
    "digit_heavy": "Digit-heavy URL/host",
    "ml_url_classifier": "ML model raised phishing probability",
}

# Rules that mean "this host imitates a brand"; together with a login-style path they score extra.
_LOOKALIKE_RULES = {
    "brand_name_in_domain", "typosquat_distance_1", "typosquat_distance_2", "brand_in_deceptive_host",
    "brand_domain_chain", "homoglyph_brand",
}


def _weight(rule_id: str) -> float:
    return float(load_scoring()["url_rules"][rule_id])



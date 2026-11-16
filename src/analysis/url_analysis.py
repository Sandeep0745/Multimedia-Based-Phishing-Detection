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


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _is_overlong(host: str) -> bool:
    return len(host) > MAX_HOST_LENGTH or any(len(label) > MAX_LABEL_LENGTH for label in host.split("."))


def _has_mixed_scripts(text: str) -> bool:
    """
    Latin letters mixed with a script whose letters pass for Latin ones (Cyrillic "а", Greek "ο"),
    or two such scripts, in one label. Accented Latin ("ångström") or a Thai / Hindi / Chinese
    name is not a look-alike trick.
    """
    scripts = set()
    for ch in text:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "UNKNOWN").split(" ", 1)[0])
    lookalike = scripts & _LOOKALIKE_SCRIPTS
    return bool(lookalike) and ("LATIN" in scripts or len(lookalike) > 1)


def _decode_idna(host: str) -> str:
    """Show punycode labels (xn--...) as the Unicode the victim sees."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def _nearest_brand(token: str, brands: list[str]) -> tuple[int, str]:
    best = (99, "")
    for b in brands:
        # The edit distance is at least the length difference, so such a brand cannot beat `best`.
        if abs(len(token) - len(b)) >= best[0]:
            continue
        d = levenshtein(token, b)
        if d < best[0]:
            best = (d, b)
    return best


def _is_letter_swap_of_short_brand(token: str, brand: str) -> bool:
    """apply/apple, chose/chase: one letter replaced by another in a short brand is usually a real word."""
    if len(brand) > 5 or len(token) != len(brand) or not token.isalpha():
        return False
    return sum(1 for a, b in zip(token, brand, strict=True) if a != b) == 1


def _word_in_token(word: str, token: str, short_length: int) -> bool:
    """A brand / keyword inside one hostname token; short ones only at the start ("chasebank", not "purchase")."""
    if len(word) <= short_length:
        return token.startswith(word)
    return word in token


def extract_features(url: str) -> dict[str, float]:
    """Numeric features used by the heuristic rules. Raises ValueError for unparseable URLs."""
    parsed = safe_urlparse(url if "://" in url else "http://" + url)
    if parsed is None:
        raise ValueError(f"Unparseable URL: {url!r}")
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or "")
    query = unquote(parsed.query or "")
    full = url.lower()
    reg = registrable_domain(host)
    label = reg.split(".")[0] if reg else host
    sub_parts = host[: -len(reg)].strip(".").split(".") if reg and host.endswith(reg) else []
    sub_parts = [p for p in sub_parts if p]
    keywords = load_keywords()
    path_kw = keywords.get("url_path_keywords", [])
    shorteners = {s.lower() for s in keywords.get("shorteners", [])}
    brands = brand_names()
    aliases = brand_aliases()
    brand_domains = brand_domain_set()
    tlds = load_suspicious_tlds()
    tld = reg.split(".")[-1] if "." in reg else ""
    max_brand_length = max((len(b) for b in brands), default=0)

    # Nearest brand over the label and each hyphen/dot token (amaz0n-prize -> amaz0n).
    min_brand_dist, near_brand = _nearest_brand(label, brands)
    tokens = re.split(r"[-_.]", label)
    for tok in tokens + [t.translate(str.maketrans("01537", "oisee")) for t in tokens]:
        if len(tok) < 4:
            continue
        d, b = _nearest_brand(tok, brands)
        if d < min_brand_dist:
            min_brand_dist, near_brand = d, b
    if min_brand_dist == 1 and _is_letter_swap_of_short_brand(label, near_brand):
        min_brand_dist = 99

    # A brand name used as the label or a whole token of another domain (paypal-login.com).
    brand_token = label in brands or any(tok in brands for tok in tokens)
    # OCR digit/letter swaps that recover an exact brand name -> treat as distance 1 typosquat.
    ocr_recovers_brand = False
    for variant_host in repair_ocr_homoglyphs(label):
        if variant_host == label:
            continue
        if variant_host in brands:
            ocr_recovers_brand = True
            min_brand_dist, near_brand = min(min_brand_dist, 1), variant_host
        for tok in re.split(r"[-_.]", variant_host):
            if tok in brands:
                ocr_recovers_brand = True
                min_brand_dist, near_brand = min(min_brand_dist, 1), tok
            # Tokens much longer than every brand cannot be within 2 edits of one.
            if 4 <= len(tok) <= max_brand_length + 2:
                d, b = _nearest_brand(tok, brands)
                if d < min_brand_dist and not _is_letter_swap_of_short_brand(tok, b):
                    min_brand_dist, near_brand = d, b

    # Unicode look-alikes: map Cyrillic/Greek letters to Latin and compare with brands.
    shown_host = _decode_idna(host)
    shown_label = _decode_idna(label)
    skeleton = shown_label.translate(_CONFUSABLES)
    homoglyph_brand = shown_label != skeleton and any(
        skeleton == b
        or b in re.split(r"[-_.]", skeleton)
        or (abs(len(skeleton) - len(b)) <= 1 and levenshtein(skeleton, b) <= 1)
        for b in brands
    )

    host_tokens = [t for t in re.split(r"[-_.]", host) if t]
    allowlist = load_allowlist()
    bare_host = host[4:] if host.startswith("www.") else host
    allowlisted = bare_host in allowlist or reg in allowlist
    brand_in_host = any(_word_in_token(b, tok, SHORT_BRAND_LENGTH) for b in brands for tok in host_tokens) or any(
        a in host_tokens for a in aliases
    )
    exact_brand = reg in brand_domains or host in brand_domains

    netloc = parsed.netloc
    return {
        "url_length": float(len(url)),
        "host_length": float(len(host)),
        "num_dots": float(host.count(".")),
        # Hyphens the victim sees: "xn--" punycode prefixes are encoding, not part of the name.
        "num_hyphens": float(shown_host.replace("xn--", "").count("-")),
        "num_digits": float(sum(c.isdigit() for c in host)),
        "subdomain_depth": float(len(sub_parts)),
        "has_ip": 1.0 if is_ip_host(host) else 0.0,
        "has_at": 1.0 if "@" in netloc else 0.0,
        "has_userinfo": 1.0 if parsed.username else 0.0,
        "punycode": 1.0 if "xn--" in host else 0.0,
        # Judged per label: a Thai or Hindi name under ".com" is normal, Latin + Cyrillic in one label is not.
        "mixed_scripts": 1.0 if any(_has_mixed_scripts(part) for part in shown_host.split(".")) else 0.0,
        "homoglyph_brand": 1.0 if homoglyph_brand else 0.0,
        "suspicious_tld": 1.0 if tld in tlds else 0.0,
        "path_keywords": float(sum(1 for k in path_kw if k in path.lower() or k in query.lower())),
        "is_shortener": 1.0 if host in shorteners or reg in shorteners else 0.0,
        "brand_distance": float(min_brand_dist),
        "near_brand_length": float(len(near_brand)),
        "brand_token": 1.0 if brand_token else 0.0,
        "ocr_recovers_brand": 1.0 if ocr_recovers_brand else 0.0,
        "brand_in_host_not_exact": 1.0 if brand_in_host and not (exact_brand or allowlisted) else 0.0,
        "exact_brand": 1.0 if exact_brand else 0.0,
        "allowlisted": 1.0 if allowlisted else 0.0,
        "has_https": 1.0 if parsed.scheme == "https" else 0.0,
        "digit_ratio": float(sum(c.isdigit() for c in full) / max(len(full), 1)),
    }


def _blocklist_key(url: str) -> str:
    """Compare URLs ignoring scheme, ``www.``, case of the host, and trailing slash."""
    return url_key(url.strip())


@lru_cache(maxsize=1)
def _blocklist_index() -> tuple[frozenset[str], frozenset[str]]:
    """(exact URL keys, hosts) from the loaded blocklist."""
    keys = {_blocklist_key(u) for u in load_blocklist()}
    return frozenset(keys), frozenset(k.split("/")[0].split("?")[0] for k in keys)


def blocklist_match(url: str, host: str, reg: str) -> str | None:
    """
    Return "url" / "host" when the URL is a reported phishing URL, else None.

    A whole host is only blocked when it is not a popular, official brand or
    allowlisted domain, so one bad page on e.g. docs.google.com does not flag all of it.
    """
    keys, hosts = _blocklist_index()
    if not keys:
        return None
    key = _blocklist_key(url)
    if key in keys:
        return "url"
    bare = host[4:] if host.startswith("www.") else host
    trusted = reg in load_top_domains() or reg in brand_domain_set() or reg in load_allowlist()
    if bare in hosts and not trusted:
        return "host"
    return None


def _fully_unquote(value: str, rounds: int = 3) -> str:
    """Undo repeated percent-encoding (http%253A%252F%252F...), a trick to hide redirect targets."""
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _redirect_targets(query: str, host: str) -> list[str]:
    """URLs on another host passed in redirect-style query parameters (?url=, ?q=, ?redirect=)."""
    targets: list[str] = []
    for key, value in parse_qsl(query, keep_blank_values=False):
        if key.lower() not in _REDIRECT_PARAMS:
            continue
        for found in extract_urls(_fully_unquote(value)):
            parsed = safe_urlparse(found)
            if parsed and (parsed.hostname or "").lower() not in ("", host) and found not in targets:
                targets.append(found)
                if len(targets) >= MAX_REDIRECT_TARGETS:
                    return targets
    return targets


def _user_content_page(host: str, path: str) -> str | None:
    bare = host[4:] if host.startswith("www.") else host
    location = (bare + path).lower()
    for prefix in load_user_content_prefixes():
        if location == prefix or location.startswith(prefix + "/") or bare == prefix:
            return prefix
        if "/" not in prefix and bare.endswith("." + prefix):
            return prefix  # bucket.s3.amazonaws.com, <cid>.ipfs.dweb.link
    return None


def _brand_words_in_path(path: str) -> list[str]:
    tokens = set(re.split(r"[^a-z0-9]+", unquote(path).lower()))
    return sorted(w for w in set(brand_names()) | set(brand_aliases()) if w in tokens)


@lru_cache(maxsize=1)
def _brand_chain_patterns() -> tuple[tuple[str, re.Pattern], ...]:
    """(official domain, pattern) for "brand.com." appearing inside a longer hostname."""
    patterns = []
    for brand in load_brands():
        for d in brand.get("domains", []):
            label = d.lower().split(".")[0]
            patterns.append((d.lower(), re.compile(rf"(?:^|\.){re.escape(label)}\.(?:com|net|org|co|in)\.")))
    return tuple(patterns)


def _brand_domain_chain(host: str, reg: str) -> bool:
    """
    paypal.com.evil.example: an official-looking brand domain used as a subdomain of another domain.

    Only the subdomain part is checked, so a brand's own country domain (paypal.co.uk,
    yahoo.co.jp) is not mistaken for a chain.
    """
    if not reg or not host.endswith(reg) or len(host) == len(reg):
        return False
    sub = host[: -len(reg)]  # keeps its trailing dot: "secure.paypal.com."
    return any(reg != domain and pattern.search(sub) for domain, pattern in _brand_chain_patterns())



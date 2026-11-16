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


def analyze_url(url: str, _depth: int = 0, *, use_blocklist: bool = True) -> ComponentResult:
    """Score a single URL and list fired rules. `use_blocklist=False` measures the rules alone."""
    rules: list[FiredRule] = []
    score = 0.0

    def fire(rule_id: str, evidence: str, weight: float | None = None, description: str | None = None) -> None:
        nonlocal score
        w = _weight(rule_id) if weight is None else weight
        score += w
        rules.append(FiredRule(rule_id, description or RULES[rule_id], w, evidence=evidence))

    def per_keyword(rule_id: str, count: float) -> float:
        return min(_weight(rule_id) * count, _weight(rule_id + "_max"))

    parsed = safe_urlparse(url if "://" in url else "http://" + url)
    if parsed is not None and _is_overlong((parsed.hostname or "").lower()):
        fire("overlong_host", (parsed.hostname or "")[:120])
        return ComponentResult(name="url", score=min(score, 100.0), rules=rules, details={"url": url[:500], "overlong": True})
    try:
        feats = extract_features(url)
    except ValueError:
        parsed = None
    if parsed is None:
        # Brackets or broken hosts make many parsers (and some scanners) give up;
        # attackers use that to slip links past filters.
        fire("malformed_url", url[:120])
        return ComponentResult(name="url", score=min(score, 100.0), rules=rules, details={"url": url, "malformed": True})

    host = (parsed.hostname or "").lower()
    reg = registrable_domain(host)
    bare_host = host[4:] if host.startswith("www.") else host
    # A hosting platform's own homepage (duckdns.org) is the provider's site, not user content.
    platform_home = reg in load_hosting_platforms() and bare_host == reg
    top_domain = reg in load_top_domains() or platform_home

    blocked = blocklist_match(url, host, reg) if use_blocklist else None
    if blocked:
        what = "URL" if blocked == "url" else "hostname"
        fire("blocklist", host, description=f"Reported phishing {what} (threat-feed / blocklist match)")

    # Open redirects: google.com/url?q=http://evil.tk — judge the real destination too.
    if _depth < 2:
        for target in _redirect_targets(parsed.query, host):
            inner = analyze_url(target, _depth + 1, use_blocklist=use_blocklist)
            if score_band(inner.score) != "safe":
                score = max(score, inner.score)
                rules.append(
                    FiredRule("redirect_to_risky_url", RULES["redirect_to_risky_url"], inner.score, evidence=target[:120])
                )
            else:
                fire("redirect_param", target[:120])

    # User-made pages on trusted platforms (Google Sites / Forms, Microsoft Forms, cloud buckets).
    user_content = _user_content_page(host, parsed.path or "")
    if user_content:
        fire("user_content_platform", user_content)
        brand_words = _brand_words_in_path(parsed.path or "")
        if brand_words or feats["path_keywords"] >= 1:
            evidence = ", ".join(brand_words) if brand_words else f"keywords={int(feats['path_keywords'])}"
            fire("user_content_brand_or_credential", evidence)

    trusted = feats["exact_brand"] >= 1.0 or feats["allowlisted"] >= 1.0
    if not blocked and trusted and feats["brand_in_host_not_exact"] < 1.0:
        # Official brand or allowlisted domain: only a mild signal from path keywords.
        if feats["path_keywords"] >= 2 or (user_content and feats["path_keywords"] >= 1):
            fire("legit_brand_sensitive_path", url, weight=per_keyword("legit_brand_sensitive_path", feats["path_keywords"]))
        if feats["allowlisted"] >= 1.0:
            fire("allowlisted_domain", reg)
        return ComponentResult(
            name="url",
            score=min(score, 100.0),
            rules=rules,
            details={"url": url, "features": feats, "registrable_domain": reg},
        )

    if feats["has_at"] or feats["has_userinfo"]:
        fire("userinfo_trick", url)
    if feats["has_ip"]:
        fire("ip_host", host)
    if feats["punycode"]:
        fire("punycode", f"{host} = {_decode_idna(host)}")
    if feats["homoglyph_brand"]:
        fire("homoglyph_brand", _decode_idna(host))
    elif feats["mixed_scripts"]:
        fire("homoglyph_scripts", host)
    if feats["suspicious_tld"]:
        fire("suspicious_tld", reg)
    if feats["subdomain_depth"] >= 3:
        fire("excessive_subdomains", f"{int(feats['subdomain_depth'])} levels")
    elif feats["subdomain_depth"] >= 2:
        fire("many_subdomains", host)
    if feats["num_hyphens"] >= 2:
        fire("hyphenated_host", host)
    if feats["is_shortener"]:
        fire("url_shortener", host)

    # Look-alikes of a brand. Popular sites (Tranco top list) are real domains in their own
    # right, e.g. apply.com, googleusercontent.com or the brand's own country site yahoo.co.jp.
    brand_dist = feats["brand_distance"]
    if not top_domain and not feats["homoglyph_brand"]:
        if feats["brand_token"]:
            fire("brand_name_in_domain", host)
        elif feats["ocr_recovers_brand"] or brand_dist == 1:
            fire("typosquat_distance_1", host)
        elif brand_dist == 2 and feats["near_brand_length"] >= 7:
            fire("typosquat_distance_2", host)
    if feats["brand_in_host_not_exact"] and not top_domain:
        fire("brand_in_deceptive_host", host)
    # Brand name as subdomain of unrelated domain: paypal.com.evil.example
    if _brand_domain_chain(host, reg):
        fire("brand_domain_chain", host)

    # Brand lookalike that also asks for login / verify / payment.
    if feats["path_keywords"] >= 1 and any(r.rule_id in _LOOKALIKE_RULES for r in rules):
        fire("lookalike_credential_path", url)
    if feats["path_keywords"] >= 1:
        fire("path_keywords", f"count={int(feats['path_keywords'])}", weight=per_keyword("path_keywords", feats["path_keywords"]))

    # Sensitive words inside the hostname itself: secure-verify-account-update.com
    host_label = host.rsplit(".", 1)[0] if "." in host else host
    label_tokens = [t for t in re.split(r"[-_.]", host_label) if t]
    host_kw = sorted({
        k for k in load_keywords().get("url_path_keywords", [])
        if any(_word_in_token(k, tok, SHORT_KEYWORD_LENGTH) for tok in label_tokens)
    })
    if host_kw and not top_domain:
        fire("host_keywords", ", ".join(host_kw), weight=per_keyword("host_keywords", len(host_kw)))

    if reg in load_hosting_platforms() and not platform_home:
        fire("free_hosting", reg)
    if feats["url_length"] > 90:
        fire("long_url", str(int(feats["url_length"])))
    if feats["digit_ratio"] > 0.25 and feats["num_digits"] >= 3:
        fire("digit_heavy", host)

    # ML hostname model (raise-only). Skipped for known-popular domains, whose
    # famous brand names the model otherwise confuses with phishing lookalikes.
    proba = None
    if not top_domain:
        from src.model.classifier import predict_phishing_probability

        proba = predict_phishing_probability(url)
    if proba is not None:
        ml = load_scoring()["ml"]
        # The model alone misfires on unusual-but-legitimate names (CDNs, short brands),
        # so it only sets a tier floor by itself when very confident; otherwise another
        # rule must agree with it.
        corroborated = bool(rules)
        if not corroborated and proba >= ml["alone_probability"]:
            floor, desc = ml["alone_floor"], "ML model: hostname very likely phishing"
        elif corroborated and proba >= ml["high_risk_probability"]:
            floor, desc = ml["high_risk_floor"], "ML model: hostname very likely phishing (confirmed by rules)"
        elif corroborated and proba >= ml["suspicious_probability"]:
            floor, desc = ml["suspicious_floor"], "ML model: hostname likely phishing (confirmed by rules)"
        elif proba >= ml["min_probability"]:
            floor, desc = 0.0, RULES["ml_url_classifier"]
        else:
            floor, desc = None, ""
        if floor is not None:
            # Add a small boost, and lift the score to the tier floor if it is lower.
            new_score = max(score + min(25.0, (proba - 0.5) * 50.0), floor)
            rules.append(FiredRule("ml_url_classifier", desc, new_score - score, evidence=f"p={proba:.2f}"))
            score = new_score

    return ComponentResult(
        name="url",
        score=min(score, 100.0),
        rules=rules,
        details={"url": url, "features": feats, "registrable_domain": reg, "ml_probability": proba},
    )


def analyze_urls(urls: list[str], cache: dict[str, ComponentResult] | None = None) -> ComponentResult:
    """
    Worst-URL-wins aggregation across all extracted URLs.

    `cache` (url -> result) lets callers that score the same URLs twice, such as the
    URL and QR components of one image, analyse each URL only once. Cached results are
    never modified.
    """
    if not urls:
        return ComponentResult(name="url", score=0.0, rules=[], details={"urls": []})
    cache = {} if cache is None else cache
    results = []
    for url in urls:
        if url not in cache:
            cache[url] = analyze_url(url)
        results.append(cache[url])
    worst = results[0]
    for result in results[1:]:
        if result.score > worst.score:
            worst = result
    return ComponentResult(
        name="url",
        score=worst.score,
        rules=list(worst.rules),
        details={"urls": urls, "per_url": [r.details for r in results], "worst_url": worst.details.get("url")},
    )

"""URL isolation from OCR text with OCR-tolerant repairs."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from src.core.config import load_tlds


# Full URLs including defanged variants (hxxp, http[:]//).
_URL_RE = re.compile(
    r"""(?ix)
    (?:
        (?:https?|hxxps?|ftp)
        (?:\s*\[\s*:\s*\]\s*:|\s*:\s*)
        (?:/+|\[/\]\[/\])
      |
        www\.
    )
    [^\s<>"'\]]+
    """
)

# Bare domains / host+path without scheme (common in screenshots and QR codes).
# Labels may be Unicode (homoglyph domains); the last label is checked against
# the Public Suffix List's TLDs in code, so "report.pdf" or "e.g." never match.
_BARE_DOMAIN_RE = re.compile(
    r"""(?x)
    (?<![@\w.\-/])                       # not inside an e-mail, word, or longer host
    (?P<host>(?:[^\W_](?:[\w\-]{0,61}[^\W_])?\.)+(?P<tld>[^\W\d_]{2,24}))
    (?![\w\-])
    (?P<path>/[^\s<>"'\]]*)?
    """
)

# Sentence punctuation that often follows a URL in text but is not part of it.
_TRAILING_PUNCTUATION = ".,;:!?>]}'\""

# Used when the Public Suffix List has not been downloaded.
_FALLBACK_TLDS = frozenset(
    "com net org edu gov io co uk us in info biz app dev xyz top tk ml ga cf gq zip mov ru cn pw cc "
    "ai site online shop click link live store me ly gl gd to ws icu buzz".split()
)

# TLDs that are also common file extensions; a bare "main.py" is a file, not a site.
_FILE_LIKE_TLDS = {"py", "md", "sh", "pl", "rs", "so", "ps", "cs", "pdf"}

# Defanged notations used in threat reports and by attackers to dodge filters.
_DEFANG_TEXT_FIXES = (
    (re.compile(r"(?i)\bhxxp(s?)"), r"http\1"),
    (re.compile(r"\s*\[\s*(?:\.|dot)\s*\]\s*|\s*\(\s*(?:\.|dot)\s*\)\s*|\s*\{\s*\.\s*\}\s*", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(/+)\s*\]"), r"\1"),
)

_OCR_HOST_FIXES = (
    (re.compile(r"(?i)\bhxxps?\b"), "https"),
    (re.compile(r"(?i)http\s*\[\s*:\s*\]\s*//"), "http://"),
    (re.compile(r"(?i)https\s*\[\s*:\s*\]\s*//"), "https://"),
    (re.compile(r"(?i)\[\.\]"), "."),
    (re.compile(r"(?i)\(\.\)"), "."),
)


# TLDs recognised when deciding whether "host.\ncom" was split by OCR.
_JOIN_TLDS = {
    "com", "net", "org", "edu", "gov", "io", "co", "uk", "us", "in", "info", "biz",
    "app", "dev", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "ru",
    "cn", "pw", "cc", "icu", "click", "link", "shop",
}

# URL head, the whitespace after it, and (lookahead) the next token.
_SPLIT_URL_RE = re.compile(r"(?i)((?:https?|hxxps?)://\S*|www\.\S*)(\s+)(?=(\S+))")
_URL_CHARS_RE = re.compile(r"(?i)^[a-z0-9\-._~/?#&=%:+@]+$")


def _should_join(head: str, gap: str, tail: str) -> bool:
    """
    Decide whether `tail` is the rest of a URL that OCR split off `head`.

    Only joins when the URL is visibly unfinished, so a complete URL followed by
    ordinary words ("https://www.microsoft.com for docs") is left alone.
    """
    if gap.count("\n") > 1:
        # Blank line = paragraph break, never a wrapped URL.
        return False
    if not _URL_CHARS_RE.match(tail):
        return False
    if tail[0] in "./":
        # "https://paypa1 .com/login" / "https://evil.example /verify"
        return True

    rest = re.sub(r"(?i)^(?:(?:https?|hxxps?)://)?(?:www\.)?", "", head)
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    in_host = len(host) == len(rest)

    if in_host and "." not in host.rstrip("."):
        # Host has no TLD yet: "https://paypa" + "1.com"
        return True
    if in_host and head.endswith("."):
        # "https://paypa1." + "com/login" — but not sentence-final "x.com. Then"
        return re.split(r"[/:?#]", tail, maxsplit=1)[0].lower() in _JOIN_TLDS
    return head[-1] in "/-_=&%"


def rejoin_broken_urls(text: str) -> str:
    """
    Rejoin URLs that OCR split across a line break or a stray space.

    Example: 'https://paypa1.\\ncom/login' -> 'https://paypa1.com/login'
    """
    if not text:
        return ""
    # Remove spaces inserted right after the scheme: "https:// paypa1.com".
    fixed = re.sub(r"(?i)((?:https?|hxxps?)://)[ \t]+", r"\1", text)
    # Repeat so a URL split in several places is fully rejoined.
    for _ in range(5):
        joined = _SPLIT_URL_RE.sub(
            lambda m: m.group(1) + ("" if _should_join(m.group(1), m.group(2), m.group(3)) else m.group(2)),
            fixed,
        )
        if joined == fixed:
            break
        fixed = joined
    return fixed


def strip_trailing_punctuation(url: str) -> str:
    """
    Drop punctuation after a URL ("see https://x.com/a)." -> "https://x.com/a").

    A closing ")" is kept when it closes a "(" inside the URL, as in
    https://en.wikipedia.org/wiki/Phishing_(disambiguation).
    """
    while url:
        last = url[-1]
        if last in _TRAILING_PUNCTUATION or (last == ")" and url.count(")") > url.count("(")):
            url = url[:-1]
        else:
            break
    return url


def undfang(url: str) -> str:
    """Normalize defanged URL notations used in security write-ups."""
    out = strip_trailing_punctuation(url.strip())
    for pattern, repl in _OCR_HOST_FIXES:
        out = pattern.sub(repl, out)
    out = out.replace(" ", "")
    return out


def repair_ocr_homoglyphs(host: str) -> list[str]:
    """
    Produce alternate host readings for common OCR digit/letter swaps.

    Used by the URL analyzer for brand distance — the original host is still scored.
    """
    variants = {host}
    swaps = {"0": "o", "1": "l", "5": "s", "3": "e"}
    chars = list(host.lower())
    for i, ch in enumerate(chars):
        if ch in swaps:
            alt = chars.copy()
            alt[i] = swaps[ch]
            variants.add("".join(alt))
    # rn <-> m
    if "rn" in host.lower():
        variants.add(host.lower().replace("rn", "m", 1))
    return list(variants)


def safe_urlparse(url: str):
    """
    urlparse that never raises.

    Malformed input such as "http://evil[.com" makes urlparse raise ValueError
    ("Invalid IPv6 URL"); attacker-controlled QR / OCR text must not crash the scan.
    Returns None when the URL cannot be parsed even after removing brackets.
    """
    for candidate in (url, url.replace("[", "").replace("]", "")):
        try:
            parsed = urlparse(candidate)
            parsed.hostname  # noqa: B018 — also validates the netloc
            return parsed
        except ValueError:
            continue
    return None


def url_key(url: str) -> str:
    """De-duplication key: host (no www.) + path + query, ignoring scheme and host case."""
    parsed = safe_urlparse(url if "://" in url else "http://" + url)
    if parsed is None:
        return url.lower()
    host = (parsed.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host + parsed.path.rstrip("/") + (("?" + parsed.query) if parsed.query else "")


def defang_text(text: str) -> str:
    """Turn defanged links ("hxxps://evil[.]com") back into plain URLs before matching."""
    for pattern, repl in _DEFANG_TEXT_FIXES:
        text = pattern.sub(repl, text)
    return text


def _normalize_candidate(raw: str) -> str | None:
    candidate = undfang(raw)
    if not candidate:
        return None
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    if "://" not in candidate and re.match(r"^[^\W_][\w.\-]*\.[^\W\d_]{2,}", candidate):
        candidate = "http://" + candidate
    # Drop trailing junk that regex may have included.
    candidate = strip_trailing_punctuation(candidate)
    parsed = safe_urlparse(candidate)
    if parsed is None or (not parsed.netloc and not parsed.path):
        return None
    return candidate


def _valid_bare_match(match: re.Match) -> bool:
    tld_raw = match.group("tld")
    tld = tld_raw.lower()
    if tld not in (load_tlds() or _FALLBACK_TLDS):
        return False
    if tld in _FILE_LIKE_TLDS and not match.group("path"):
        return False
    # "account.Click here" is a sentence with a missing space, not a domain.
    return tld_raw.islower() or match.group("host").isupper()


def extract_urls(text: str) -> list[str]:
    """Extract and normalize URLs / bare domains from OCR or QR text."""
    if not text:
        return []
    prepared = rejoin_broken_urls(defang_text(text))
    found: list[str] = []
    seen: set[str] = set()
    spans: list[tuple[int, int]] = []

    def add(raw: str) -> None:
        norm = _normalize_candidate(raw)
        if norm and url_key(norm) not in seen:
            seen.add(url_key(norm))
            found.append(norm)

    for match in _URL_RE.finditer(prepared):
        spans.append(match.span())
        add(match.group(0))

    for match in _BARE_DOMAIN_RE.finditer(prepared):
        # Skip hosts that are part of a full URL already found above.
        if any(start <= match.start() < end for start, end in spans):
            continue
        if _valid_bare_match(match):
            add(match.group(0))

    return found


_EMAIL_RE = re.compile(r"(?<![\w.+\-])[\w.+\-]+@(?P<domain>(?:[^\W_][\w\-]*\.)+(?P<tld>[^\W\d_]{2,24}))(?![\w\-])")


def extract_email_domains(text: str) -> list[str]:
    """
    Domains of e-mail addresses in the text (sender lines, "reply to" addresses).

    A spoofed sender such as service@paypa1-security.com is as telling as a link.
    UPI ids (name@ybl) have no dot after the @ and are not matched.
    """
    domains: list[str] = []
    for match in _EMAIL_RE.finditer(text or ""):
        domain = match.group("domain").lower().rstrip(".")
        if match.group("tld").lower() in (load_tlds() or _FALLBACK_TLDS) and domain not in domains:
            domains.append(domain)
    return domains


def urls_from_qr_payloads(payloads: list[str]) -> list[str]:
    """URLs carried by QR payloads: links with or without a scheme, plus URLs embedded in other data."""
    urls: list[str] = []
    for p in payloads:
        low = p.strip().lower()
        if low.startswith(("http://", "https://", "hxxp://", "hxxps://", "www.")):
            # Keep the raw payload if it cannot be cleaned; URL analysis flags it as malformed.
            urls.append(_normalize_candidate(defang_text(p.strip())) or p.strip())
        else:
            urls.extend(extract_urls(p))
    return urls

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



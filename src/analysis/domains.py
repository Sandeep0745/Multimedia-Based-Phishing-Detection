"""Hostname helpers shared by the URL and text analysis: registrable domain (eTLD+1), IP hosts."""

from __future__ import annotations

import ipaddress

from src.core.config import load_public_suffixes

# Fallback multi-part suffixes, used only if data/config/public_suffix_list.dat is missing.
_MULTI_SUFFIXES = {
    "co.uk",
    "com.au",
    "co.jp",
    "com.br",
    "co.in",
    "com.mx",
    "co.za",
    "com.sg",
}


def _public_suffix(labels: list[str]) -> str | None:
    """Longest matching ICANN public suffix for the host labels, or None without the list."""
    rules, wildcards, exceptions = load_public_suffixes()
    if not rules:
        return None
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1:])
        if candidate in rules:
            return candidate
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wildcards:
            return candidate
    return labels[-1]  # Default rule "*": the TLD itself.


def is_ip_host(host: str) -> bool:
    host = host.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    """
    The part of a hostname its owner registered (eTLD+1), computed offline.

    Uses the Public Suffix List (ICANN section), so "x.gov.in" -> "x.gov.in" and
    "a.b.co.uk" -> "b.co.uk". Falls back to a small built-in table without the list.
    """
    host = host.lower().rstrip(".").split(":")[0]
    if not host:
        return ""
    if is_ip_host(host):
        return host
    parts = host.split(".")
    if len(parts) < 2:
        return host
    suffix = _public_suffix(parts)
    if suffix is not None:
        n = suffix.count(".") + 1
        return ".".join(parts[-(n + 1):]) if len(parts) > n else host
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two

#!/usr/bin/env python3
from __future__ import annotations

from typing import List, Tuple
from urllib.parse import urlparse
import re

TRUSTED_EXACT_DOMAINS = {
    "mozilla.org", "wikipedia.org", "wikimedia.org",
    "stackoverflow.com", "stackexchange.com",
    "virustotal.com", "hybrid-analysis.com", "urlscan.io",
    "shodan.io", "securitytrails.com",
}

TRUSTED_SUFFIXES = [
    "github.io", "gitlab.io", "gitbook.io",
    "netlify.app", "vercel.app", "herokuapp.com",
    "azurewebsites.net", "amazonaws.com", "cloudfront.net",
    "firebaseapp.com", "web.app", "appspot.com",
]

HIGH_TRUST_TLD_SUFFIXES = [
    "edu", "edu.vn", "edu.au", "edu.uk", "ac.uk", "ac.jp",
    "gov", "gov.uk", "gov.au", "gov.vn", "mil",
]

LEGITIMATE_NEW_TLDS = {".dev", ".app", ".io", ".tech", ".ai", ".co"}
CONTEXT_SUBDOMAINS = {"lab", "dev", "test", "staging", "demo"}
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account", "update",
    "confirm", "password", "signin", "banking"
}

PUNYCODE_PREFIX = "xn--"
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _normalize(url: str) -> Tuple[str, str]:
    p = urlparse(url)
    return (p.scheme or "").lower(), (p.hostname or "").lower().strip(".")


def _is_ipv4(host: str) -> bool:
    if not host or not IPV4_RE.match(host):
        return False
    try:
        return all(0 <= int(x) <= 255 for x in host.split("."))
    except ValueError:
        return False


def _strong_signals(url: str, host: str) -> bool:
    u = url.lower()
    return (
        any(k in u for k in SUSPICIOUS_KEYWORDS)
        or (PUNYCODE_PREFIX in host)
        or _is_ipv4(host)
        or (host.count("-") >= 4)
    )


def _endswith_domain(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith("." + suffix)


def check_trusted_pattern(url: str) -> Tuple[bool, str]:
    _, host = _normalize(url)
    if not host or _strong_signals(url, host):
        return False, ""

    if host in TRUSTED_EXACT_DOMAINS:
        return True, "trusted_exact_domain"

    for suf in TRUSTED_SUFFIXES:
        if _endswith_domain(host, suf):
            return True, f"trusted_platform_suffix:{suf}"

    for suf in HIGH_TRUST_TLD_SUFFIXES:
        if _endswith_domain(host, suf):
            return True, f"trusted_high_trust_suffix:{suf}"

    return False, ""


def adjust_score_for_context(url: str, base_score: float) -> Tuple[float, List[str]]:
    scheme, host = _normalize(url)
    adjusted = float(base_score)
    reasons: List[str] = []
    if not host:
        return max(0.0, min(1.0, adjusted)), reasons

    strong = _strong_signals(url, host)

    trusted, why = check_trusted_pattern(url)
    if trusted:
        adjusted *= 0.65
        reasons.append(why)

    if scheme == "https":
        adjusted *= 0.97
        reasons.append("has_https")

    if not strong:
        parts = host.split(".")
        if len(parts) > 2 and parts[0] in CONTEXT_SUBDOMAINS:
            adjusted *= 0.92
            reasons.append(f"legitimate_subdomain:{parts[0]}")

        for tld in LEGITIMATE_NEW_TLDS:
            if host.endswith(tld):
                adjusted *= 0.95
                reasons.append(f"legitimate_tld:{tld}")
                break

    if not any(k in url.lower() for k in SUSPICIOUS_KEYWORDS):
        adjusted *= 0.95
        reasons.append("no_suspicious_keywords")

    adjusted = max(0.0, min(1.0, adjusted))
    return adjusted, reasons


def should_whitelist_automatically(url: str) -> Tuple[bool, str]:
    return check_trusted_pattern(url)

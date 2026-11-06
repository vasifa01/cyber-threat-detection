"""Hand-crafted lexical URL features.

These are explainable signals (shown to the user as "indicators") and are
also fed to the URL model next to character n-grams.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "bank",
    "confirm", "password", "paypal", "webscr", "ebayisapi", "free", "lucky",
    "bonus", "wallet",
)
SUSPICIOUS_TLDS = (
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".ru", ".cn",
    ".info", ".biz",
)
EXECUTABLE_EXTENSIONS = (
    ".exe", ".apk", ".scr", ".bat", ".msi", ".jar", ".dll", ".bin", ".vbs",
    ".ps1", ".sh", ".dmg", ".zip", ".rar", ".7z",
)
_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "num_dots", "num_hyphens",
    "num_at", "num_question", "num_equals", "num_slashes", "digit_ratio",
    "has_ip_host", "has_https", "num_subdomains", "suspicious_word_count",
    "has_suspicious_tld", "has_executable_ext", "entropy",
]


def _parse(url: str):
    candidate = url if "://" in url else f"http://{url}"
    try:
        return urlparse(candidate)
    except ValueError:
        return urlparse("http://invalid")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def extract(url: str) -> dict:
    """Return a dict of named numeric features for a single URL."""
    url = (url or "").strip()
    lower = url.lower()
    parsed = _parse(lower)
    host = parsed.hostname or ""
    path = parsed.path or ""
    digits = sum(ch.isdigit() for ch in url)
    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_slashes": url.count("/"),
        "digit_ratio": digits / len(url) if url else 0.0,
        "has_ip_host": int(bool(_IP_HOST.match(host))),
        "has_https": int(lower.startswith("https://")),
        "num_subdomains": max(host.count(".") - 1, 0),
        "suspicious_word_count": sum(w in lower for w in SUSPICIOUS_WORDS),
        "has_suspicious_tld": int(host.endswith(SUSPICIOUS_TLDS)),
        "has_executable_ext": int(path.endswith(EXECUTABLE_EXTENSIONS)),
        "entropy": round(_entropy(lower), 4),
    }


def extract_matrix(urls) -> list:
    """Vectorised form used inside the sklearn pipeline (FunctionTransformer)."""
    series = urls.iloc[:, 0] if hasattr(urls, "iloc") and urls.ndim == 2 else urls
    return [[extract(str(u))[name] for name in FEATURE_NAMES] for u in series]


def malicious_subtype(url: str) -> str:
    """Rule-based split of a malicious URL into Malware vs Phishing.

    The public training set only labels URLs good/bad, so the subtype is
    decided by explainable rules: links to executables/archives are treated
    as malware delivery, everything else as phishing.
    """
    return "Malware" if extract(url)["has_executable_ext"] else "Phishing"

"""URL 전처리 및 피처 추출 — 학습 파이프라인과 동일한 26개 피처 생성"""

import math
import re
from urllib.parse import urlsplit, urlunsplit

import numpy as np
import pandas as pd

# ═══════════════════════════════════════════════════════════════
#  피처 컬럼 정의 (학습 시 사용된 순서 그대로)
# ═══════════════════════════════════════════════════════════════

FEATURE_COLUMNS = [
    "url_length", "num_dots", "num_hyphens", "num_slashes",
    "num_digits", "ratio_digits", "ratio_special_chars",
    "path_length", "has_at_symbol",
    "has_double_slash_anomaly", "ratio_url_encoded",
    "num_subdomains", "has_ip_address", "domain_length", "domain_entropy",
    "contains_login", "contains_verify", "contains_account",
    "contains_secure", "contains_update", "contains_bank",
    "contains_confirm", "contains_password",
    "suspicious_tld", "brand_similarity", "is_shortened_url",
]


# ═══════════════════════════════════════════════════════════════
#  URL 전처리 (정규화 · 검증)
# ═══════════════════════════════════════════════════════════════

def _has_garbage_whitespace(url: str) -> bool:
    return any(ch in url for ch in [" ", "\t", "\n", "\r"])


def _parse_and_validate_url(url: str) -> str | None:
    if not isinstance(url, str):
        return None

    url = url.strip()
    if url == "" or _has_garbage_whitespace(url):
        return None

    candidate = url
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parts = urlsplit(candidate)
    except Exception:
        return None

    if not parts.scheme or not parts.netloc:
        return None

    hostname = parts.hostname
    if hostname is None:
        return None

    host = hostname.strip()
    if host == "" or ("." not in host and host.lower() != "localhost"):
        return None

    host_lower = host.lower()

    try:
        port = parts.port
    except ValueError:
        return None

    if port is not None:
        netloc = f"{host_lower}:{port}"
    else:
        netloc = host_lower

    if parts.username is not None:
        userinfo = parts.username
        if parts.password is not None:
            userinfo += f":{parts.password}"
        netloc = f"{userinfo}@{netloc}"

    return urlunsplit((
        parts.scheme.lower(),
        netloc,
        parts.path,
        parts.query,
        parts.fragment,
    ))


def _normalize_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except Exception:
        return None

    if not parts.scheme or not parts.netloc:
        return None

    hostname = parts.hostname
    if hostname is None:
        return None

    host = hostname.lower()

    try:
        port = parts.port
    except ValueError:
        return None

    if port is not None:
        if (parts.scheme.lower() == "http" and port == 80) or \
           (parts.scheme.lower() == "https" and port == 443):
            netloc = host
        else:
            netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parts.path
    if path not in ["", "/"]:
        path = path.rstrip("/")
        if path == "":
            path = "/"

    return urlunsplit((
        parts.scheme.lower(),
        netloc,
        path,
        parts.query,
        parts.fragment,
    ))


def preprocess_url(url: str) -> str | None:
    """URL 검증 + 정규화. 유효하지 않으면 None 반환."""
    parsed = _parse_and_validate_url(url)
    if parsed is None:
        return None
    return _normalize_url(parsed)


# ═══════════════════════════════════════════════════════════════
#  피처 추출 헬퍼 함수
# ═══════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _is_ip(domain: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None


def _count_subdomains(domain: str) -> int:
    if not domain:
        return 0
    parts = domain.split(".")
    return len(parts) - 2 if len(parts) > 2 else 0


_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "cutt.ly", "tiny.cc",
])


def _has_shortener(domain: str) -> int:
    if not domain:
        return 0
    domain = domain.lower()
    return int(any(domain == s or domain.endswith("." + s) for s in _SHORTENERS))


_SUSPICIOUS_TLDS = frozenset(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"])


def _suspicious_tld(domain: str) -> int:
    if not domain or "." not in domain:
        return 0
    tld = domain.split(".")[-1].lower()
    return int(tld in _SUSPICIOUS_TLDS)


def _levenshtein(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    dp = np.zeros((len(a) + 1, len(b) + 1), dtype=int)

    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost,
            )
    return dp[len(a)][len(b)]


_BRANDS = ["google", "facebook", "apple", "amazon", "paypal", "bank", "microsoft"]


def _brand_similarity(domain: str) -> int:
    if not domain:
        return 999
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    scores = [_levenshtein(domain, b) for b in _BRANDS]
    return min(scores)


# ═══════════════════════════════════════════════════════════════
#  메인 피처 추출 함수
# ═══════════════════════════════════════════════════════════════

def extract_features(url: str) -> pd.DataFrame:
    """
    URL 문자열 → 26개 피처 DataFrame (shape: 1×26).
    학습 파이프라인의 extract_features_from_url과 동일한 출력.

    Raises:
        ValueError: URL이 유효하지 않을 경우
    """
    normalized_url = preprocess_url(url)
    if normalized_url is None:
        raise ValueError(f"Invalid or malformed URL: {url}")

    parts = urlsplit(normalized_url)

    domain = parts.hostname if parts.hostname else ""
    path = parts.path if parts.path else ""

    full_url = str(normalized_url)
    lower_url = full_url.lower()

    url_length = len(full_url)
    num_dots = full_url.count(".")
    num_hyphens = full_url.count("-")
    num_slashes = full_url.count("/")
    num_digits = sum(c.isdigit() for c in full_url)
    ratio_digits = num_digits / url_length if url_length > 0 else 0
    special_chars = len(re.findall(r"[^a-zA-Z0-9]", full_url))
    ratio_special_chars = special_chars / url_length if url_length > 0 else 0
    path_length = len(path)
    has_at_symbol = int("@" in full_url)

    has_double_slash_anomaly = int(full_url.count("//") > 1)
    encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
    ratio_url_encoded = encoded_chars / url_length if url_length > 0 else 0

    num_subdomains = _count_subdomains(domain)
    has_ip_address = int(_is_ip(domain))
    domain_length = len(domain)
    domain_entropy = _shannon_entropy(domain)

    contains_login = int("login" in lower_url)
    contains_verify = int("verify" in lower_url)
    contains_account = int("account" in lower_url)
    contains_secure = int("secure" in lower_url)
    contains_update = int("update" in lower_url)
    contains_bank = int("bank" in lower_url)
    contains_confirm = int("confirm" in lower_url)
    contains_password = int("password" in lower_url)

    tld_flag = _suspicious_tld(domain)
    brand_sim = _brand_similarity(domain)
    short_flag = _has_shortener(domain)

    features = [[
        url_length, num_dots, num_hyphens, num_slashes,
        num_digits, ratio_digits, ratio_special_chars,
        path_length, has_at_symbol,
        has_double_slash_anomaly, ratio_url_encoded,
        num_subdomains, has_ip_address, domain_length, domain_entropy,
        contains_login, contains_verify, contains_account,
        contains_secure, contains_update, contains_bank,
        contains_confirm, contains_password,
        tld_flag, brand_sim, short_flag,
    ]]

    return pd.DataFrame(features, columns=FEATURE_COLUMNS)

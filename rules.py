# rules.py
"""
Simple deterministic rule engine used by predictor.
Returns a rule risk score (0-100) to be blended to final risk.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store", ".loan"}
BRAND_LIST = ["nike", "adidas", "asics", "apple", "samsung", "dhl", "fedex", "paypal", "zara", "amazon", "ebay"]

def detect_brand_impersonation(domain: str):
    domain = domain.lower()
    for brand in BRAND_LIST:
        if brand in domain and not domain.endswith(brand + ".com"):
            return True
    return False

def suspicious_tld(domain: str):
    domain = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False

def many_query_params(url: str):
    try:
        q = urlparse(url).query
        if not q:
            return False
        # count params
        return len(q.split("&")) >= 4
    except Exception:
        return False

def uses_ip(host: str):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

def detect_redirect_scams(url: str):
    u = (url or "").lower()
    return int("utm_" in u or "fbclid" in u or "gclid" in u or "ref=" in u)

def compute_rule_risk(url: str, features: dict = None):
    """
    Returns an integer 0-100 representing additional risk from rules.
    Heuristics:
      - suspicious tld -> +15
      - brand impersonation -> +25
      - many query params -> +10
      - uses IP -> +20
      - redirect params -> +10
    """
    risk = 0
    try:
        parsed = urlparse(url if url else (features.get("url", "") if features else ""))
        host = parsed.netloc.split(":")[0].lower()
    except Exception:
        host = ""

    if suspicious_tld(host):
        risk += 15
    if detect_brand_impersonation(host):
        risk += 25
    if many_query_params(url):
        risk += 10
    if uses_ip(host):
        risk += 20
    if detect_redirect_scams(url):
        risk += 10

    # clamp
    return min(100, risk)

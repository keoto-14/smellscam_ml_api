# rules.py
"""
Enterprise rule engine — stronger heuristics for SmellScam
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store", ".loan"}
BRAND_LIST = ["nike", "adidas", "asics", "apple", "samsung", "dhl", "fedex", "paypal", "zara", "amazon", "ebay"]

def detect_brand_impersonation(domain: str) -> bool:
    d = (domain or "").lower()
    for b in BRAND_LIST:
        if b in d and not d.endswith(b + ".com"):
            return True
    return False

def suspicious_tld(domain: str) -> bool:
    d = (domain or "").lower()
    for t in SUSPICIOUS_TLDS:
        if d.endswith(t):
            return True
    return False

def many_query_params(url: str) -> bool:
    try:
        q = urlparse(url).query
        return bool(q and len(q.split("&")) >= 4)
    except:
        return False

def uses_ip(host: str) -> bool:
    if not host:
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

def detect_redirect_scams(url: str) -> bool:
    u = (url or "").lower()
    return any(x in u for x in ["utm_", "fbclid", "gclid", "ref="])

def compute_rule_risk(url: str, features: dict = None) -> int:
    try:
        parsed = urlparse(url if url else (features.get("url", "") if features else ""))
        host = parsed.netloc.split(":")[0].lower()
    except:
        host = ""

    risk = 0
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

    return min(100, int(risk))

"""
url_feature_extractor.py — UNIFIED shopping detection (URL-only logic)
This version does NOT depend on HTML at all for shopping detection.
It detects ANY online shopping website using URL patterns only.
"""

import os
import re
import ssl
import time
import socket
import urllib.parse
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except:
    requests = None

try:
    from bs4 import BeautifulSoup
except:
    BeautifulSoup = None

try:
    import whois as pywhois
except:
    pywhois = None

try:
    import dns.resolver
except:
    dns = None

try:
    from simple_cache import cache_get, cache_set
except:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        if k not in _CACHE:
            return None
        ts, val = _CACHE[k]
        if time.time() - ts > max_age:
            return None
        return val

    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

VT_API_KEY = os.environ.get("VT_API_KEY")


def vt_scan_info(url):
    if not VT_API_KEY or requests is None:
        return (0, 0, 0.0)

    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.split(":")[0].lower()
    except:
        domain = url.lower().split(":")[0]

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key, max_age=7200)
    if cached:
        return cached["total"], cached["malicious"], cached["ratio"]

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            total = sum(stats.values())
            mal = stats.get("malicious", 0)
            ratio = mal / total if total else 0

            cache_set(cache_key, {
                "total": total,
                "malicious": mal,
                "ratio": ratio
            })

            return total, mal, ratio

    except:
        pass

    return (0, 0, 0.0)


def safe_request(url, timeout=6):
    if requests is None:
        return None
    try:
        return requests.get(url, timeout=timeout, verify=False).text
    except:
        return None


def safe_whois(host):
    if pywhois is None:
        return None
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, str):
            cd = datetime.fromisoformat(cd)
        return (datetime.utcnow() - cd).days
    except:
        return None


def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, 443), timeout=4)
        sock = ctx.wrap_socket(conn, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        return bool(cert)
    except:
        return None


def safe_quad9_blocked(host):
    if dns is None:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=2)
        return 0
    except:
        return 1


# -----------------------------------------------------------
# UNIVERSAL SHOPPING DETECTOR  — URL ONLY (VERY RELIABLE)
# -----------------------------------------------------------

SHOP_URL_KEYWORDS = [
    "product", "products", "item", "items",
    "shop", "store", "collections", "collection",
    "category", "categories",
    "cart", "checkout",
    "buy", "sale", "sku",
    "variant", "add-to-cart", "add_to_cart",
    "order", "bag"
]

def detect_shopping_url_only(url: str) -> bool:
    """Detect ANY online shopping website based on URL structure only."""
    url_l = url.lower()

    for key in SHOP_URL_KEYWORDS:
        if key in url_l:
            return True

    # If domain looks like a store (e.g., mystore.com)
    store_indicators = ["shop", "store", "boutique", "fashion", "outlet"]
    domain = urllib.parse.urlparse(url).netloc.lower()

    for kw in store_indicators:
        if kw in domain:
            return True

    return False



# -----------------------------------------------------------
# MAIN FEATURE EXTRACTOR (KEPT SAME)
# -----------------------------------------------------------
def extract_all_features(url):

    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path or "/"
    url_l = url.lower()

    f = {}

    # BASIC FEATURES — unchanged
    f["length_url"] = len(url)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in url)
    f["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login","verify","secure","bank","account","update","confirm","urgent","pay","gift","free","click","signin"
    ]))
    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_hash"] = url.count("#")
    f["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l)))
    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))
    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

    # lexical similarity
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common = set(tokens_host).intersection(tokens_path)
    f["domain_in_brand"] = int(bool(common))
    f["brand_in_path"] = int(bool(common))
    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))
    f["ratio_digits_url"] = (sum(c.isdigit() for c in url) / len(url)) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / len(host)) * 100

    # live features
    age = safe_whois(host)
    f["domain_age_days"] = age if age else 365

    ssl_ok = safe_ssl_valid(host)
    f["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    q9 = safe_quad9_blocked(host)
    f["quad9_blocked"] = int(q9) if q9 else 0

    vt_total, vt_mal, vt_ratio = vt_scan_info(url)
    f["vt_total_vendors"] = vt_total
    f["vt_malicious_count"] = vt_mal
    f["vt_detection_ratio"] = vt_ratio

    # do NOT depend on HTML for shopping identification anymore

    f["external_favicon"] = 0
    f["login_form"] = 0
    f["iframe_present"] = 0
    f["popup_window"] = 0
    f["right_click_disabled"] = 0
    f["empty_title"] = 0
    f["web_traffic"] = 100

    # -----------------------------------------------------------
    # FINAL: UNIVERSAL SHOPPING DETECTOR (URL ONLY)
    # -----------------------------------------------------------
    f["is_shopping"] = int(detect_shopping_url_only(url))

    # ensure all 40 keys exist
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars",
        "contains_scam_keyword","nb_at","nb_qm","nb_and","nb_underscore",
        "nb_tilde","nb_percent","nb_slash","nb_hash","shortening_service",
        "nb_www","ends_with_com","nb_subdomains","abnormal_subdomain","prefix_suffix",
        "path_extension_php","domain_in_brand","brand_in_path","char_repeat3",
        "ratio_digits_url","ratio_digits_host","ssl_valid","domain_age_days",
        "quad9_blocked","vt_total_vendors","vt_malicious_count","vt_detection_ratio",
        "external_favicon","login_form","iframe_present","popup_window",
        "right_click_disabled","empty_title","web_traffic","is_shopping"
    ]

    for k in expected:
        if k not in f:
            f[k] = 0

    return f

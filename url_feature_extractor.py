# url_feature_extractor.py
"""
SmellScam Optimized Feature Extractor v3
---------------------------------------
• 40 features (same order as model training)
• Fast + stable for production
• Safe network requests with fallbacks
• UNIVERSAL shopping detection (URL + HTML)
"""

import os
import re
import ssl
import time
import socket
import urllib.parse
from datetime import datetime

# Disable HTTPS warnings globally
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional imports ------------------------------------------------------------
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

# simple_cache (optional)
try:
    from simple_cache import cache_get, cache_set
except:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        if k not in _CACHE: return None
        ts, val = _CACHE[k]
        if time.time() - ts > max_age:
            return None
        return val

    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

# -----------------------------------------------------------------------------  
# VirusTotal Domain Lookup (cached)
# -----------------------------------------------------------------------------  
VT_API_KEY = os.environ.get("VT_API_KEY")

def vt_scan_info(url_or_host):
    if not VT_API_KEY or requests is None:
        return 0, 0, 0.0

    try:
        parsed = urllib.parse.urlparse(
            url_or_host if "://" in url_or_host else "http://" + url_or_host
        )
        domain = parsed.netloc.split(":")[0].lower()
    except:
        domain = url_or_host.lower().split(":")[0]

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key, max_age=3600)
    if cached:
        return cached["total"], cached["malicious"], cached["ratio"]

    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=5
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values())
            mal = stats.get("malicious", 0)
            ratio = mal / total if total else 0.0

            cache_set(cache_key, {
                "total": total,
                "malicious": mal,
                "ratio": ratio
            })
            return total, mal, ratio

    except:
        pass

    return 0, 0, 0.0

# -----------------------------------------------------------------------------  
# Safe HTML Fetch
# -----------------------------------------------------------------------------  
def safe_request(url, timeout=6, max_bytes=200000):
    if requests is None: return None
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (SmellScamBot)"},
            stream=True
        )
        data = b""
        for chunk in resp.iter_content(4096):
            if not chunk: break
            data += chunk
            if len(data) > max_bytes: break
        return data.decode(errors="ignore")
    except:
        return None

# -----------------------------------------------------------------------------  
# WHOIS / SSL / DNS
# -----------------------------------------------------------------------------  
def safe_whois(host):
    if pywhois is None: return None
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str):
            try: cd = datetime.fromisoformat(cd)
            except: return None
        if not cd: return None
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
    if dns is None: return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=2)
        return 0
    except:
        return 1

# -----------------------------------------------------------------------------  
# UNIVERSAL SHOPPING DETECTOR (URL + HTML)
# -----------------------------------------------------------------------------  
def detect_shopping_universal(url, soup, text):
    url_l = url.lower()
    score = 0

    # ---------------------------------------------------------
    # 1) URL-based detection (VERY strong)
    # ---------------------------------------------------------
    SHOP_URL_KEYWORDS = [
        "shop", "store", "product", "products", "collection", "collections",
        "category", "categories", "item", "items", "buy",
        "/en/", "/us/", "/uk/", "/sg/", "/my/", "/id/", "/ph/",
        "/cart", "/checkout"
    ]
    if any(k in url_l for k in SHOP_URL_KEYWORDS):
        score += 4

    # ---------------------------------------------------------
    # 2) Strong HTML signals
    # ---------------------------------------------------------
    STRONG_HTML = [
        "add to cart", "buy now", "checkout", "shopping cart",
        "add-to-cart", "add_to_cart", "place order"
    ]
    if any(k in text for k in STRONG_HTML):
        score += 4

    # ---------------------------------------------------------
    # 3) Weak HTML signals
    # ---------------------------------------------------------
    WEAK_HTML = [
        "price", "sale", "product", "products",
        "sku", "variant", "wishlist", "shop", "store"
    ]
    if any(k in text for k in WEAK_HTML):
        score += 2

    # ---------------------------------------------------------
    # 4) Price detection
    # ---------------------------------------------------------
    if re.search(r"(RM|\$|USD|EUR|SGD|IDR|PHP|MYR)\s?\d{1,7}", text):
        score += 3

    # ---------------------------------------------------------
    # 5) Ecommerce platforms
    # ---------------------------------------------------------
    ECOMMERCE = ["shopify", "woocommerce", "prestashop", "magento", "bigcommerce", "ecwid"]
    if any(p in text for p in ECOMMERCE):
        score += 4

    # Final decision
    return score >= 3

# -----------------------------------------------------------------------------  
# MAIN FEATURE EXTRACTOR (40 features)
# -----------------------------------------------------------------------------  
def extract_all_features(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path or "/"
    url_l = url.lower()

    f = {}

    # -----------------------------------------------------
    # Lexical features
    # -----------------------------------------------------
    f["length_url"] = len(url)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in url)

    f["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login","verify","secure","bank","account","update","confirm",
        "urgent","pay","gift","free","click","signin"
    ]))

    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_hash"] = url.count("#")

    f["shortening_service"] = int(bool(re.search(
        r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l)))

    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))

    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

    # lexical similarity
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common = set(t for t in tokens_host if len(t)>2).intersection(
        t for t in tokens_path if len(t)>2
    )
    f["domain_in_brand"] = int(bool(common))
    f["brand_in_path"] = int(bool(common))
    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))

    f["ratio_digits_url"] = (sum(c.isdigit() for c in url) / len(url)) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / len(host)) * 100

    # -----------------------------------------------------
    # Live features
    # -----------------------------------------------------
    age = safe_whois(host)
    f["domain_age_days"] = age if age is not None else 365

    ssl_ok = safe_ssl_valid(host)
    f["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    q9 = safe_quad9_blocked(host)
    f["quad9_blocked"] = 1 if q9 else 0

    vt_total, vt_mal, vt_ratio = vt_scan_info(url)
    f["vt_total_vendors"] = vt_total
    f["vt_malicious_count"] = vt_mal
    f["vt_detection_ratio"] = vt_ratio

    # -----------------------------------------------------
    # HTML-based features
    # -----------------------------------------------------
    html = safe_request(url)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None
    text = soup.get_text(" ", strip=True).lower() if soup else ""

    # favicon external
    def external_favicon():
        if not soup: return 0
        try:
            link = soup.find("link", rel=re.compile("icon", re.I))
            if not link: return 0
            href = link.get("href", "")
            if href.startswith("data:"): return 0
            p = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
            fav_host = p.netloc.split(":")[0]
            return 0 if fav_host.endswith(host) else 1
        except:
            return 0

    f["external_favicon"] = external_favicon()
    f["login_form"] = int(bool(soup and soup.find("input", {"type": "password"})))
    f["iframe_present"] = int(bool(soup and soup.find_all("iframe")))
    f["popup_window"] = int("popup" in text or "modal" in text)
    f["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())

    title = ""
    try:
        title = soup.title.string.strip() if soup and soup.title else ""
    except:
        pass
    f["empty_title"] = int(title == "")

    # text length scoring
    if text:
        wc = len(text.split())
        if wc > 2000: f["web_traffic"] = 1000
        elif wc > 500: f["web_traffic"] = 500
        elif wc > 100: f["web_traffic"] = 100
        else: f["web_traffic"] = 10
    else:
        f["web_traffic"] = 100

    # UNIVERSAL SHOPPING DETECTION
    f["is_shopping"] = int(detect_shopping_universal(url, soup, text))

    # -----------------------------------------------------
    # Ensure all expected keys exist
    # -----------------------------------------------------
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars",
        "contains_scam_keyword","nb_at","nb_qm","nb_and","nb_underscore",
        "nb_tilde","nb_percent","nb_slash","nb_hash","shortening_service",
        "nb_www","ends_with_com","nb_subdomains","abnormal_subdomain","prefix_suffix",
        "path_extension_php","domain_in_bra

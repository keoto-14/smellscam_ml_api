# url_feature_extractor.py
"""
Improved 40-feature extractor + universal shopping-site detector.
Only shopping detection was updated — everything else remains unchanged.
"""

import os
import re
import socket
import ssl
import urllib.parse
import time
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# optional helpers
try:
    import requests
except Exception:
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import dns.resolver
except Exception:
    dns = None

# try simple_cache if present
try:
    from simple_cache import cache_get, cache_set
except Exception:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        if k not in _CACHE: return None
        ts, val = _CACHE[k]
        if time.time() - ts > max_age:
            return None
        return val
    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)


VT_API_KEY = os.environ.get("VT_API_KEY")

def safe_request(url, timeout=6, verify=False, max_bytes=200000):
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout, verify=verify,
                         headers={"User-Agent": "Mozilla/5.0 (smellscam)"},
                         stream=True)
        content = b""
        for chunk in r.iter_content(chunk_size=4096):
            if not chunk:
                break
            content += chunk
            if len(content) > max_bytes:
                break
        return content.decode(errors="ignore")
    except Exception:
        return None

def safe_whois(host):
    if pywhois is None:
        return None
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str):
            try:
                cd = datetime.fromisoformat(cd)
            except Exception:
                cd = None
        if not cd: return None
        return max(0, (datetime.utcnow() - cd).days)
    except Exception:
        return None

def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, 443), timeout=5)
        sock = ctx.wrap_socket(conn, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        return bool(cert)
    except Exception:
        return None

def safe_quad9_blocked(host):
    if dns is None:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=3)
        return 0
    except Exception:
        return 1

def vt_scan_info(url_or_host):
    if not VT_API_KEY or requests is None:
        return 0,0,0.0
    try:
        parsed = urllib.parse.urlparse(url_or_host if "://" in url_or_host else "http://" + url_or_host)
        domain = (parsed.netloc or url_or_host).split(":")[0].lower()
    except Exception:
        domain = url_or_host.lower().split(":")[0]
    cache_key = f"vt_domain::{domain}"
    cached = cache_get(cache_key, max_age=3600)
    if cached:
        return cached["total"], cached["malicious"], cached["ratio"]
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=6)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                ratio = malicious / total if total>0 else 0.0
                cache_set(cache_key, {"total": total, "malicious": malicious, "ratio": ratio})
                return total, malicious, ratio
    except Exception:
        pass
    return 0,0,0.0



# ------------------------------------------------------------------------
# NEW — UNIVERSAL SHOPPING DETECTOR (fixes Shopee, Lazada, Shopify, etc.)
# ------------------------------------------------------------------------

PRICE_RE = re.compile(r"(rm|\$|usd|eur|€|£)\s?\d{1,5}", re.I)

URL_KEYWORDS = [
    "product", "products", "shop", "store", "cart", "checkout",
    "item", "sku", "goods", "sale", "category", "collections",
    "add-to-cart", "buy", "basket", "detail"
]

HTML_KEYWORDS = [
    "add to cart", "add-to-cart", "buy now", "checkout",
    "price", "sale", "shipping", "quantity", "order now",
    "variant", "color", "size", "wishlist"
]


def detect_shopping(url, soup, text):
    """Universal shopping detector (no whitelist required)."""
    score = 0

    url_l = url.lower()
    text_l = text.lower() if text else ""

    # URL-only detection
    if any(k in url_l for k in URL_KEYWORDS):
        score += 2
    if re.search(r"/(product|products|shop|store|item|goods)/", url_l):
        score += 2
    if any(p in url_l for p in ["price=", "amount=", "sku=", "variant="]):
        score += 1

    # price in HTML text
    if PRICE_RE.search(text_l):
        score += 2

    # HTML keyword detection
    if any(k in text_l for k in HTML_KEYWORDS):
        score += 2

    # HTML structure
    if soup:
        og = soup.find("meta", property="og:type")
        if og and "product" in (og.get("content") or "").lower():
            score += 3

        if soup.find(attrs={"itemtype": re.compile("Product", re.I)}):
            score += 3

        classes = " ".join(
            c for t in soup.find_all(True) for c in (t.get("class") or [])
        ).lower()

        if any(c in classes for c in ["product", "price", "cart", "add-to-cart"]):
            score += 2

    return score >= 3



# ------------------------------------------------------------------------
# MAIN FEATURE EXTRACTOR (unchanged)
# ------------------------------------------------------------------------

def extract_all_features(url):
    url_l = url.lower()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path or "/"

    f = {}

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

    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(
        t for t in tokens_path if len(t) > 2
    )
    f["domain_in_brand"] = int(bool(common_tokens))
    f["brand_in_path"] = int(bool(common_tokens))
    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))

    f["ratio_digits_url"] = (sum(c.isdigit() for c in url) / max(1, len(url))) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    age = safe_whois(host)
    f["domain_age_days"] = age if age is not None else 365

    ssl_ok = safe_ssl_valid(host)
    f["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    q9 = safe_quad9_blocked(host)
    f["quad9_blocked"] = int(q9) if q9 is not None else 0

    vt_total, vt_mal, vt_ratio = vt_scan_info(url)
    f["vt_total_vendors"] = vt_total
    f["vt_malicious_count"] = vt_mal
    f["vt_detection_ratio"] = vt_ratio

    html = safe_request(url, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None
    body = soup.get_text(" ", strip=True).lower() if soup else ""

    def external_favicon():
        if not soup:
            return 0
        try:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            if not link: return 0
            href = link.get("href","")
            if href.startswith("data:"): return 0
            parsed2 = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
            fav_host = parsed2.netloc.split(":")[0]
            return 0 if fav_host.endswith(host) else 1
        except Exception:
            return 0

    f["external_favicon"] = external_favicon()

    if soup:
        login = 0
        for form in soup.find_all("form"):
            inputs = [i.get("type","").lower() for i in form.find_all("input")]
            if "password" in inputs or "login" in form.text.lower():
                login = 1
                break
        f["login_form"] = login
    else:
        f["login_form"] = 0

    f["iframe_present"] = int(bool(soup.find_all("iframe"))) if soup else 0
    f["popup_window"] = int("popup" in (body or "") or "modal" in (body or ""))
    f["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())

    try:
        title = soup.title.string.strip() if soup and soup.title else ""
        f["empty_title"] = int(title == "")
    except Exception:
        f["empty_title"] = 0

    if body:
        wc = len(re.findall(r"\w+", body))
        if wc > 2000:
            f["web_traffic"] = 1000
        elif wc > 500:
            f["web_traffic"] = 500
        elif wc > 100:
            f["web_traffic"] = 100
        else:
            f["web_traffic"] = 10
    else:
        f["web_traffic"] = 100

    # FIXED SHOPPING DETECTOR HERE
    f["is_shopping"] = int(detect_shopping(url, soup, body))

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

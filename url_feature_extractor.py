# url_feature_extractor.py
"""
Extractor with correct 40 features + improved shopping detection.
"""

import os, re, ssl, socket, urllib.parse, time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# optional imports
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

# optional cache
try:
    from simple_cache import cache_get, cache_set
except:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        v = _CACHE.get(k)
        if not v:
            return None
        ts, val = v
        if time.time() - ts > max_age:
            return None
        return val
    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

VT_API_KEY = os.environ.get("VT_API_KEY")

# --------------------------------------------------------
# Helpers
# --------------------------------------------------------
def safe_request(url, timeout=6, max_bytes=150000):
    if not requests:
        return None
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (smellscam)"},
                         stream=True)
        data = b""
        for chunk in r.iter_content(4096):
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                break
        return data.decode(errors="ignore")
    except:
        return None

def safe_whois(host):
    if not pywhois:
        return None
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, str):
            try:
                cd = datetime.fromisoformat(cd)
            except:
                cd = None
        if not cd:
            return None
        return (datetime.utcnow() - cd).days
    except:
        return None

def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, 443), timeout=4)
        sock = ctx.wrap_socket(conn, server_hostname=host)
        sock.getpeercert()
        sock.close()
        return 1
    except:
        return None

def safe_quad9_blocked(host):
    if not dns:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=2)
        return 0
    except:
        return 1

def vt_scan_info(host):
    if not VT_API_KEY or not requests:
        return 0,0,0.0

    cache_key = f"vt::{host}"
    cached = cache_get(cache_key)
    if cached:
        return cached["total"], cached["mal"], cached["ratio"]

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{host}",
            headers={"x-apikey": VT_API_KEY},
            timeout=6,
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            total = sum(stats.values())
            mal = stats.get("malicious", 0)
            ratio = mal / total if total > 0 else 0.0
            cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
            return total, mal, ratio
    except:
        pass

    return 0,0,0.0

# --------------------------------------------------------
# Shopping detection
# --------------------------------------------------------
SHOP_URL_KEYWORDS = [
    "product","products","item","items","shop","store","collections",
    "category","cart","checkout","buy","sale","sku","variant","order"
]

ECOMMERCE_DOMAINS = [
    "shop","store","boutique","outlet","market","shopify",
    "woocommerce","magento","prestashop","bigcommerce","wix"
]

def detect_shopping(url, host, soup, body):
    url_l = url.lower()
    host_l = host.lower()
    body_l = (body or "").lower()

    # URL keywords
    if any(k in url_l for k in SHOP_URL_KEYWORDS):
        return True

    # domain indicators
    if any(k in host_l for k in ECOMMERCE_DOMAINS):
        return True

    if not soup:
        return False

    # HTML indicators
    has_price = bool(re.search(r"(rm|\$|usd|€|£)\s?\d", body_l))
    has_cart = any(k in body_l for k in ["add to cart","buy now","checkout","cart"])

    has_schema = False
    for tag in soup.find_all("script", type="application/ld+json"):
        txt = tag.string or ""
        if '"Product"' in txt:
            has_schema = True
            break

    return has_price or has_cart or has_schema

# --------------------------------------------------------
# Main feature extractor
# --------------------------------------------------------
def extract_all_features(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0]
    path = parsed.path or "/"
    url_l = url.lower()

    f = {}

    # lexical features
    f["length_url"] = len(url)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in url)

    f["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login","verify","bank","secure","account","confirm","urgent"
    ]))

    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_hash"] = url.count("#")

    f["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl)", url_l)))
    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))
    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

    # token similarity
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common = set(t for t in tokens_host if len(t) > 2).intersection(
        t for t in tokens_path if len(t) > 2
    )
    f["domain_in_brand"] = int(bool(common))
    f["brand_in_path"] = int(bool(common))

    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))

    f["ratio_digits_url"] = (sum(c.isdigit() for c in url) / max(1, len(url))) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # WHOIS / SSL / Quad9 / VT
    age = safe_whois(host)
    f["domain_age_days"] = age if age is not None else 365

    ssl_ok = safe_ssl_valid(host)
    f["ssl_valid"] = 1 if ssl_ok else 0

    q9 = safe_quad9_blocked(host)
    f["quad9_blocked"] = q9 if q9 is not None else 0

    vt_total, vt_mal, vt_ratio = vt_scan_info(host)
    f["vt_total_vendors"] = vt_total
    f["vt_malicious_count"] = vt_mal
    f["vt_detection_ratio"] = vt_ratio

    # HTML
    html = safe_request(url)
    soup = BeautifulSoup(html, "html.parser") if (html and BeautifulSoup) else None
    body = soup.get_text(" ", strip=True) if soup else ""

    def favicon_external():
        if not soup:
            return 0
        try:
            link = soup.find("link

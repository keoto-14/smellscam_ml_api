"""
New extractor (40 features) — rewritten as requested.
- Produces the exact 40 features expected by your models (names must match features.pkl)
- Shopping detection: URL-first (robust for JS-heavy or blocked sites) with optional HTML fallback
- Minimal external dependencies (requests optional, BeautifulSoup optional)
"""

import os
import re
import ssl
import socket
import urllib.parse
import time
from datetime import datetime

# silence InsecureRequestWarning when verify=False is used in requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# optional file cache (keeps behavior if simple_cache exists)
try:
    from simple_cache import cache_get, cache_set
except Exception:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        v = _CACHE.get(k)
        if not v: return None
        ts, val = v
        if time.time() - ts > max_age:
            return None
        return val
    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

VT_API_KEY = os.environ.get("VT_API_KEY")

# -------------------------
# Helpers
# -------------------------
def safe_request(url, timeout=6, max_bytes=200000):
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers={"User-Agent": "Mozilla/5.0 (smellscam)"}, stream=True, allow_redirects=True)
        data = b""
        for chunk in r.iter_content(4096):
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                break
        return data.decode(errors="ignore")
    except Exception:
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
            try:
                cd = datetime.fromisoformat(cd)
            except:
                cd = None
        if not cd:
            return None
        return max(0, (datetime.utcnow() - cd).days)
    except Exception:
        return None

def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, 443), timeout=4)
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
        r.resolve(host, "A", lifetime=2)
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

# URL-only shopping detector (robust)
SHOP_URL_KEYWORDS = [
    "product", "products", "item", "items",
    "shop", "store", "collections", "collection",
    "category", "categories", "cart", "checkout",
    "buy", "sale", "sku", "variant",
    "add-to-cart", "add_to_cart", "order", "bag"
]

PLATFORM_INDICATORS = ["shopify", "woocommerce", "magento", "bigcommerce", "prestashop", "wix", "squareup"]

def detect_shopping_url_only(url: str) -> bool:
    u = url.lower()
    for k in SHOP_URL_KEYWORDS:
        if k in u:
            return True
    # domain-level hint
    domain = urllib.parse.urlparse(url).netloc.lower()
    for p in ["shop", "store", "boutique", "outlet", "market"]:
        if p in domain:
            return True
    for p in PLATFORM_INDICATORS:
        if p in url.lower():
            return True
    return False

def detect_shopping_from_html(soup, body):
    # optional HTML fallback: price + add-to-cart + product schema
    score = 0
    txt = (body or "").lower()
    if re.search(r"(\$|€|£|rm|usd)\s?\d", txt):
        score += 2
    if any(k in txt for k in ["add to cart", "buy now", "checkout", "add-to-cart"]):
        score += 3
    try:
        if soup:
            for tag in soup.find_all("script", type="application/ld+json"):
                try:
                    s = tag.string or ""
                    if '"@type"' in s and '"Product"' in s:
                        score += 4
                        break
                except:
                    pass
    except:
        pass
    return score >= 3

# Main extractor
def extract_all_features(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path or "/"
    url_l = url.lower()

    f = {}
    # lexical
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

    # live features
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

    # HTML features
    html = None
    soup = None
    if requests is not None and BeautifulSoup is not None:
        try:
            html = safe_request(url)
            if html:
                soup = BeautifulSoup(html, "html.parser")
        except Exception:
            html = None
            soup = None

    def external_favicon():
        if not soup:
            return 0
        try:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            if not link:
                return 0
            href = link.get("href", "")
            if href.startswith("data:"):
                return 0
            p = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
            fav_host = p.netloc.split(":")[0]
            return 0 if fav_host.endswith(host) else 1
        except:
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
        f["iframe_present"] = int(bool(soup.find_all("iframe")))
        body = soup.get_text(" ", strip=True).lower()
    else:
        f["login_form"] = 0
        f["iframe_present"] = 0
        body = ""

    f["popup_window"] = int(any(k in (body or "") for k in ["popup","modal","cookie","overlay","subscribe"]))
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

    # -----------------------------------
    # Shopping detection: URL-first
    # -----------------------------------
    is_shop = detect_shopping_url_only(url)
    if not is_shop and soup:
        try:
            if detect_shopping_from_html(soup, body):
                is_shop = True
        except Exception:
            pass

    f["is_shopping"] = int(is_shop)

    # ----------------------------------------------------
    # UNIVERSAL SHOPPING FALLBACK (no brand list needed)
    # ----------------------------------------------------
    if f["is_shopping"] == 0:
        domain_is_old = f["domain_age_days"] >= 180
        ssl_ok = f["ssl_valid"] == 1
        path_depth = parsed.path.count("/") >= 2
        traffic_ok = f["web_traffic"] >= 100

        score = 0
        for cond in (domain_is_old, ssl_ok, path_depth, traffic_ok):
            score += 1 if cond else 0

        if score >= 3:
            f["is_shopping"] = 1

    # ensure expected keys (40 features)
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
            if k in ("ssl_valid","shortening_service","nb_www","path_extension_php",
                     "domain_in_brand","brand_in_path","char_repeat3","external_favicon",
                     "login_form","iframe_present","popup_window","right_click_disabled",
                     "empty_title","is_shopping"):
                f[k] = 0
            elif k == "domain_age_days":
                f[k] = 365
            elif k == "web_traffic":
                f[k] = 100
            elif k in ("vt_total_vendors","vt_malicious_count"):
                f[k] = 0
            elif k in ("vt_detection_ratio","ratio_digits_url","ratio_digits_host"):
                f[k] = 0.0
            else:
                f[k] = 0

    return f

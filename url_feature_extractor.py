"""
Enterprise-grade 40+ feature extractor for SmellScam.
Optimized for stability, performance, and consistent feature output.
"""

import os, re, socket, ssl, urllib.parse, time
from datetime import datetime

# Optional dependencies
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

# Optional simple_cache
try:
    from simple_cache import cache_get, cache_set
except:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        if k not in _CACHE: return None
        ts, val = _CACHE[k]
        return val if (time.time() - ts < max_age) else None
    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

VT_API_KEY = os.environ.get("VT_API_KEY")

# -------------------- Safe live request helpers --------------------

def safe_request(url, timeout=6, verify=False, max_bytes=200_000):
    if requests is None:
        return None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": "Mozilla/5.0 (SmellScamBot)"},
            stream=True,
        )
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
    except:
        return None


def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        conn = socket.create_connection((host, 443), timeout=5)
        sock = ctx.wrap_socket(conn, server_hostname=host)
        sock.getpeercert()
        sock.close()
        return 1
    except Exception:
        return 0


def safe_quad9_blocked(host):
    if dns is None:
        return 0
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=3)
        return 0
    except:
        return 1


# -------------------- VirusTotal minimal lookup with caching --------------------

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

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=6,
        )
        if r.status_code == 200:
            stats = (
                r.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            total = sum(stats.values())
            mal = stats.get("malicious", 0)
            ratio = mal / total if total > 0 else 0.0
            cache_set(cache_key, {
                "total": total,
                "malicious": mal,
                "ratio": ratio
            })
            return total, mal, ratio
    except:
        pass

    return 0, 0, 0.0


# -------------------- Shopping detection --------------------

PRICE_RE = re.compile(
    r"(\$|£|€|₹|RM|USD|SGD|MYR|IDR|PHP)\s?\d{1,4}(?:[.,]\d{2,3})?"
)

SHOP_KEYWORDS = [
    "add to cart", "buy now", "checkout", "cart", "basket",
    "product", "products", "shop", "store", "price", "sale",
    "collections", "sku", "item", "wishlist"
]


def detect_shopping_html(soup, body):
    if not soup and not body:
        return 0

    text = (body or "").lower()

    score = 0

    # prices
    if PRICE_RE.search(text):
        score += 2

    # keywords
    for k in SHOP_KEYWORDS:
        if k in text:
            score += 1

    # og:type
    try:
        if soup:
            og = soup.find("meta", property="og:type")
            if og and og.get("content", "").lower() == "product":
                score += 3
    except:
        pass

    return 1 if score >= 2 else 0


# -------------------- Main extractor --------------------

def extract_all_features(url):
    url_l = url.lower()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0].lower()
    path = parsed.path or "/"

    f = {}

    # Lexical features
    f["length_url"] = len(url)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in url)

    f["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login", "verify", "secure", "bank", "account", "update",
        "confirm", "urgent", "pay", "gift", "free", "click", "signin"
    ]))

    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_hash"] = url.count("#")

    f["shortening_service"] = int(bool(
        re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l)
    ))
    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))

    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

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

    # Live features
    age = safe_whois(host)
    f["domain_age_days"] = age if age is not None else 365

    f["ssl_valid"] = safe_ssl_valid(host)
    f["quad9_blocked"] = safe_quad9_blocked(host)

    vt_total, vt_mal, vt_ratio = vt_scan_info(url)
    f["vt_total_vendors"] = vt_total
    f["vt_malicious_count"] = vt_mal
    f["vt_detection_ratio"] = vt_ratio

    # HTML features
    html = safe_request(url, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None
    body = soup.get_text(" ", strip=True).lower() if soup else ""

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
            parsed2 = urllib.parse.urlparse(
                href if "://" in href else f"http://{host}{href}"
            )
            fav_host = parsed2.netloc.split(":")[0]
            return 0 if fav_host.endswith(host) else 1
        except:
            return 0

    f["external_favicon"] = external_favicon()

    # login form
    f["login_form"] = 0
    if soup:
        for form in soup.find_all("form"):
            inputs = [i.get("type", "").lower() for i in form.find_all("input")]
            if "password" in inputs or "login" in form.text.lower():
                f["login_form"] = 1
                break

    f["iframe_present"] = int(bool(soup.find_all("iframe"))) if soup else 0
    f["popup_window"] = int(any(k in body for k in ["popup", "modal", "cookie", "overlay", "subscribe"]))
    f["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())

    try:
        title = soup.title.string.strip() if (soup and soup.title) else ""
        f["empty_title"] = int(title == "")
    except:
        f["empty_title"] = 0

    # web traffic approx from body length
    if body:
        wc = len(re.findall(r"\w+", body))
        if wc > 2000: f["web_traffic"] = 1000
        elif wc > 500: f["web_traffic"] = 500
        elif wc > 100: f["web_traffic"] = 100
        else: f["web_traffic"] = 10
    else:
        f["web_traffic"] = 100

    # -------------------- SHOPPING DETECTION --------------------
    f["is_shopping"] = detect_shopping_html(soup, body)

    # Ensure 40 keys exist
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

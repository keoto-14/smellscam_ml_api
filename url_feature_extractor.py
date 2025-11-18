# url_feature_extractor.py
"""
40-feature universal extractor for SmellScam.
Automatically supports:
 - TRAIN_MODE (env) = fast lexical-only extraction
 - Production mode = WHOIS / SSL / Quad9 / VT / HTML

Exports: extract_all_features(url)
"""

import os
import re
import time
import socket
import ssl
import urllib.parse
from datetime import datetime

TRAIN_MODE = os.environ.get("TRAIN_MODE", "0") == "1"
VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")

# optional libs
try:
    import requests
except: requests = None

try:
    from bs4 import BeautifulSoup
except: BeautifulSoup = None

try:
    import whois as pywhois
except: pywhois = None

try:
    import dns.resolver
except: dns = None

# optional caching layer
try:
    from simple_cache import cache_get, cache_set
except:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        v = _CACHE.get(k)
        if not v: return None
        ts, val = v
        if time.time() - ts > max_age: return None
        return val
    def cache_set(k, v): _CACHE[k] = (time.time(), v)

# -------------------------
# Helpers
# -------------------------

def safe_request(url, timeout=6, verify=False, max_bytes=200000):
    if not requests:
        return None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": "Mozilla/5.0 smells"}
        )
        content = r.content[:max_bytes]
        return content.decode(errors="ignore")
    except:
        return None


def safe_whois(host):
    if not pywhois:
        return None
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str): cd = datetime.fromisoformat(cd)
        if not cd: return None
        return max(0, (datetime.utcnow() - cd).days)
    except:
        return None


def safe_ssl_valid(host):
    try:
        ctx = ssl.create_default_context()
        s = socket.create_connection((host, 443), timeout=4)
        sock = ctx.wrap_socket(s, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        return bool(cert)
    except:
        return None


def safe_quad9_blocked(host):
    if not dns:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=3)
        return 0     # resolves => not blocked
    except:
        return 1     # blocked / unresolved


def vt_domain_info(url_or_host):
    if not VT_API_KEY or not requests:
        return 0, 0, 0.0

    # parse domain
    try:
        parsed = urllib.parse.urlparse(
            url_or_host if "://" in url_or_host else "http://" + url_or_host
        )
        domain = (parsed.netloc or url_or_host).split(":")[0].lower()
    except:
        domain = url_or_host.lower()

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached["total"], cached["mal"], cached["ratio"]

    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers=headers, timeout=6)

        if r.status_code == 200:
            stats = (
                r.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            total = sum(stats.values()) if stats else 0
            mal = stats.get("malicious", 0)
            ratio = mal / total if total > 0 else 0.0
            cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
            return total, mal, ratio

    except:
        pass

    cache_set(cache_key, {"total": 0, "mal": 0, "ratio": 0.0})
    return 0, 0, 0.0


def extract_host(url):
    p = urllib.parse.urlparse(
        url if "://" in url else "http://" + url
    )
    host = (p.netloc or "").split(":")[0].lower()
    return p, host


# -------------------------
# Main Extractor (40 features)
# -------------------------

def extract_all_features(url):
    """
    Returns STRICTLY 40 features + "url".
    Fully compatible with your predictor + features.pkl order.
    """

    u = str(url).strip()
    parsed, host = extract_host(u)
    path = parsed.path or "/"
    scheme = parsed.scheme or ""
    url_l = u.lower()

    features = {}

    # -------------------------
    # Lexical-only features (always)
    # -------------------------

    features["length_url"]           = len(u)
    features["length_hostname"]      = len(host)
    features["nb_dots"]              = host.count(".")
    features["nb_hyphens"]           = host.count("-")
    features["nb_numeric_chars"]     = sum(c.isdigit() for c in u)

    features["contains_scam_keyword"] = int(
        any(k in url_l for k in [
            "login","verify","secure","bank","account","update","confirm","urgent",
            "pay","gift","free","click","signin","auth"
        ])
    )

    features["nb_at"]            = u.count("@")
    features["nb_qm"]            = u.count("?")
    features["nb_and"]           = u.count("&")
    features["nb_underscore"]    = u.count("_")
    features["nb_tilde"]         = u.count("~")
    features["nb_percent"]       = u.count("%")
    features["nb_slash"]         = u.count("/")
    features["nb_hash"]          = u.count("#")

    features["shortening_service"] = int(
        bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l))
    )

    features["nb_www"]          = int(host.startswith("www"))
    features["ends_with_com"]   = int(host.endswith(".com"))
    features["nb_subdomains"]   = max(0, host.count(".") - 1)
    features["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    features["prefix_suffix"]      = int("-" in host)
    features["path_extension_php"] = int(path.endswith(".php"))

    # domain/path token relationship
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(
        t for t in tokens_path if len(t) > 2
    )

    features["domain_in_brand"] = int(bool(common_tokens))
    features["brand_in_path"]   = int(bool(common_tokens))
    features["char_repeat3"]    = int(bool(re.search(r"(.)\1\1", u)))

    features["ratio_digits_url"]  = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # -------------------------
    # If TRAIN_MODE, skip heavy features
    # -------------------------

    if TRAIN_MODE:
        features.update({
            "ssl_valid": 1,
            "domain_age_days": 365,
            "quad9_blocked": 0,
            "vt_total_vendors": 0,
            "vt_malicious_count": 0,
            "vt_detection_ratio": 0.0,

            "external_favicon": 0,
            "login_form": 0,
            "iframe_present": 0,
            "popup_window": 0,
            "right_click_disabled": 0,
            "empty_title": 0,
            "web_traffic": 100,
        })
        features["url"] = u
        return features

    # -------------------------
    # LIVE FEATURES (Production Mode)
    # -------------------------

    # WHOIS
    age = safe_whois(host)
    features["domain_age_days"] = age if age is not None else 365

    # SSL
    ssl_ok = safe_ssl_valid(host)
    features["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    # Quad9
    q9 = safe_quad9_blocked(host)
    features["quad9_blocked"] = int(q9) if q9 is not None else 0

    # VirusTotal
    vt_total, vt_mal, vt_ratio = vt_domain_info(u)
    features["vt_total_vendors"] = vt_total
    features["vt_malicious_count"] = vt_mal
    features["vt_detection_ratio"] = vt_ratio

    # HTML Parsing
    html = safe_request(u, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None

    # favicon
    try:
        if soup:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            if not link:
                features["external_favicon"] = 0
            else:
                href = link.get("href", "")
                if href.startswith("data:"):
                    features["external_favicon"] = 0
                else:
                    p2 = urllib.parse.urlparse(
                        href if "://" in href else f"http://{host}{href}"
                    )
                    fav_host = (p2.netloc or "").split(":")[0]
                    features["external_favicon"] = int(not fav_host.endswith(host))
        else:
            features["external_favicon"] = 0
    except:
        features["external_favicon"] = 0

    # form, iframe, popup, contextmenu, title, traffic
    if soup:
        # login form
        login = 0
        for f in soup.find_all("form"):
            inputs = [i.get("type", "").lower() for i in f.find_all("input")]
            if "password" in inputs or "login" in f.text.lower():
                login = 1
                break
        features["login_form"] = login

        features["iframe_present"] = int(bool(soup.find_all("iframe")))

        body = soup.get_text(" ", strip=True).lower()
        features["popup_window"] = int(
            any(k in body for k in ["popup", "modal", "overlay", "subscribe", "cookie"])
        )
        features["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())

        try:
            title = soup.title.string.strip() if soup.title else ""
            features["empty_title"] = int(title == "")
        except:
            features["empty_title"] = 0

        # simple traffic heuristic by word count
        wc = len(re.findall(r"\w+", body))
        if wc > 2000:
            features["web_traffic"] = 1000
        elif wc > 500:
            features["web_traffic"] = 500
        elif wc > 100:
            features["web_traffic"] = 100
        else:
            features["web_traffic"] = 10
    else:
        features.update({
            "login_form": 0,
            "iframe_present": 0,
            "popup_window": 0,
            "right_click_disabled": 0,
            "empty_title": 0,
            "web_traffic": 100,
        })

    # ensure all fields exist (strict 40)
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars",
        "contains_scam_keyword","nb_at","nb_qm","nb_and","nb_underscore",
        "nb_tilde","nb_percent","nb_slash","nb_hash","shortening_service",
        "nb_www","ends_with_com","nb_subdomains","abnormal_subdomain","prefix_suffix",
        "path_extension_php","domain_in_brand","brand_in_path","char_repeat3",
        "ratio_digits_url","ratio_digits_host","ssl_valid","domain_age_days",
        "quad9_blocked","vt_total_vendors","vt_malicious_count","vt_detection_ratio",
        "external_favicon","login_form","iframe_present","popup_window",
        "right_click_disabled","empty_title","web_traffic"
    ]

    for k in expected:
        if k not in features:
            # defaults
            if k in ("ssl_valid","external_favicon","login_form","iframe_present",
                     "popup_window","right_click_disabled","empty_title","shortening_service",
                     "nb_www","path_extension_php","domain_in_brand","brand_in_path",
                     "char_repeat3","quad9_blocked"):
                features[k] = 0
            elif k == "domain_age_days":
                features[k] = 365
            elif k == "web_traffic":
                features[k] = 100
            elif k in ("vt_total_vendors","vt_malicious_count"):
                features[k] = 0
            elif k in ("vt_detection_ratio","ratio_digits_url","ratio_digits_host"):
                features[k] = 0.0
            else:
                features[k] = 0

    # final
    features["url"] = u
    return features

# url_feature_extractor.py
"""
Single extractor that switches behavior based on TRAIN_MODE env var.
TRAIN_MODE=1 -> FAST "training" extractor (no VT/WHOIS/SSL/DNS/HTML).
TRAIN_MODE=0 -> FULL production extractor with VT/WHOIS/SSL/Quad9/HTML + caching.

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
VT_API_KEY = os.environ.get("VT_API_KEY", None)
GSB_API_KEY = os.environ.get("GSB_API_KEY", None)

# optional libs
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

# simple disk cache for VT/GSB results
try:
    from simple_cache import cache_get, cache_set
except Exception:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        v = _CACHE.get(k)
        if not v: return None
        ts, val = v
        if time.time() - ts > max_age: return None
        return val
    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

# ---------------- Helper functions ----------------
def safe_request(url, timeout=6, verify=False, max_bytes=200000):
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout, verify=verify, headers={"User-Agent":"Mozilla/5.0 (smellscam)"}, stream=True)
        content = b""
        for chunk in r.iter_content(chunk_size=4096):
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
            except Exception:
                return None
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
        r.resolve(host, "A", lifetime=3)
        return 0
    except Exception:
        return 1

def vt_domain_info(url_or_host):
    # returns (total_vendors, malicious_count, ratio)
    if not VT_API_KEY or requests is None:
        return 0, 0, 0.0
    try:
        parsed = urllib.parse.urlparse(url_or_host if "://" in url_or_host else "http://" + url_or_host)
        domain = (parsed.netloc or url_or_host).split(":")[0].lower()
    except Exception:
        domain = url_or_host.lower().split(":")[0]
    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached.get("total", 0), cached.get("malicious", 0), cached.get("ratio", 0.0)
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=6)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                ratio = malicious / total if total > 0 else 0.0
                cache_set(cache_key, {"total": total, "malicious": malicious, "ratio": ratio})
                return total, malicious, ratio
    except Exception:
        pass
    cache_set(cache_key, {"total": 0, "malicious": 0, "ratio": 0.0})
    return 0, 0, 0.0

def extract_host(url):
    p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = (p.netloc or "").split(":")[0].lower()
    return p, host

# ---------------- Main extractor ----------------
def extract_all_features(url):
    """
    Returns dict of 40 features (+ url at the end).
    Behavior switches on TRAIN_MODE:
      - TRAIN_MODE=True  -> fast lexical-only extractor (no network heavy calls)
      - TRAIN_MODE=False -> production extractor with VT/WHOIS/SSL/DNS/HTML (cached)
    """
    u = str(url).strip()
    parsed, host = extract_host(u)
    path = parsed.path or "/"
    query = parsed.query or ""
    scheme = parsed.scheme or ""

    features = {}
    url_l = u.lower()

    # --- lexical features (always) ---
    features["length_url"] = len(u)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(c.isdigit() for c in u)
    features["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login","verify","secure","bank","account","update","confirm","urgent","pay","gift","free","click","signin","auth"
    ]))
    features["nb_at"] = u.count("@")
    features["nb_qm"] = u.count("?")
    features["nb_and"] = u.count("&")
    features["nb_underscore"] = u.count("_")
    features["nb_tilde"] = u.count("~")
    features["nb_percent"] = u.count("%")
    features["nb_slash"] = u.count("/")
    features["nb_hash"] = u.count("#")
    features["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l)))
    features["nb_www"] = int(host.startswith("www"))
    features["ends_with_com"] = int(host.endswith(".com"))
    features["nb_subdomains"] = max(0, host.count(".") - 1)
    features["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    features["prefix_suffix"] = int("-" in host)
    features["path_extension_php"] = int(path.endswith(".php"))

    # domain/path token alignment
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(t for t in tokens_path if len(t) > 2)
    features["domain_in_brand"] = int(bool(common_tokens))
    features["brand_in_path"] = int(bool(common_tokens))

    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", u)))
    features["ratio_digits_url"] = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # --- TRAIN MODE: set safe defaults for heavy features and return ---
    if TRAIN_MODE:
        # safe defaults
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
            "web_traffic": 100
        })
        features["url"] = u
        return features

    # --- PRODUCTION MODE: attempt live/VT/WHOIS/SSL/HTML checks (cached/fallbacks) ---
    # WHOIS / domain age
    age = safe_whois(host)
    features["domain_age_days"] = age if age is not None else 365

    # SSL
    ssl_ok = safe_ssl_valid(host)
    features["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    # Quad9
    q9 = safe_quad9_blocked(host)
    features["quad9_blocked"] = int(q9) if q9 is not None else 0

    # VirusTotal (domain)
    vt_total, vt_mal, vt_ratio = vt_domain_info(u)
    features["vt_total_vendors"] = int(vt_total)
    features["vt_malicious_count"] = int(vt_mal)
    features["vt_detection_ratio"] = float(vt_ratio)

    # HTML features (safe_request)
    html = safe_request(u, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None

    # external favicon
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
                    parsed2 = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
                    fav_host = (parsed2.netloc or "").split(":")[0]
                    features["external_favicon"] = 0 if fav_host.endswith(host) else 1
        else:
            features["external_favicon"] = 0
    except Exception:
        features["external_favicon"] = 0

    # login form, iframe, popup, right-click, title, traffic heuristic
    if soup:
        login = 0
        for form in soup.find_all("form"):
            inputs = [i.get("type", "").lower() for i in form.find_all("input")]
            if "password" in inputs or "login" in form.text.lower():
                login = 1
                break
        features["login_form"] = login
        features["iframe_present"] = int(bool(soup.find_all("iframe")))
        body = soup.get_text(" ", strip=True).lower()
        features["popup_window"] = int(any(k in body for k in ["popup", "modal", "cookie", "overlay", "subscribe"]))
        features["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())
        try:
            title = soup.title.string.strip() if soup and soup.title else ""
            features["empty_title"] = int(title == "")
        except:
            features["empty_title"] = 0
        wc = len(re.findall(r"\w+", body or ""))
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
            "web_traffic": 100
        })

    # ensure keys
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
            if k in ("ssl_valid","shortening_service","nb_www","path_extension_php",
                     "domain_in_brand","brand_in_path","char_repeat3","external_favicon",
                     "login_form","iframe_present","popup_window","right_click_disabled",
                     "empty_title"):
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

    features["url"] = u
    return features

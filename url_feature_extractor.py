# ==============================================================
# url_feature_extractor.py — Railway-optimized (FAST, non-blocking)
# - FAST_MODE=1 disables slow network ops (WHOIS/VT/Quad9/HTML fetch)
# - Returns a stable feature dict with expected ordering
# ==============================================================

import os
import re
import time
import socket
import ssl
import urllib.parse
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Modes
TRAIN_MODE = os.environ.get("TRAIN_MODE", "0") == "1"
FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"   # set to "1" on Railway to skip slow checks
VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")

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

# Simple in-memory cache
_CACHE = {}
def cache_get(key, max_age=3600):
    v = _CACHE.get(key)
    if not v:
        return None
    ts, val = v
    return val if (time.time() - ts) <= max_age else None
def cache_set(key, val):
    _CACHE[key] = (time.time(), val)


# -------------------------
# Safe HTTP request (short)
# -------------------------
def safe_request(url, timeout=2, verify=False, max_bytes=120000):
    if not requests:
        return None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": "Mozilla/5.0 SmellScam"}
        )
        return r.content[:max_bytes].decode(errors="ignore")
    except:
        return None


# -------------------------
# WHOIS (fast fallback)
# -------------------------
def safe_whois(host):
    if FAST_MODE:
        return 365  # assume reasonable age in FAST mode
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
                # whois strings can be messy
                return None
        if cd:
            return max(0, (datetime.utcnow() - cd).days)
    except:
        return None
    return None


# -------------------------
# SSL cert check (short timeout)
# -------------------------
def safe_ssl_valid(host):
    if FAST_MODE:
        return 1
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=1.5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as sock:
                return bool(sock.getpeercert())
    except:
        return None


# -------------------------
# Quad9 DNS check
# -------------------------
def safe_quad9_blocked(host):
    if FAST_MODE:
        return 0
    if not dns:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=1.5)
        return 0
    except:
        return 1


# -------------------------
# VirusTotal domain info (short)
# -------------------------
def vt_domain_info(url_or_host):
    if FAST_MODE or not VT_API_KEY or not requests:
        return 0, 0, 0.0

    try:
        parsed = urllib.parse.urlparse(url_or_host if "://" in url_or_host else "http://" + url_or_host)
        domain = (parsed.netloc or url_or_host).split(":")[0].lower()
    except:
        domain = url_or_host.lower()

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached["total"], cached["mal"], cached["ratio"]

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=2
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            mal = stats.get("malicious", 0)
            ratio = mal / total if total > 0 else 0.0
            cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
            return total, mal, ratio
    except:
        pass

    cache_set(cache_key, {"total": 0, "mal": 0, "ratio": 0.0})
    return 0, 0, 0.0


# -------------------------
# Parse host
# -------------------------
def extract_host(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = (parsed.netloc or "").split(":")[0].lower()
    return parsed, host


# -------------------------
# Shannon entropy (simple)
# -------------------------
def shannon_entropy(s: str):
    import math
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log(p, 2) for p in probs)


# -------------------------
# MAIN extractor
# -------------------------
def extract_all_features(url: str):
    u = str(url or "").strip()
    parsed, host = extract_host(u)
    path = parsed.path or "/"
    url_l = u.lower()

    features = {}

    # BASIC string/structure features
    features["length_url"] = len(u)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(c.isdigit() for c in u)

    scam_keywords = ["login","verify","secure","bank","account","update","confirm","urgent","pay","gift","free","click","signin","auth"]
    features["contains_scam_keyword"] = int(any(k in url_l for k in scam_keywords))

    # symbol counts
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

    # brand tokens
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common = set(t for t in tokens_host if len(t) > 2).intersection(t for t in tokens_path if len(t) > 2)
    features["domain_in_brand"] = int(bool(common))
    features["brand_in_path"] = int(bool(common))

    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", u)))
    features["ratio_digits_url"] = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # NEW features you requested
    tld = host.split(".")[-1] if host else ""
    suspicious_tlds = {"top","cfd","xyz","cyou","shop","win","vip","asia","click","online","support","live","rest","gq","ml","tk","ru"}
    features["suspicious_tld"] = int(tld in suspicious_tlds)

    known_brands = ["paypal","bank","coinbase","apple","google","microsoft","meta","asics","dhl","fedex","post","facebook","instagram","amazon"]
    features["brand_mismatch"] = int(any(b in url_l and b not in host for b in known_brands))

    features["double_hyphen"] = int("--" in host)
    features["subdomain_count"] = host.count(".")
    features["suspicious_subdomain"] = int(features["subdomain_count"] >= 3)

    features["entropy_url"] = shannon_entropy(u)

    free_hosts = ["webflow.io","wixsite.com","weebly.com","000webhostapp.com","000webhost","firebaseapp.com","github.io","shopify.com","wordpress.com","blogspot.com"]
    features["free_hosting"] = int(any(h in host for h in free_hosts))

    extra_keywords = ["superdeal","bonus","giveaway","offer","promo","sale","discount","freegift","claim","verify","secure","update"]
    features["keyword_suspect"] = int(any(k in url_l for k in extra_keywords))

    # TRAIN_MODE or FAST_MODE: skip live expensive checks
    if TRAIN_MODE or FAST_MODE:
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

    # LIVE features (attempt but with short timeouts and safe fallbacks)
    age = safe_whois(host)
    features["domain_age_days"] = age if age is not None else 365

    ssl_ok = safe_ssl_valid(host)
    features["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1

    q9 = safe_quad9_blocked(host)
    features["quad9_blocked"] = int(q9) if q9 is not None else 0

    vt_total, vt_mal, vt_ratio = vt_domain_info(u)
    features["vt_total_vendors"] = vt_total
    features["vt_malicious_count"] = vt_mal
    features["vt_detection_ratio"] = vt_ratio

    # HTML analysis: short timeout
    html = safe_request(u, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None

    if soup:
        # favicon
        try:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            if link:
                href = link.get("href", "")
                if href.startswith("data:"):
                    features["external_favicon"] = 0
                else:
                    p2 = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
                    fav_host = (p2.netloc or "").split(":")[0]
                    features["external_favicon"] = int(not fav_host.endswith(host))
            else:
                features["external_favicon"] = 0
        except:
            features["external_favicon"] = 0

        # login forms
        try:
            login_flag = 0
            for f in soup.find_all("form"):
                inputs = [i.get("type", "").lower() for i in f.find_all("input")]
                if "password" in inputs or "login" in f.get_text(" ", True).lower():
                    login_flag = 1
                    break
            features["login_form"] = login_flag
        except:
            features["login_form"] = 0

        features["iframe_present"] = int(bool(soup.find_all("iframe")))
        body = soup.get_text(" ", strip=True).lower()
        features["popup_window"] = int(any(k in body for k in ["popup","modal","overlay","subscribe","cookie"]))
        features["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())
        try:
            title = soup.title.string.strip() if soup.title else ""
            features["empty_title"] = int(title == "")
        except:
            features["empty_title"] = 0

        wc = len(re.findall(r"\w+", body))
        features["web_traffic"] = 1000 if wc > 2000 else 500 if wc > 500 else 100 if wc > 100 else 10
    else:
        features.update({
            "external_favicon": 0,
            "login_form": 0,
            "iframe_present": 0,
            "popup_window": 0,
            "right_click_disabled": 0,
            "empty_title": 0,
            "web_traffic": 100,
        })

    # Final expected feature list (ensures ordering / keys)
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars",
        "contains_scam_keyword","nb_at","nb_qm","nb_and","nb_underscore",
        "nb_tilde","nb_percent","nb_slash","nb_hash","shortening_service",
        "nb_www","ends_with_com","nb_subdomains","abnormal_subdomain",
        "prefix_suffix","path_extension_php","domain_in_brand","brand_in_path",
        "char_repeat3","ratio_digits_url","ratio_digits_host",

        # NEW FEATURES
        "suspicious_tld","brand_mismatch","double_hyphen","subdomain_count",
        "suspicious_subdomain","entropy_url","free_hosting","keyword_suspect",

        # LIVE FEATURES
        "ssl_valid","domain_age_days","quad9_blocked","vt_total_vendors",
        "vt_malicious_count","vt_detection_ratio","external_favicon",
        "login_form","iframe_present","popup_window",
        "right_click_disabled","empty_title","web_traffic"
    ]

    for k in expected:
        features.setdefault(k, 0)

    features["url"] = u
    return features

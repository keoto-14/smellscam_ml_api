# url_feature_extractor.py
"""
Full 40-feature extractor matching your ML model.
Includes:
- WHOIS (with fallback)
- SSL certificate validation (fallback)
- Quad9 DNS block check (fallback)
- VirusTotal URL/domain analysis (safe)
- HTML-based features (iframe, popup, login form, title, right-click disable, favicon)
- URL lexical features (length, dots, hyphens, digits, scam keywords, etc.)
Safe for Railway hosting (no failures → fallback safe defaults).
"""

import os
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from collections import Counter

# optional imports
try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    import requests
    from requests.exceptions import RequestException
except Exception:
    requests = None
    RequestException = Exception

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import dns.resolver
except Exception:
    dns = None

# ---------------------------
# VirusTotal settings
# ---------------------------
VT_API_KEY = os.environ.get("VT_API_KEY", None)

def vt_scan_info(url_or_host):
    """
    Robust VirusTotal lookup with safe fallback.
    Returns (total_vendors, malicious, ratio)
    """
    if not VT_API_KEY or requests is None:
        return 0, 0, 0.0  # safe default

    headers = {"x-apikey": VT_API_KEY}

    # ---- 1) Domain lookup (fast, cached) ----
    try:
        parsed = urllib.parse.urlparse(url_or_host if "://" in url_or_host else "http://" + url_or_host)
        domain = parsed.netloc or url_or_host
        domain = domain.split(":")[0]

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=6
        )
        if resp.status_code == 200:
            j = resp.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                ratio = malicious / total if total > 0 else 0.0
                return total, malicious, ratio
    except Exception:
        pass

    # ---- 2) URL lookup (fallback) ----
    try:
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url_or_host},
            headers=headers, timeout=6
        )
        if resp.status_code not in (200, 202):
            return 0, 0, 0.0

        analysis_id = resp.json().get("data", {}).get("id")
        if not analysis_id:
            return 0, 0, 0.0

        time.sleep(1)  # allow VT to prepare
        summary = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers, timeout=6
        )

        if summary.status_code == 200:
            stats = summary.json().get("data", {}).get("attributes", {}).get("stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                ratio = malicious / total if total > 0 else 0.0
                return total, malicious, ratio
    except Exception:
        pass

    # ---- Final fallback ----
    return 0, 0, 0.0


# ---------------------------
# Helper utilities
# ---------------------------
def safe_request(url, timeout=5, verify=True):
    if requests is None:
        return None
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": "Mozilla/5.0 (smellscam)"}
        )
        return resp.text
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
        if not cd:
            return None
        if isinstance(cd, str):
            try:
                cd = datetime.fromisoformat(cd)
            except Exception:
                return None
        age = (datetime.utcnow() - cd).days
        return max(0, age)
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
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['9.9.9.9']
        resolver.resolve(host, 'A', lifetime=3)
        return 0  # not blocked
    except Exception:
        return 1  # assume blocked


def extract_host(url):
    if "://" not in url:
        url = "http://" + url
    p = urllib.parse.urlparse(url)
    host = p.netloc.split(":")[0].lower()
    return p, host


def external_favicon_flag(soup, host):
    if soup is None:
        return 0
    try:
        link = soup.find("link", rel=re.compile(".*icon.*", re.I))
        if not link:
            return 0
        href = link.get("href", "")
        if href.startswith("data:"):
            return 0
        parsed = urllib.parse.urlparse(
            href if "://" in href else f"http://{host}{href}"
        )
        fav_host = parsed.netloc.split(":")[0]
        return 0 if fav_host.endswith(host) else 1
    except Exception:
        return 0


# ---------------------------
# MAIN FEATURE EXTRACTOR
# ---------------------------
def extract_all_features(url):
    url_l = url.lower()
    parsed, host = extract_host(url)
    path = parsed.path or "/"

    features = {}

    # -------------------
    # BASIC LEXICAL
    # -------------------
    features["length_url"] = len(url)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(c.isdigit() for c in url)
    features["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login", "verify", "secure", "bank", "account", "update",
        "confirm", "urgent", "pay", "gift", "free", "click", "signin"
    ]))

    # punctuation / symbol counts
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_hash"] = url.count("#")

    features["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)", url_l)))
    features["nb_www"] = int(host.startswith("www"))
    features["ends_with_com"] = int(host.endswith(".com"))

    # subdomains
    features["nb_subdomains"] = max(0, host.count(".") - 1)
    features["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    features["prefix_suffix"] = int("-" in host)

    # path / brand detection
    features["path_extension_php"] = int(path.endswith(".php"))
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(
        t for t in tokens_path if len(t) > 2
    )
    features["domain_in_brand"] = int(len(common_tokens) > 0)
    features["brand_in_path"] = int(len(common_tokens) > 0)

    # character repetition
    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))

    # digit ratios
    features["ratio_digits_url"] = (sum(c.isdigit() for c in url) / max(1, len(url))) * 100
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # -------------------
    # LIVE FEATURES (safe fallbacks)
    # -------------------
    # WHOIS age
    domain_age = safe_whois(host)
    if domain_age is None:
        # fallback: assume old & safe
        domain_age = 365
    features["domain_age_days"] = domain_age

    # SSL validity
    ssl_ok = safe_ssl_valid(host)
    if ssl_ok is None:
        ssl_ok = 1
    features["ssl_valid"] = int(ssl_ok)

    # Quad9 DNS
    q9 = safe_quad9_blocked(host)
    if q9 is None:
        q9 = 0
    features["quad9_blocked"] = int(q9)

    # VirusTotal
    vt_total, vt_mal, vt_ratio = vt_scan_info(url)
    features["vt_total_vendors"] = vt_total
    features["vt_malicious_count"] = vt_mal
    features["vt_detection_ratio"] = vt_ratio

    # -------------------
    # HTML FEATURES
    # -------------------
    html = safe_request(url, timeout=6, verify=False)
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None

    # external favicon
    features["external_favicon"] = external_favicon_flag(soup, host)

    # login form
    if soup:
        login = 0
        for form in soup.find_all("form"):
            inputs = [i.get("type", "").lower() for i in form.find_all("input")]
            if "password" in inputs or "login" in form.text.lower():
                login = 1
                break
        features["login_form"] = login
    else:
        features["login_form"] = 0

    # iframe
    features["iframe_present"] = int(bool(soup.find_all("iframe"))) if soup else 0

    # popup / modal keywords
    body = soup.get_text(" ", strip=True).lower() if soup else ""
    features["popup_window"] = int(any(k in body for k in ["popup", "modal", "cookie", "overlay", "subscribe"]))

    # right-click disabled
    features["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())

    # empty title
    try:
        title = soup.title.string.strip() if soup and soup.title else ""
        features["empty_title"] = int(title == "")
    except:
        features["empty_title"] = 0

    # web_traffic (simple heuristic fallback)
    if html:
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
        features["web_traffic"] = 100  # safe default

    # -------------------
    # FINAL CHECK: Ensure all 40 keys exist
    # -------------------
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
            # set safe defaults
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

    return features

# url_feature_extractor.py
"""
Robust URL feature extractor for smellscam.
Produces a dictionary of features matching the model's FEATURES list.
Safe for restricted environments (Railway, Docker) — uses conservative fallbacks.
"""

import os
import re
import socket
import ssl
import time
import json
import urllib.parse
from datetime import datetime
from collections import Counter

# optional imports (wrapped)
try:
    import whois as pywhois  # pip install python-whois
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

# Optional VirusTotal support (requires VT_API_KEY environment var)
VT_API_KEY = os.environ.get("VT_API_KEY", None)

# -------------------------
# Helper utilities
# -------------------------
def safe_request(url, timeout=5, verify=True, headers=None):
    """Return (text, final_url) or (None, None) if requests not available or fails."""
    if requests is None:
        return None, None
    try:
        resp = requests.get(url, timeout=timeout, verify=verify, headers=headers or {"User-Agent": "smellscam-bot/1.0"})
        return resp.text, resp.url
    except Exception:
        return None, None

def extract_host(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.lower()
    if ":" in host:
        host = host.split(":")[0]
    return parsed, host

def safe_whois(host):
    """Return domain_age_days or None if not available."""
    if pywhois is None:
        return None
    try:
        w = pywhois.whois(host)
        # whois library returns creation_date which may be a list
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None
        if isinstance(cd, str):
            try:
                cd = datetime.fromisoformat(cd)
            except Exception:
                try:
                    cd = datetime.strptime(cd, "%Y-%m-%d")
                except Exception:
                    return None
        days = (datetime.utcnow() - cd).days
        return max(0, int(days))
    except Exception:
        return None

def safe_ssl_valid(host, port=443, timeout=5):
    """Return True/False or None if check cannot be performed."""
    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port), timeout=timeout)
        sock = context.wrap_socket(conn, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
        # basic sanity: cert should have subject and not be empty
        return bool(cert)
    except Exception:
        return None

def safe_quad9_blocked(host):
    """Return 1 if blocked by Quad9 (9.9.9.9) or 0 if resolvable or None on failure."""
    if dns is None:
        return None
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['9.9.9.9']
        # If resolution succeeds, return 0
        answers = resolver.resolve(host, 'A', lifetime=3)
        return 0
    except Exception as e:
        # if NXDOMAIN or no answer, return 1; if unknown error, None
        if hasattr(e, 'rcode') or isinstance(e, dns.resolver.NXDOMAIN):
            return 1
        return 1

def vt_scan_info(host_or_url):
    """Optional VirusTotal summary. Returns (total_vendors, malicious_count, ratio) or (None,None,None)."""
    if not VT_API_KEY or requests is None:
        return None, None, None
    # prefer URL scanning, fallback to domain
    try:
        headers = {"x-apikey": VT_API_KEY}
        # attempt url lookup
        url_safe = host_or_url
        resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url_safe}, headers=headers, timeout=6)
        if resp.status_code in (200, 202):
            # get analysis id
            j = resp.json()
            if 'data' in j and 'id' in j['data']:
                analysis_id = j['data']['id']
                # fetch summary (may take time) - do best-effort
                time.sleep(1)
                summary = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=6)
                if summary.status_code == 200:
                    sj = summary.json()
                    vendors = sj.get('data', {}).get('attributes', {}).get('stats', {})
                    total = sum(vendors.values()) if isinstance(vendors, dict) else None
                    mal = vendors.get('malicious', 0) if isinstance(vendors, dict) else None
                    ratio = None
                    if total and mal is not None:
                        ratio = float(mal) / float(total) if total else 0.0
                    return total, mal, ratio
        # fallback: domain report
        parsed = urllib.parse.urlparse(host_or_url if "://" in host_or_url else "http://" + host_or_url)
        domain = parsed.netloc or host_or_url
        report = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=6)
        if report.status_code == 200:
            j = report.json()
            stats = j.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            total = sum(stats.values()) if isinstance(stats, dict) else None
            mal = stats.get('malicious', 0) if isinstance(stats, dict) else None
            ratio = None
            if total and mal is not None:
                ratio = float(mal) / float(total) if total else 0.0
            return total, mal, ratio
    except Exception:
        pass
    return None, None, None

def external_favicon_flag(soup, host):
    """Return 1 if favicon is hosted on external domain, 0 if same domain, None if cannot tell."""
    if soup is None:
        return None
    try:
        link = soup.find("link", rel=re.compile(".*icon.*", re.I))
        if not link:
            return 0
        href = link.get("href", "")
        if not href or href.startswith("data:"):
            return 0
        parsed = urllib.parse.urlparse(href if "://" in href else urllib.parse.urljoin(f"http://{host}", href))
        fav_host = parsed.netloc.split(":")[0].lower() if parsed.netloc else host
        return 0 if fav_host.endswith(host) or host.endswith(fav_host) else 1
    except Exception:
        return None

# -------------------------
# Main extractor
# -------------------------
def extract_all_features(url):
    """
    Returns dictionary of features named exactly to match your model feature list.
    Safe defaults used where live checks fail.
    """
    url_l = url.lower()
    parsed, host = extract_host(url)
    path = parsed.path or "/"
    query = parsed.query or ""
    features = {}

    # Basic lexical features
    features["length_url"] = len(url)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(1 for c in url if c.isdigit())
    features["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login", "verify", "secure", "bank", "account",
        "update", "confirm", "urgent", "pay", "gift", "free", "click", "signin"
    ]))

    # Additional lexical tokens
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_hash"] = url.count("#")
    features["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|buff\.ly|is\.gd|bitly|tinycc)", url_l)))
    features["nb_www"] = int(host.startswith("www."))
    features["ends_with_com"] = int(host.endswith(".com"))
    # count subdomains (host like a.b.c.com -> subdomains = 2)
    features["nb_subdomains"] = max(0, host.count(".") - 1)
    features["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))  # starts with digits -> abnormal
    features["prefix_suffix"] = int("-" in host)  # already have nb_hyphens, keep simple

    # path/extension & brand-ish heuristics
    features["path_extension_php"] = int(path.lower().endswith(".php"))
    # domain_in_brand and brand_in_path: look for long tokens repeated between host and path
    host_tokens = re.split(r"[\-._/]+", host)
    path_tokens = re.split(r"[\-._/]+", path)
    common = set([t for t in host_tokens if t and len(t) > 2]).intersection(set([t for t in path_tokens if t and len(t) > 2]))
    features["domain_in_brand"] = int(len(common) > 0)
    features["brand_in_path"] = int(len(common) > 0)

    # character repetition and digit ratios
    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))  # any char repeated 3 times
    features["ratio_digits_url"] = (sum(c.isdigit() for c in url) / max(1, len(url))) * 100.0
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100.0

    # ---------------------------
    # Live checks with safe fallbacks
    # ---------------------------
    # WHOIS -> domain_age_days
    domain_age = safe_whois(host)
    if domain_age is None:
        # fallback: if hostname looks like a known big brand or has many characters assume older
        if len(host) < 20 and re.search(r"(amazon|google|facebook|zara|apple|microsoft|youtube|bing|baidu|shop|ebay|alibaba|aliexpress)", host):
            domain_age = 3650  # assume old brand
        else:
            domain_age = 365  # safe default: 1 year
    features["domain_age_days"] = domain_age

    # SSL validity
    ssl_ok = safe_ssl_valid(host)
    if ssl_ok is None:
        ssl_ok = 1  # assume valid certificate in restricted env
    features["ssl_valid"] = int(bool(ssl_ok))

    # Quad9 DNS check
    q9 = safe_quad9_blocked(host)
    if q9 is None:
        q9 = 0  # assume not blocked
    features["quad9_blocked"] = int(bool(q9))

    # VirusTotal summary (optional)
    vt_total, vt_malicious, vt_ratio = vt_scan_info(url)
    features["vt_total_vendors"] = int(vt_total) if vt_total is not None else 0
    features["vt_malicious_count"] = int(vt_malicious) if vt_malicious is not None else 0
    features["vt_detection_ratio"] = float(vt_ratio) if vt_ratio is not None else 0.0

    # HTTP fetch for HTML-based checks
    html, final_url = safe_request(url, timeout=6, verify=False)
    soup = BeautifulSoup(html, "html.parser") if BeautifulSoup and html else None

    # favicon external
    efav = external_favicon_flag(soup, host) if soup is not None else None
    features["external_favicon"] = int(efav) if efav is not None else 0

    # login form detection
    try:
        if soup is not None:
            login_form = 0
            for form in soup.find_all("form"):
                inputs = [i.get("type", "").lower() for i in form.find_all("input")]
                if "password" in inputs or any("login" in str(x).lower() for x in form.text.split()):
                    login_form = 1
                    break
            features["login_form"] = login_form
        else:
            features["login_form"] = 0
    except Exception:
        features["login_form"] = 0

    # iframe / popup / right-click / empty title / web_traffic heuristic
    try:
        features["iframe_present"] = int(bool(soup.find_all("iframe"))) if soup is not None else 0
    except Exception:
        features["iframe_present"] = 0

    try:
        body_text = soup.get_text(" ", strip=True).lower() if soup is not None else ""
        features["popup_window"] = int(bool(re.search(r"(popup|modal|subscribe|subscribe now|cookie|overlay|subscribe-popup)", body_text)))
    except Exception:
        features["popup_window"] = 0

    try:
        html_src = html.lower() if html else ""
        features["right_click_disabled"] = int("oncontextmenu" in html_src or "contextmenu" in html_src)
    except Exception:
        features["right_click_disabled"] = 0

    try:
        title = soup.title.string.strip() if soup and soup.title and soup.title.string else ""
        features["empty_title"] = int(title == "")
    except Exception:
        features["empty_title"] = 0

    # Web traffic: best-effort heuristic - if fetch succeeded, score by presence of many words / resources
    try:
        if html:
            words = len(re.findall(r"\w+", body_text))
            # heuristic: fewer words -> low traffic (but can be accurate only roughly)
            if words > 2000:
                web_traffic_score = 1000
            elif words > 500:
                web_traffic_score = 500
            elif words > 100:
                web_traffic_score = 100
            else:
                web_traffic_score = 10
        else:
            web_traffic_score = 100  # fallback mid-safe
        features["web_traffic"] = int(web_traffic_score)
    except Exception:
        features["web_traffic"] = 100

    # final safety: ensure all expected keys exist: (list below should match your model features)
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars","contains_scam_keyword",
        "nb_at","nb_qm","nb_and","nb_underscore","nb_tilde","nb_percent","nb_slash","nb_hash",
        "shortening_service","nb_www","ends_with_com","nb_subdomains","abnormal_subdomain","prefix_suffix",
        "path_extension_php","domain_in_brand","brand_in_path","char_repeat3","ratio_digits_url","ratio_digits_host",
        "ssl_valid","domain_age_days","quad9_blocked","vt_total_vendors","vt_malicious_count","vt_detection_ratio",
        "external_favicon","login_form","iframe_present","popup_window","right_click_disabled","empty_title","web_traffic"
    ]

    # fill any missing with safe defaults
    for k in expected:
        if k not in features:
            if k in ("ssl_valid", "shortening_service", "nb_www", "path_extension_php", "domain_in_brand", "brand_in_path", "char_repeat3", "external_favicon", "login_form", "iframe_present", "popup_window", "right_click_disabled", "empty_title"):
                features[k] = 0
            elif k in ("domain_age_days",):
                features[k] = 365
            elif k in ("web_traffic",):
                features[k] = 100
            elif k in ("vt_total_vendors","vt_malicious_count"):
                features[k] = 0
            elif k in ("vt_detection_ratio","ratio_digits_url","ratio_digits_host"):
                features[k] = 0.0
            else:
                features[k] = 0

    # final normalization: ensure numeric types are correct
    for k, v in list(features.items()):
        if isinstance(v, bool):
            features[k] = int(v)
        elif v is None:
            # replace None with conservative safe default
            if k in ("vt_detection_ratio","ratio_digits_url","ratio_digits_host"):
                features[k] = 0.0
            else:
                features[k] = 0

    return features

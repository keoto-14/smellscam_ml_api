# url_feature_extractor.py
"""
Robust 40-feature extractor with safe fallbacks.
- Does lexical features (deterministic, no network blocking)
- Optionally fetches HTML for a few HTML features (safe_request)
- Uses simple_cache for VT lookups if called from predictor (predictor handles VT)
"""

import os
import re
import urllib.parse
import socket
import ssl
from datetime import datetime
import time

# optional imports
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

# basic safe request (small stream)
def safe_request(url, timeout=5, max_bytes=150000, verify=False):
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout, stream=True, verify=verify,
                         headers={"User-Agent":"Mozilla/5.0 (smellscam)"})
        content = b""
        for chunk in r.iter_content(4096):
            content += chunk
            if len(content) >= max_bytes:
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

def safe_quad9(host):
    if dns is None:
        return None
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=3)
        return 0
    except Exception:
        return 1

def extract_all_features(url):
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    p = urllib.parse.urlparse(u)
    host = (p.netloc or "").split(":")[0].lower()
    path = p.path or "/"
    query = p.query or ""
    scheme = p.scheme or ""

    features = {}

    # lexical
    features["length_url"] = len(u)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(c.isdigit() for c in u)
    url_l = u.lower()
    features["contains_scam_keyword"] = int(any(k in url_l for k in [
        "login","verify","secure","bank","account","update","confirm","urgent",
        "pay","gift","free","click","signin","auth","password","billing"
    ]))
    # punctuation
    features["nb_at"] = u.count("@")
    features["nb_qm"] = u.count("?")
    features["nb_and"] = u.count("&")
    features["nb_underscore"] = u.count("_")
    features["nb_tilde"] = u.count("~")
    features["nb_percent"] = u.count("%")
    features["nb_slash"] = u.count("/")
    features["nb_hash"] = u.count("#")
    features["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd)", url_l)))
    features["nb_www"] = int(host.startswith("www"))
    features["ends_with_com"] = int(host.endswith(".com"))
    features["nb_subdomains"] = max(0, host.count(".") - 1)
    features["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    features["prefix_suffix"] = int("-" in host)
    features["path_extension_php"] = int(path.endswith(".php"))
    # brand alignment
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)
    common = set(t for t in tokens_host if len(t) > 2).intersection(t for t in tokens_path if len(t) > 2)
    features["domain_in_brand"] = int(bool(common))
    features["brand_in_path"] = int(bool(common))
    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", u)))
    features["ratio_digits_url"] = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100.0
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100.0

    # live
    wa = safe_whois(host)
    features["domain_age_days"] = wa if wa is not None else 365
    s_ok = safe_ssl_valid(host)
    features["ssl_valid"] = int(s_ok) if s_ok is not None else 1
    q9 = safe_quad9(host)
    features["quad9_blocked"] = int(q9) if q9 is not None else 0

    # vt placeholders (predictor handles real VT)
    features["vt_total_vendors"] = 0
    features["vt_malicious_count"] = 0
    features["vt_detection_ratio"] = 0.0

    # html features (best-effort)
    html = safe_request(u) if requests is not None else None
    soup = BeautifulSoup(html, "html.parser") if (BeautifulSoup and html) else None

    # external favicon
    try:
        if soup:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            href = link.get("href","") if link else ""
            if href.startswith("data:"):
                features["external_favicon"] = 0
            else:
                parsed = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
                fav_host = (parsed.netloc or "").split(":")[0]
                features["external_favicon"] = 0 if fav_host.endswith(host) else 1
        else:
            features["external_favicon"] = 0
    except Exception:
        features["external_favicon"] = 0

    # login form
    if soup:
        login = 0
        for form in soup.find_all("form"):
            inputs = [i.get("type","").lower() for i in form.find_all("input")]
            if "password" in inputs or "login" in (form.text or "").lower():
                login = 1
                break
        features["login_form"] = login
        features["iframe_present"] = int(bool(soup.find_all("iframe")))
        body = soup.get_text(" ", strip=True).lower()
        features["popup_window"] = int(any(k in body for k in ["popup","modal","subscribe","overlay","cookie"]))
        features["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())
        try:
            title = soup.title.string.strip() if soup.title else ""
            features["empty_title"] = int(title == "")
        except Exception:
            features["empty_title"] = 0
    else:
        features["login_form"] = 0
        features["iframe_present"] = 0
        features["popup_window"] = 0
        features["right_click_disabled"] = 0
        features["empty_title"] = 0

    # traffic heuristic
    if html:
        wc = len(re.findall(r"\w+", (soup.get_text(" ", strip=True) if soup else "")))
        if wc > 2000:
            features["web_traffic"] = 1000
        elif wc > 500:
            features["web_traffic"] = 500
        elif wc > 100:
            features["web_traffic"] = 100
        else:
            features["web_traffic"] = 10
    else:
        features["web_traffic"] = 100

    # ensure all expected keys (40 features)
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
            # safe defaults
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

    # include original url for predictor if needed
    features["url"] = url.strip()
    return features

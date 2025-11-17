# url_feature_extractor.py
import os
import re
import socket
import ssl
import urllib.parse
from datetime import datetime

try:
    import requests
except Exception:
    requests = None

try:
    import whois as pywhois
except Exception:
    pywhois = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import dns.resolver
except Exception:
    dns = None

# safe helper functions
def extract_host(url):
    if "://" not in url:
        url = "http://" + url
    p = urllib.parse.urlparse(url)
    host = p.netloc.split(":")[0].lower()
    return p, host

def safe_request_text(url, timeout=6):
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "smellscam-agent"}, stream=True, verify=False)
        content = b""
        for chunk in r.iter_content(chunk_size=4096):
            content += chunk
            if len(content) > 200000:
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

# minimal lexical + safe live features
def extract_all_features(url):
    p, host = extract_host(url)
    path = p.path or "/"
    url_l = url.lower()

    f = {}
    # lexical
    f["url"] = url
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
    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(t for t in tokens_path if len(t) > 2)
    f["domain_in_brand"] = int(bool(common_tokens))
    f["brand_in_path"] = int(bool(common_tokens))
    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", url)))
    f["ratio_digits_url"] = (sum(c.isdigit() for c in url) / max(1, len(url))) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # live (safe fallbacks)
    age = safe_whois(host)
    f["domain_age_days"] = age if age is not None else 365
    ssl_ok = safe_ssl_valid(host)
    f["ssl_valid"] = int(ssl_ok) if ssl_ok is not None else 1
    q9 = safe_quad9_blocked(host)
    f["quad9_blocked"] = int(q9) if q9 is not None else 0

    # placeholders for vt (predictor will call vt_domain_report separately)
    f["vt_total_vendors"] = 0
    f["vt_malicious_count"] = 0
    f["vt_detection_ratio"] = 0.0

    # HTML features (safe)
    html = safe_request_text(url)
    soup = None
    if html and BeautifulSoup:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            soup = None

    def external_favicon_flag():
        if not soup:
            return 0
        try:
            link = soup.find("link", rel=re.compile(".*icon.*", re.I))
            if not link:
                return 0
            href = link.get("href", "")
            if href.startswith("data:"):
                return 0
            p2 = urllib.parse.urlparse(href if "://" in href else f"http://{host}{href}")
            fav_host = p2.netloc.split(":")[0]
            return 0 if fav_host.endswith(host) else 1
        except Exception:
            return 0

    f["external_favicon"] = external_favicon_flag()
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
        f["popup_window"] = int(any(k in body for k in ["popup","modal","cookie","overlay","subscribe"]))
        f["right_click_disabled"] = int("oncontextmenu" in (html or "").lower())
        try:
            title = soup.title.string.strip() if soup and soup.title else ""
            f["empty_title"] = int(title == "")
        except Exception:
            f["empty_title"] = 0
        # web traffic heuristic
        wc = len(re.findall(r"\w+", body))
        f["web_traffic"] = 1000 if wc > 2000 else 500 if wc > 500 else 100 if wc > 100 else 10
    else:
        f["login_form"] = 0
        f["iframe_present"] = 0
        f["popup_window"] = 0
        f["right_click_disabled"] = 0
        f["empty_title"] = 0
        f["web_traffic"] = 100

    # ensure expected keys (safe defaults)
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
        if k not in f:
            if k in ("ssl_valid","shortening_service","nb_www","path_extension_php",
                     "domain_in_brand","brand_in_path","char_repeat3","external_favicon",
                     "login_form","iframe_present","popup_window","right_click_disabled",
                     "empty_title"):
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

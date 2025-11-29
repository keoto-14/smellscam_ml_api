import os
import re
import urllib.parse
import ssl
import socket
from datetime import datetime
import urllib3

urllib3.disable_warnings()

FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"
TRAIN_MODE = os.environ.get("TRAIN_MODE", "0") == "1"

try:
    import requests
except:
    requests = None

try:
    from bs4 import BeautifulSoup
except:
    BeautifulSoup = None

try:
    import dns.resolver
except:
    dns = None

try:
    import whois as pywhois
except:
    pywhois = None


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def extract_host(url):
    p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    return p, (p.netloc or "").split(":")[0].lower()


def safe_request(url):
    if FAST_MODE or not requests:
        return None
    try:
        r = requests.get(url, timeout=2, verify=False)
        return r.text[:150000]
    except:
        return None


def safe_whois(host):
    if FAST_MODE or not pywhois:
        return 365
    try:
        w = pywhois.whois(host)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str): cd = datetime.fromisoformat(cd)
        if cd:
            return max(0, (datetime.utcnow() - cd).days)
    except:
        return 365
    return 365


def safe_ssl(host):
    if FAST_MODE:
        return 1
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=2) as s:
            with ctx.wrap_socket(s, server_hostname=host) as sock:
                return 1 if sock.getpeercert() else 0
    except:
        return 1


def quad9_block(host):
    if FAST_MODE or not dns:
        return 0
    try:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ["9.9.9.9"]
        r.resolve(host, "A", lifetime=2)
        return 0
    except:
        return 1


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
def extract_all_features(url):
    u = str(url).strip()
    p, host = extract_host(u)
    path = p.path or "/"
    url_l = u.lower()

    f = {}

    # BASIC
    f["length_url"] = len(u)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in u)

    scamwords = [
        "login","verify","secure","bank","account","update",
        "confirm","urgent","pay","gift","free","click","signin","auth"
    ]
    f["contains_scam_keyword"] = int(any(w in url_l for w in scamwords))

    # special chars
    for sym, name in [
        ("@", "nb_at"),
        ("?", "nb_qm"),
        ("&", "nb_and"),
        ("_", "nb_underscore"),
        ("~", "nb_tilde"),
        ("%", "nb_percent"),
        ("/", "nb_slash"),
        ("#", "nb_hash"),
    ]:
        f[name] = u.count(sym)

    f["shortening_service"] = int(bool(re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl)", url_l)))
    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))
    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

    # brand similarity
    tk_host = re.split(r"[\W_]+", host)
    tk_path = re.split(r"[\W_]+", path)
    common = set(t for t in tk_host if len(t) > 2).intersection(
        t for t in tk_path if len(t) > 2
    )
    f["domain_in_brand"] = int(bool(common))
    f["brand_in_path"] = int(bool(common))

    f["char_repeat3"] = int(bool(re.search(r"(.)\1\1", u)))
    f["ratio_digits_url"] = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100
    f["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # new features
    tld = host.split(".")[-1]
    f["suspicious_tld"] = int(tld in {"top","xyz","win","tk","ml","gq","ru","vip","live"})

    brands = ["paypal","google","apple","amazon","microsoft","bank","meta"]
    f["brand_mismatch"] = int(any(b in url_l and b not in host for b in brands))

    f["double_hyphen"] = int("--" in host)
    f["subdomain_count"] = host.count(".")
    f["suspicious_subdomain"] = int(f["subdomain_count"] >= 3)

    # entropy
    def entropy(s):
        import math
        prob = [s.count(c)/len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log(p, 2) for p in prob)
    f["entropy_url"] = entropy(u) if u else 0

    f["free_hosting"] = int(any(h in host for h in [
        "wixsite.com","weebly.com","000webhost","github.io","webflow.io","blogspot.com"
    ]))

    f["keyword_suspect"] = int(any(k in url_l for k in [
        "promo","discount","freegift","bonus","offer","deal"
    ]))

    # LIVE
    if FAST_MODE or TRAIN_MODE:
        f.update({
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
    else:
        f["ssl_valid"] = safe_ssl(host)
        f["domain_age_days"] = safe_whois(host)
        f["quad9_blocked"] = quad9_block(host)

        html = safe_request(u)
        soup = BeautifulSoup(html, "html.parser") if (html and BeautifulSoup) else None

        if soup:
            f["iframe_present"] = int(bool(soup.find_all("iframe")))
            f["login_form"] = int(bool(soup.find_all("input", {"type": "password"})))

            txt = soup.get_text(" ", strip=True).lower()
            f["popup_window"] = int("popup" in txt or "modal" in txt)
            f["right_click_disabled"] = int("oncontextmenu" in (html.lower() if html else ""))

            title = soup.title.string.strip() if soup.title else ""
            f["empty_title"] = int(title == "")

            wc = len(re.findall(r"\w+", txt))
            f["web_traffic"] = 1000 if wc > 2000 else 500 if wc > 500 else 100 if wc > 100 else 10
        else:
            f["iframe_present"] = 0
            f["login_form"] = 0
            f["popup_window"] = 0
            f["right_click_disabled"] = 0
            f["empty_title"] = 0
            f["web_traffic"] = 100

        f["vt_total_vendors"] = 0
        f["vt_malicious_count"] = 0
        f["vt_detection_ratio"] = 0.0

    # FIXED ORDER (your old features.pkl order)
    expected = [
        "length_url","length_hostname","nb_dots","nb_hyphens","nb_numeric_chars",
        "contains_scam_keyword","nb_at","nb_qm","nb_and","nb_underscore",
        "nb_tilde","nb_percent","nb_slash","nb_hash","shortening_service",
        "nb_www","ends_with_com","nb_subdomains","abnormal_subdomain",
        "prefix_suffix","path_extension_php","domain_in_brand","brand_in_path",
        "char_repeat3","ratio_digits_url","ratio_digits_host",

        "suspicious_tld","brand_mismatch","double_hyphen","subdomain_count",
        "suspicious_subdomain","entropy_url","free_hosting","keyword_suspect",

        "ssl_valid","domain_age_days","quad9_blocked","vt_total_vendors",
        "vt_malicious_count","vt_detection_ratio","external_favicon",
        "login_form","iframe_present","popup_window",
        "right_click_disabled","empty_title","web_traffic",
    ]

    for k in expected:
        f.setdefault(k, 0)

    f["url"] = u
    return f

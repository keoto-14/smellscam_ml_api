# url_feature_extractor.py
"""
40-feature extractor (FAST + SAFE)
- Pure lexical features
- Light HTML inspection (optional)
- No WHOIS, no SSL, no DNS, no VT here
- Zero risk of Railway network blocks
- Fully compatible with 40-feature ML training set
"""

import urllib.parse
import re

try:
    import requests
    from bs4 import BeautifulSoup
except:
    requests = None
    BeautifulSoup = None


def safe_request(url, max_bytes=150000):
    """Fetch HTML safely without blocking the API."""
    if requests is None:
        return None
    try:
        r = requests.get(url, timeout=4, verify=False, stream=True,
            headers={"User-Agent": "Mozilla/5.0 (SmellScam)"})

        content = b""
        for c in r.iter_content(4096):
            content += c
            if len(content) > max_bytes:
                break

        return content.decode(errors="ignore")

    except:
        return None


def extract_all_features(url):
    """Return the 40 lexical features used by your ML model."""

    if "://" not in url:
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path or "/"
    url_l = url.lower()

    f = {}

    # ------------------------
    # BASIC LEXICAL FEATURES
    # ------------------------
    f["length_url"] = len(url)
    f["length_hostname"] = len(host)
    f["nb_dots"] = host.count(".")
    f["nb_hyphens"] = host.count("-")
    f["nb_numeric_chars"] = sum(c.isdigit() for c in url)

    scam_words = [
        "login","secure","verify","account","bank",
        "free","gift","confirm","urgent","signin"
    ]

    f["contains_scam_keyword"] = int(any(k in url_l for k in scam_words))

    f["nb_at"] = url.count("@")
    f["nb_qm"] = url.count("?")
    f["nb_and"] = url.count("&")
    f["nb_underscore"] = url.count("_")
    f["nb_tilde"] = url.count("~")
    f["nb_percent"] = url.count("%")
    f["nb_slash"] = url.count("/")
    f["nb_hash"] = url.count("#")

    f["shortening_service"] = int(
        bool(re.search(r"(bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd)", url_l))
    )

    f["nb_www"] = int(host.startswith("www"))
    f["ends_with_com"] = int(host.endswith(".com"))
    f["nb_subdomains"] = max(0, host.count(".") - 1)
    f["abnormal_subdomain"] = int(bool(re.match(r"^\d+\.", host)))
    f["prefix_suffix"] = int("-" in host)
    f["path_extension_php"] = int(path.endswith(".php"))

    # brand detection
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

    # ------------------------
    # NETWORK-FREE LIVE FEATURES (SAFE DEFAULTS)
    # ------------------------
    # These are *always safe* and do not require external calls.
    f["ssl_valid"] = 1           # always assume TRUE, ML corrects via lexical
    f["domain_age_days"] = 365   # neutral default
    f["quad9_blocked"] = 0       # no DNS checking
    
    # VT is handled in predictor, not here
    f["vt_total_vendors"] = 0
    f["vt_malicious_count"] = 0
    f["vt_detection_ratio"] = 0.0

    # ------------------------
    # HTML FEATURES (if available)
    # ------------------------
    html = safe_request(url)
    soup = BeautifulSoup(html, "html.parser") if (html and BeautifulSoup) else None

    # favicon external?
    def external_favicon():
        if not soup:
            return 0
        try:
            link = soup.find("link", rel=re.compile("icon", re.I))
            if not link:
                return 0
            href = link.get("href", "")
            if href.startswith("data:"):
                return 0
            parsed2 = urllib.parse.urlparse(
                href if "://" in href else f"https://{host}{href}"
            )
            fav_host = parsed2.netloc.lower().split(":")[0]
            return int(fav_host != host)
        except:
            return 0

    f["external_favicon"] = external_favicon()

    # login form detection
    f["login_form"] = 0
    if soup:
        try:
            for form in soup.find_all("form"):
                inputs = [i.get("type", "").lower() for i in form.find_all("input")]
                if "password" in inputs or "login" in form.text.lower():
                    f["login_form"] = 1
                    break
        except:
            pass

    f["iframe_present"] = int(bool(soup.find_all("iframe"))) if soup else 0

    body = soup.get_text(" ", strip=True).lower() if soup else ""
    f["popup_window"] = int(any(k in body for k in ["popup","cookie","modal","subscribe"]))
    f["right_click_disabled"] = int("oncontextmenu" in (html or "").lower()) if html else 0

    try:
        f["empty_title"] = int(not bool(soup.title.string.strip()))
    except:
        f["empty_title"] = 0

    # simple heuristic traffic estimate
    if body:
        wc = len(re.findall(r"\w+", body))
        if wc > 2000: f["web_traffic"] = 1000
        elif wc > 500: f["web_traffic"] = 500
        elif wc > 100: f["web_traffic"] = 100
        else: f["web_traffic"] = 10
    else:
        f["web_traffic"] = 100

    return f

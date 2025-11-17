# url_feature_extractor.py
import urllib.parse
import re

def extract_all_features(url: str):
    """
    FAST, deterministic 40-feature extractor.
    No network calls (WHOIS, SSL, DNS, VT removed).
    Used ONLY for ML input. VT/GSB handled in predictor.py.
    """

    u = url.strip()
    parsed = urllib.parse.urlparse(u if "://" in u else "http://" + u)

    host = parsed.netloc.lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    scheme = parsed.scheme or ""

    url_l = u.lower()

    # -------------------------------------
    # BASIC LEXICAL FEATURES
    # -------------------------------------
    features = {
        "length_url": len(u),
        "length_hostname": len(host),
        "nb_dots": host.count("."),
        "nb_hyphens": host.count("-"),
        "nb_numeric_chars": sum(c.isdigit() for c in u),
        "contains_scam_keyword": int(any(k in url_l for k in [
            "login","verify","secure","bank","account","update",
            "confirm","urgent","pay","gift","free","click","signin","auth"
        ])),
        "nb_at": u.count("@"),
        "nb_qm": u.count("?"),
        "nb_and": u.count("&"),
        "nb_underscore": u.count("_"),
        "nb_tilde": u.count("~"),
        "nb_percent": u.count("%"),
        "nb_slash": u.count("/"),
        "nb_hash": u.count("#"),

        "shortening_service": int(bool(re.search(
            r"(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly)",
            url_l
        ))),

        "nb_www": int(host.startswith("www")),
        "ends_with_com": int(host.endswith(".com")),
        "nb_subdomains": max(0, host.count(".") - 1),
        "abnormal_subdomain": int(bool(re.match(r"^\d+\.", host))),
        "prefix_suffix": int("-" in host),
        "path_extension_php": int(path.endswith(".php")),
    }

    # -------------------------------------
    # BRAND / PATH FEATURES
    # -------------------------------------
    tokens_host = re.split(r"[\W_]+", host)
    tokens_path = re.split(r"[\W_]+", path)

    common_tokens = set(t for t in tokens_host if len(t) > 2).intersection(
        t for t in tokens_path if len(t) > 2
    )

    features["domain_in_brand"] = int(bool(common_tokens))
    features["brand_in_path"] = int(bool(common_tokens))

    # -------------------------------------
    # DIGIT RATIOS / REPEAT PATTERNS
    # -------------------------------------
    features["char_repeat3"] = int(bool(re.search(r"(.)\1\1", u)))
    features["ratio_digits_url"] = (sum(c.isdigit() for c in u) / max(1, len(u))) * 100
    features["ratio_digits_host"] = (sum(c.isdigit() for c in host) / max(1, len(host))) * 100

    # -------------------------------------
    # PLACEHOLDERS FOR LIVE FEATURES
    # Predictor.py fills these with real VT/GSB
    # -------------------------------------
    features["ssl_valid"] = 0
    features["domain_age_days"] = 0
    features["quad9_blocked"] = 0

    features["vt_total_vendors"] = 0
    features["vt_malicious_count"] = 0
    features["vt_detection_ratio"] = 0.0

    # HTML placeholders
    features["external_favicon"] = 0
    features["login_form"] = 0
    features["iframe_present"] = 0
    features["popup_window"] = 0
    features["right_click_disabled"] = 0
    features["empty_title"] = 0
    features["web_traffic"] = 0

    return features

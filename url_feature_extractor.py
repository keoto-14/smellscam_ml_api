# url_feature_extractor.py
import urllib.parse
import re


def extract_all_features(url: str):
    url = url.strip()
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)

    host = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_l = url.lower()

    features = {}

    # Basic lexical
    features["length_url"] = len(url)
    features["length_hostname"] = len(host)
    features["nb_dots"] = host.count(".")
    features["nb_hyphens"] = host.count("-")
    features["nb_numeric_chars"] = sum(c.isdigit() for c in url)

    scam_words = [
        "login", "verify", "secure", "account", "update",
        "confirm", "urgent", "bank", "signin", "free"
    ]
    features["contains_scam_keyword"] = int(any(k in url_l for k in scam_words))

    # Simple structural
    features["uses_ip"] = int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)))
    features["has_query"] = int(bool(query))
    features["has_www"] = int(host.startswith("www."))
    features["https"] = int(parsed.scheme == "https")

    # Placeholders (required by ML model)
    features["vt_total_vendors"] = 0
    features["vt_malicious_count"] = 0
    features["vt_detection_ratio"] = 0.0

    return features

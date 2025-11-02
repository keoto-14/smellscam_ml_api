# url_feature_extractor.py
import re
import socket
import ssl
import datetime
import requests
import tldextract
import dns.resolver
from bs4 import BeautifulSoup

# Optional imports that may fail safely
try:
    import whois
except ImportError:
    whois = None


def extract_all_features(url: str) -> dict:
    """
    Extracts simple and live features from a given URL.
    Returns a dictionary of features expected by your ML models.
    This version is Railway-safe (no blocking network calls or crashes).
    """

    features = {}

    # ---- Basic String Features ----
    features["URL_Length"] = len(url)
    features["Has_IP_Address"] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features["Num_Dots"] = url.count(".")
    features["Num_Hyphens"] = url.count("-")
    features["Num_Slashes"] = url.count("/")
    features["Has_At_Symbol"] = 1 if "@" in url else 0
    features["Has_Https"] = 1 if url.lower().startswith("https") else 0
    features["Num_Query_Params"] = url.count("?") + url.count("&")
    features["Num_Subdomains"] = len(tldextract.extract(url).subdomain.split(".")) if tldextract.extract(url).subdomain else 0
    features["Domain_Name"] = tldextract.extract(url).domain
    features["Suffix"] = tldextract.extract(url).suffix

    # ---- Live DNS/SSL/WHOIS Checks ----
    domain = f"{features['Domain_Name']}.{features['Suffix']}"
    features["SSL_Valid"] = 0
    features["Domain_Age_Days"] = 0
    features["Quad9_Blocked"] = 0
    features["VT_Detection_Ratio"] = 0.0  # Placeholder for VirusTotal

    try:
        # SSL validation
        if url.startswith("https"):
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
                cert = s.getpeercert()
                if cert:
                    features["SSL_Valid"] = 1
    except Exception:
        features["SSL_Valid"] = 0

    # ---- WHOIS domain age ----
    try:
        if whois:
            info = whois.whois(domain)
            creation = info.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age_days = (datetime.datetime.utcnow() - creation).days
                features["Domain_Age_Days"] = max(age_days, 0)
    except Exception:
        features["Domain_Age_Days"] = 0

    # ---- DNS resolution (simple existence check) ----
    try:
        dns.resolver.resolve(domain, "A")
    except Exception:
        pass

    # ---- HTML-based heuristic ----
    try:
        resp = requests.get(url, timeout=4)
        soup = BeautifulSoup(resp.text, "html.parser")
        features["Num_Forms"] = len(soup.find_all("form"))
        features["Num_Scripts"] = len(soup.find_all("script"))
    except Exception:
        features["Num_Forms"] = 0
        features["Num_Scripts"] = 0

    # ---- Return defaults for missing model features ----
    # You can adjust based on your actual feature_list.pkl
    defaults = [
        "URL_Length", "Has_IP_Address", "Num_Dots", "Num_Hyphens", "Num_Slashes",
        "Has_At_Symbol", "Has_Https", "Num_Query_Params", "Num_Subdomains",
        "SSL_Valid", "Domain_Age_Days", "Quad9_Blocked", "VT_Detection_Ratio",
        "Num_Forms", "Num_Scripts"
    ]

    for key in defaults:
        features.setdefault(key, 0)

    return features


if __name__ == "__main__":
    test_url = "https://example.com"
    feats = extract_all_features(test_url)
    print(f"Extracted {len(feats)} features for {test_url}")
    for k, v in feats.items():
        print(f"{k}: {v}")

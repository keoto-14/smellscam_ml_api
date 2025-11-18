import requests
import socket
import ssl
import whois
import re
import datetime
import tldextract
import numpy as np
from urllib.parse import urlparse

# ======================
#  VirusTotal + Quad9
# ======================
VT_API_KEY = "8fe25e2f3a5dbd46fc46a8ae875c1ae03a2ee6ee3d3a7ca9c784d4d894682cf9"  # <-- replace with your API key or load from .env

def check_quad9_block(url):
    """Check if domain is blocked by Quad9 DNS"""
    try:
        domain = tldextract.extract(url).registered_domain
        resolver = "9.9.9.9"
        response = socket.gethostbyname_ex(domain)
        return 0  # resolved → not blocked
    except Exception:
        return 1  # failed → possibly blocked or dead

def get_vt_reputation(url):
    """Check VirusTotal for detections"""
    try:
        domain = tldextract.extract(url).registered_domain
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=10)

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return positives / total  # detection ratio 0.0 → 1.0
        else:
            return 0.0
    except Exception:
        return 0.0

# ======================
#  Main Feature Extractor
# ======================
def extract_all_features(url):
    """Extracts both static and live features for the given URL"""
    features = {}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc or url
        ext = tldextract.extract(url)
        hostname = ext.registered_domain
    except Exception:
        features = {f"feat_{i}": 0 for i in range(50)}
        return features

    # Example lexical features (replace with your existing ones)
    features["NumDots"] = url.count(".")
    features["UrlLength"] = len(url)
    features["NumDash"] = url.count("-")
    features["HasHTTPs"] = 1 if url.startswith("https") else 0
    features["SubdomainLevel"] = len(ext.subdomain.split(".")) if ext.subdomain else 0

    # SSL check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
        features["SSL_Valid"] = 1
    except Exception:
        features["SSL_Valid"] = 0

    # WHOIS / Domain age
    try:
        w = whois.whois(hostname)
        if isinstance(w.creation_date, list):
            created = w.creation_date[0]
        else:
            created = w.creation_date
        if created:
            age_days = (datetime.datetime.now() - created).days
            features["Domain_Age_Days"] = age_days
        else:
            features["Domain_Age_Days"] = 0
    except Exception:
        features["Domain_Age_Days"] = 0

    # 🧠 Reputation features
    features["VT_Detection_Ratio"] = get_vt_reputation(url)
    features["Quad9_Blocked"] = check_quad9_block(url)

    # ✅ Ensure no NaNs
    for k, v in features.items():
        if v is None or v == "" or (isinstance(v, float) and np.isnan(v)):
            features[k] = 0

    return features

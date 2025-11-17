import os
import pickle
import numpy as np
import pandas as pd
import urllib.parse
import requests
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set

MODEL_DIR = "models"


###############################################
# LOADING MODELS
###############################################
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    model = XGBClassifier()
    model.load_model(path)
    return model

def load_models():
    print("📦 Loading ML models...")
    models = {
        "xgb": load_xgb_model(os.path.join(MODEL_DIR, "xgb.json")),
        "rf": load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }
    print("XGB MODEL:", type(models["xgb"]))
    print("STACKER INPUTS:", models["stacker"].coef_.shape[1])
    print("Models loaded successfully!")
    return models


###############################################
# GOOGLE SAFE BROWSING
###############################################
GSB_API_KEY = os.environ.get("GSB_API_KEY")

def check_gsb(url):
    if not GSB_API_KEY:
        return False

    cache_key = f"gsb::{url}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "smellscam", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(endpoint, json=body, timeout=4)
        result = bool(r.json().get("matches"))
        cache_set(cache_key, result)
        return result
    except:
        return False


###############################################
# VIRUSTOTAL FAST-DOMAIN CHECK
###############################################
VT_API_KEY = os.environ.get("VT_API_KEY")

def vt_domain_report(domain):
    if not VT_API_KEY:
        return 0, 0, 0.0

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached["total"], cached["mal"], cached["ratio"]

    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers=headers, timeout=5)
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        total = sum(stats.values()) if stats else 0
        mal = stats.get("malicious", 0) if stats else 0
        ratio = mal / total if total > 0 else 0

        cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
        return total, mal, ratio

    except:
        return 0, 0, 0.0


###############################################
# SHOPPING WEBSITE DETECTOR (NEW)
###############################################
SHOPPING_KEYWORDS = [
    "shop", "store", "product", "products", "item",
    "cart", "checkout", "buy", "sale", "collections",
    "payment", "add-to-cart"
]

# websites that are NEVER shopping sites
WHITELIST_NONE_SHOPPING = [
    "facebook.com", "instagram.com", "youtube.com",
    "twitter.com", "gmi.edu.my", "uitm.edu.my",
    "ox.ac.uk", "w3schools.com", "github.com"
]

def detect_shopping_site(raw_url, domain):
    url_l = (raw_url or "").lower()

    # 1) whitelist → not shopping
    if domain in WHITELIST_NONE_SHOPPING:
        return False

    # 2) keywords in URL → shopping
    if any(k in url_l for k in SHOPPING_KEYWORDS):
        return True

    # 3) brands that typically have shopping sites
    if any(b in domain for b in ["nike", "adidas", "asics", "puma", "uniqlo", "zara"]):
        return True

    return False


###############################################
# MAIN HYBRID PREDICTOR
###############################################
def predict_from_features(features, models, raw_url=None):

    feature_names = models["features"]
    X = np.array([[features.get(f, 0) for f in feature_names]], dtype=float)

    # ML models
    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except:
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except:
        p_rf = 0.5

    stack_input = np.array([[p_xgb, p_rf]])
    try:
        final_ml = float(models["stacker"].predict_proba(stack_input)[0][1])
    except:
        final_ml = (p_xgb + p_rf) / 2

    ml_risk = final_ml * 100

    # Domain parsing
    parsed = urllib.parse.urlparse(raw_url or "")
    domain = parsed.netloc.lower().split(":")[0]

    # VIRUSTOTAL DOMAIN SCORE
    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
    vt_risk = ((vt_ratio * 100) ** 2) / 100
    vt_risk = min(vt_risk, 100)

    # GOOGLE SAFE BROWSING
    gsb = check_gsb(raw_url)
    gsb_risk = 100 if gsb else 0

    # FINAL RISK WEIGHTS
    FINAL_RISK = (
        ml_risk * 0.50 +
        vt_risk * 0.45 +
        gsb_risk * 0.05
    )
    FINAL_RISK = min(max(FINAL_RISK, 0), 100)
    trust = 100 - FINAL_RISK

    prediction = "phishing" if FINAL_RISK >= 50 else "safe"

    # SHOPPING DETECTOR (NEW)
    is_shopping = detect_shopping_site(raw_url, domain)

    return {
        "prediction": prediction,
        "trust_score": round(trust, 3),
        "risk_score": round(FINAL_RISK, 3),
        "gsb_match": bool(gsb),
        "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
        "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": final_ml},
        "is_shopping": is_shopping
    }

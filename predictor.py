# predictor.py
import os
import pickle
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set
import traceback
import urllib.parse
import requests

MODEL_DIR = "models"

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
    print("Stacker inputs:", models["stacker"].coef_.shape[1])
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
        r = requests.post(endpoint, json=body, timeout=5)
        result = bool(r.json().get("matches"))
        cache_set(cache_key, result)
        return result
    except:
        return False


###############################################
# VIRUSTOTAL DOMAIN CHECK
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
        r = requests.get(url, headers=headers, timeout=6)
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        total = sum(stats.values()) if stats else 0
        mal = stats.get("malicious", 0) if stats else 0
        ratio = mal / total if total > 0 else 0

        cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
        return total, mal, ratio

    except:
        return 0, 0, 0.0


###############################################
# EXTRA RULES
###############################################
SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store"}
BRAND_LIST = ["nike", "adidas", "asics", "apple", "samsung", "puma", "uniqlo", "dhl", "fedex"]

def detect_brand_impersonation(domain):
    root = domain.split(".")[-2]
    for brand in BRAND_LIST:
        if brand in domain and not domain.endswith(brand + ".com"):
            return True
    return False

def detect_redirect_scam(url):
    return int("utm_" in url.lower() or "fbclid" in url.lower())


###############################################
# MAIN HYBRID PREDICTOR (NO WARNINGS VERSION)
###############################################
def predict_from_features(features, models, raw_url=None):
    feature_names = models["features"]

    # 🟢 FIXED: Build DataFrame WITH column names (no warnings)
    X = pd.DataFrame([[features.get(f, 0) for f in feature_names]], columns=feature_names)

    # ML Predictions
    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except:
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except:
        p_rf = 0.5

    # 🟢 FIXED: DataFrame for stacker
    stack_input = pd.DataFrame([[p_xgb, p_rf]], columns=["xgb", "rf"])

    try:
        final_ml = float(models["stacker"].predict_proba(stack_input)[0][1])
    except:
        final_ml = (p_xgb + p_rf) / 2

    ml_risk = final_ml * 100


    ###############################################
    # VIRUSTOTAL STRONG SIGNAL
    ###############################################
    try:
        domain = urllib.parse.urlparse(raw_url or "").netloc.lower().split(":")[0]
    except:
        domain = ""

    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)

    vt_risk = ((vt_ratio * 100) ** 2) / 100
    vt_risk = min(vt_risk, 100)


    ###############################################
    # GSB → Hard risk if flagged
    ###############################################
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100 if gsb_match else 0


    ###############################################
    # Extra domain rules
    ###############################################
    rule_risk = 0

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            rule_risk += 15

    if detect_brand_impersonation(domain):
        rule_risk += 25

    if detect_redirect_scam(raw_url):
        rule_risk += 10


    ###############################################
    # FINAL HYBRID WEIGHT
    ###############################################
    FINAL_RISK = (
        ml_risk * 0.50 +
        vt_risk * 0.45 +
        gsb_risk * 0.05 +
        rule_risk
    )

    FINAL_RISK = min(max(FINAL_RISK, 0), 100)
    trust = 100 - FINAL_RISK

    prediction = "phishing" if FINAL_RISK >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust, 3),
        "risk_score": round(FINAL_RISK, 3),
        "gsb_match": bool(gsb_match),
        "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
        "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": final_ml},
        "rule_risk": rule_risk
    }

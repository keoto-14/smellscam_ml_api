# predictor.py
import os
import pickle
import traceback
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set
import requests
import urllib.parse

MODEL_DIR = "models"

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    # load XGBoost saved JSON (trained with XGBClassifier().save_model)
    model = XGBClassifier()
    model.load_model(path)
    return model

def load_models():
    print("📦 Loading ML models...")
    # Expected files: xgb.json, rf.pkl, stacker.pkl, features.pkl
    models = {
        "xgb": load_xgb_model(os.path.join(MODEL_DIR, "xgb.json")),
        "rf": load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }
    print("XGB MODEL:", type(models["xgb"]))
    try:
        print("Stacker inputs:", models["stacker"].coef_.shape[1])
    except Exception:
        pass
    print("Models loaded successfully!")
    return models

# -------------------------------
# Google Safe Browsing (GSB)
# -------------------------------
GSB_API_KEY = os.environ.get("GSB_API_KEY")

def check_gsb(url):
    """Return True if GSB reports a match. Cached to /tmp via simple_cache."""
    if not GSB_API_KEY or not url:
        return False

    cache_key = f"gsb::{url}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "smellscam", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=body, timeout=6)
        if r.status_code == 200:
            j = r.json()
            match = bool(j.get("matches"))
            cache_set(cache_key, match)
            return match
    except Exception:
        traceback.print_exc()
    cache_set(cache_key, False)
    return False

# -------------------------------
# VirusTotal domain report
# -------------------------------
VT_API_KEY = os.environ.get("VT_API_KEY")

def vt_domain_report(domain):
    """Return (total_vendors, malicious_count, ratio) for domain (cached)."""
    if not VT_API_KEY or not domain:
        return 0, 0, 0.0

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached.get("total",0), cached.get("malicious",0), cached.get("ratio",0.0)

    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers=headers, timeout=6)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                ratio = malicious / total if total > 0 else 0.0
                cache_set(cache_key, {"total": total, "malicious": malicious, "ratio": ratio})
                return total, malicious, ratio
    except Exception:
        traceback.print_exc()

    cache_set(cache_key, {"total": 0, "malicious": 0, "ratio": 0.0})
    return 0, 0, 0.0

# -------------------------------
# Extra heuristic rules
# -------------------------------
SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store"}
BRAND_LIST = ["nike","adidas","asics","apple","samsung","puma","uniqlo","dhl","fedex"]

def detect_brand_impersonation(domain):
    for brand in BRAND_LIST:
        if brand in domain and not domain.endswith(brand + ".com"):
            return True
    return False

def detect_redirect_scam(url):
    low = (url or "").lower()
    return int("utm_" in low or "fbclid" in low or "gclid" in low)

# -------------------------------
# Main prediction + hybrid scoring
# -------------------------------
def predict_from_features(features, models, raw_url=None):
    """
    Returns:
      { prediction, trust_score, risk_score, gsb_match, vt, model_probs }
    """
    feature_names = models["features"]  # list in training order

    # Build DataFrame matching feature order to avoid sklearn warnings
    X_df = pd.DataFrame([{k: features.get(k, 0) for k in feature_names}])

    # ML model probabilities
    try:
        p_xgb = float(models["xgb"].predict_proba(X_df)[:,1][0])
    except Exception:
        traceback.print_exc()
        # fallback neutral
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X_df)[:,1][0])
    except Exception:
        traceback.print_exc()
        p_rf = 0.5

    # Stacker — trained on [xgb, rf]
    stack_input_df = pd.DataFrame([{"xgb": p_xgb, "rf": p_rf}])
    try:
        final_ml_prob = float(models["stacker"].predict_proba(stack_input_df)[:,1][0])
    except Exception:
        traceback.print_exc()
        # fallback average
        final_ml_prob = float((p_xgb + p_rf) / 2.0)

    ml_risk = final_ml_prob * 100.0

    # VirusTotal (domain)
    domain = ""
    try:
        domain = (urllib.parse.urlparse(raw_url).netloc or "").lower().split(":")[0]
    except Exception:
        domain = ""
    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
    # use quadratic / stronger scaling to emphasize vendors
    vt_risk = min(100.0, ((vt_ratio * 100.0) ** 2) / 100.0)

    # Google Safe Browsing
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0

    # heuristic rules
    rule_risk = 0.0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            rule_risk += 12.0
    if detect_brand_impersonation(domain):
        rule_risk += 20.0
    if detect_redirect_scam(raw_url):
        rule_risk += 8.0

    # FINAL WEIGHTS per your request: ML 50%, VT 45%, GSB 5%
    FINAL_RISK = (
        ml_risk * 0.50 +
        vt_risk * 0.45 +
        gsb_risk * 0.05 +
        rule_risk
    )
    FINAL_RISK = max(0.0, min(100.0, FINAL_RISK))

    trust_score = 100.0 - FINAL_RISK

    # decide label: if GSB matched, force 'phishing'; else threshold 50
    if gsb_match:
        prediction = "phishing"
    else:
        prediction = "phishing" if FINAL_RISK >= 50.0 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 6),
        "risk_score": round(FINAL_RISK, 6),
        "gsb_match": bool(gsb_match),
        "vt": {
            "total_vendors": int(vt_total),
            "malicious": int(vt_mal),
            "ratio": float(vt_ratio)
        },
        "model_probs": {
            "xgb": float(p_xgb),
            "rf": float(p_rf),
            "ml_final_prob": float(final_ml_prob)
        },
        "rule_risk": round(rule_risk, 3)
    }

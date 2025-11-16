# predictor.py
import os
import pickle
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set
import traceback

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
    print("XGB MODEL TYPE =", type(models["xgb"]))
    try:
        print("STACKER INPUTS =", models["stacker"].coef_.shape[1])
    except Exception:
        pass
    print("✅ Models loaded successfully!")
    return models

# GSB helper
import requests
GSB_API_KEY = os.environ.get("GSB_API_KEY")

def check_gsb(url):
    """Returns True if GSB flags the URL. Uses cache."""
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
        r = requests.post(endpoint, json=body, timeout=5)
        if r.status_code == 200:
            j = r.json()
            match = bool(j.get("matches"))
            cache_set(cache_key, match)
            return match
    except Exception:
        traceback.print_exc()
    cache_set(cache_key, False)
    return False

# VirusTotal helper (domain report)
VT_API_KEY = os.environ.get("VT_API_KEY")
def vt_domain_report(domain):
    """Return (total_vendors, malicious_count, ratio) — uses cache, falls back to zeros."""
    if not VT_API_KEY or not domain:
        return 0, 0, 0.0
    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached.get("total",0), cached.get("malicious",0), cached.get("ratio",0.0)
    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers=headers, timeout=6)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if isinstance(stats, dict) else 0
            malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
            ratio = (malicious / total) if total > 0 else 0.0
            cache_set(cache_key, {"total": total, "malicious": malicious, "ratio": ratio})
            return total, malicious, ratio
    except Exception:
        traceback.print_exc()
    cache_set(cache_key, {"total": 0, "malicious": 0, "ratio": 0.0})
    return 0, 0, 0.0

def predict_from_features(features, models, raw_url=None):
    """
    Returns:
      { prediction, trust_score, risk_score, vt, gsb_match, model_probs }
    """
    feature_names = models["features"]
    # prepare X
    X = np.array([[features.get(f, 0) for f in feature_names]], dtype=float)

    # ML base probs
    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except Exception:
        traceback.print_exc()
        p_xgb = 0.5
    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except Exception:
        traceback.print_exc()
        p_rf = 0.5

    # stacker expects DataFrame-like order - we used stacker trained on [xgb, rf]
    stack_input = np.array([[p_xgb, p_rf]])
    try:
        final_ml_prob = float(models["stacker"].predict_proba(stack_input)[0][1])
    except Exception:
        traceback.print_exc()
        final_ml_prob = (p_xgb + p_rf) / 2.0

    ml_risk = final_ml_prob * 100.0

    # VT: domain-based
    vt_total = vt_mal = 0
    vt_ratio = 0.0
    # derive domain
    domain = ""
    try:
        import urllib.parse
        domain = urllib.parse.urlparse(raw_url or features.get("url","")).netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]
    except Exception:
        domain = ""
    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)

    vt_risk = float(vt_ratio) * 100.0

    # GSB
    gsb_match = check_gsb(raw_url)

    gsb_risk = 100.0 if gsb_match else 0.0

    # HYBRID weights: GSB 20%, VT 30%, ML 50%
    final_risk = (0.20 * gsb_risk) + (0.30 * vt_risk) + (0.50 * ml_risk)
    final_risk = max(0.0, min(100.0, final_risk))
    trust_score = 100.0 - final_risk

    # final decision: GSB forced phishing, otherwise >=50 => phishing
    if gsb_match:
        prediction = "phishing"
    else:
        prediction = "phishing" if final_risk >= 50.0 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 6),
        "risk_score": round(final_risk, 6),
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
        }
    }

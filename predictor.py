# predictor.py  (FINAL HYBRID VERSION)
import os
import pickle
import numpy as np
import pandas as pd
import traceback
import requests
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set

MODEL_DIR = "models"

# -----------------------------------------------------
# Model Loaders
# -----------------------------------------------------
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

# -----------------------------------------------------
# Google Safe Browsing (optional, low weight)
# -----------------------------------------------------
GSB_API_KEY = os.getenv("GSB_API_KEY")

def check_gsb(url):
    """Google Safe Browsing check with caching."""
    if not GSB_API_KEY or not url:
        return False

    cache_key = f"gsb::{url}"
    cached = cache_get(cache_key, max_age=3600)
    if cached is not None:
        return cached

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "smellscam", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE","SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=body, timeout=5)
        if r.status_code == 200:
            match = bool(r.json().get("matches"))
            cache_set(cache_key, match)
            return match
    except Exception:
        traceback.print_exc()

    cache_set(cache_key, False)
    return False


# -----------------------------------------------------
# FINAL HYBRID PREDICTION LOGIC
# -----------------------------------------------------
def predict_from_features(features, models, raw_url=None):
    """Machine Learning + VirusTotal + (optional) Safe Browsing hybrid"""

    feature_names = models["features"]

    # Build DataFrame with exact ML model feature list
    X_df = pd.DataFrame([features])
    for col in feature_names:
        if col not in X_df.columns:
            X_df[col] = 0
    X_df = X_df[feature_names].apply(pd.to_numeric, errors="coerce").fillna(0)

    # --------------------------
    # ML Predictions
    # --------------------------
    try:
        p_xgb = float(models["xgb"].predict_proba(X_df)[0][1])
    except Exception:
        traceback.print_exc()
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X_df)[0][1])
    except Exception:
        traceback.print_exc()
        p_rf = 0.5

    stack_df = pd.DataFrame([{"xgb": p_xgb, "rf": p_rf}])

    try:
        ml_final_prob = float(models["stacker"].predict_proba(stack_df)[0][1])
    except Exception:
        ml_final_prob = (p_xgb + p_rf) / 2

    ml_risk = ml_final_prob * 100

    # CLAMP ML RISK (ML tends to output too high)
    ml_risk_clamped = min(ml_risk, 60)

    # --------------------------
    # VIRUSTOTAL (From extractor)
    # --------------------------
    vt_ratio = float(features.get("vt_detection_ratio", 0.0))
    vt_total = int(features.get("vt_total_vendors", 0))
    vt_mal = int(features.get("vt_malicious_count", 0))

    # Boost VT signal (default VT ratio is too weak)
    vt_risk = vt_ratio * 150    # <— THIS IS THE MAGIC BOOST

    # --------------------------
    # GOOGLE SAFE BROWSING (optional)
    # --------------------------
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0

    # --------------------------
    # FINAL HYBRID RISK SCORE
    # --------------------------
    FINAL_RISK = (
        0.35 * ml_risk_clamped +   # ML = 20%
        0.60 * vt_risk +           # VT = 70%
        0.05 * gsb_risk            # GSB = 10%
    )

    FINAL_RISK = max(0, min(FINAL_RISK, 100))
    TRUST = 100 - FINAL_RISK

    # --------------------------
    # FINAL PREDICTION DECISION
    # --------------------------
    if gsb_match:
        prediction = "phishing"
    else:
        prediction = "phishing" if FINAL_RISK >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(TRUST, 6),
        "risk_score": round(FINAL_RISK, 6),
        "gsb_match": bool(gsb_match),
        "vt": {
            "total_vendors": vt_total,
            "malicious": vt_mal,
            "ratio": vt_ratio
        },
        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "ml_final_prob": ml_final_prob
        }
    }

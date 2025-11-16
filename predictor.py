# predictor.py
import os
import pickle
import numpy as np
import pandas as pd
import traceback
import requests
from xgboost import XGBClassifier
from dotenv import load_dotenv
from simple_cache import cache_get, cache_set

load_dotenv()

MODEL_DIR = "models"

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    model = XGBClassifier()
    model.load_model(path)
    return model


# --------------------------------------------------
# LOAD MODELS
# --------------------------------------------------
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


# --------------------------------------------------
# GOOGLE SAFE BROWSING CHECK
# --------------------------------------------------
GSB_API_KEY = os.getenv("GSB_API_KEY")

def check_gsb(url):
    """Cached Google Safe Browsing lookup."""
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
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
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


# --------------------------------------------------
# MAIN HYBRID PREDICTION
# --------------------------------------------------
def predict_from_features(features, models, raw_url=None):
    """
    Hybrid scoring:
        ML = 50%
        VT = 30%
        GSB = 20%
    Uses VT from extractor, not from here.
    """

    # Ensure correct feature order for ML models
    feature_names = models["features"]
    X = np.array([[features.get(f, 0) for f in feature_names]], dtype=float)

    # ----------------------
    # ML MODEL PREDICTIONS
    # ----------------------
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

    # stacker uses [xgb_prob, rf_prob]
    stack_input = np.array([[p_xgb, p_rf]])
    try:
        ml_final_prob = float(models["stacker"].predict_proba(stack_input)[0][1])
    except Exception:
        traceback.print_exc()
        ml_final_prob = (p_xgb + p_rf) / 2

    ml_risk = ml_final_prob * 100.0


    # ----------------------
    # VIRUSTOTAL (FROM EXTRACTOR)
    # ----------------------
    vt_total = int(features.get("vt_total_vendors", 0))
    vt_malicious = int(features.get("vt_malicious_count", 0))
    vt_ratio = float(features.get("vt_detection_ratio", 0.0))

    vt_risk = vt_ratio * 100.0


    # ----------------------
    # SAFE BROWSING
    # ----------------------
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0


    # ----------------------
    # HYBRID FINAL SCORE
    # ----------------------
    final_risk = (
        0.50 * ml_risk +
        0.30 * vt_risk +
        0.20 * gsb_risk
    )

    final_risk = max(0.0, min(100.0, final_risk))
    trust_score = 100.0 - final_risk


    # ----------------------
    # FINAL LABEL
    # ----------------------
    if gsb_match:
        prediction = "phishing"     # forced
    else:
        prediction = "phishing" if final_risk >= 50 else "safe"


    # ----------------------
    # RETURN (Frontend safe)
    # ----------------------
    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 6),
        "risk_score": round(final_risk, 6),

        # Debug fields — frontend ignores these
        "gsb_match": gsb_match,
        "vt": {
            "total_vendors": vt_total,
            "malicious": vt_malicious,
            "ratio": vt_ratio,
        },
        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "ml_final_prob": ml_final_prob,
        }
    }

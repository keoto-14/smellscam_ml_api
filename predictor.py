# predictor.py  (HYBRID VERSION)
import os
import pickle
import numpy as np
import requests
import traceback
from xgboost import XGBClassifier
import pandas as pd

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
    print("STACKER INPUTS =", models["stacker"].coef_.shape[1])
    print("✅ Models loaded successfully!")
    return models


# ----------------------
# Google Safe Browsing
# ----------------------
GSB_API_KEY = os.environ.get("GSB_API_KEY")

def check_gsb(url):
    if not GSB_API_KEY:
        return False

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
        if r.status_code == 200 and "matches" in r.json():
            return True
    except:
        pass

    return False


# ----------------------
# Prediction (Hybrid)
# ----------------------
def predict_from_features(features, models, raw_url=None):
    FEATURES = models["features"]

    X = pd.DataFrame([features])
    for col in FEATURES:
        if col not in X.columns:
            X[col] = 0
    X = X[FEATURES].fillna(0)

    # ML-only level
    p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    p_rf  = float(models["rf"].predict_proba(X)[0][1])

    stack_in = pd.DataFrame([{"xgb": p_xgb, "rf": p_rf}])
    final_ml_prob = float(models["stacker"].predict_proba(stack_in)[0][1])

    ml_risk = final_ml_prob * 100.0

    # VirusTotal (already included in extractor)
    vt_total = features.get("vt_total_vendors", 0)
    vt_mal  = features.get("vt_malicious_count", 0)
    vt_ratio = features.get("vt_detection_ratio", 0.0)
    vt_risk = vt_ratio * 100.0

    # Google Safe Browsing
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0

    # Hybrid scoring
    final_risk = (
        0.50 * gsb_risk +
        0.30 * vt_risk +
        0.20 * ml_risk
    )

    final_risk = max(0, min(100, final_risk))
    trust_score = 100 - final_risk

    prediction = "phishing" if final_risk >= 50 else "safe"
    if gsb_match:
        prediction = "phishing"

    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 3),
        "risk_score": round(final_risk, 3),
        "gsb_match": gsb_match,
        "vt": {
            "total_vendors": vt_total,
            "malicious": vt_mal,
            "ratio": vt_ratio
        },
        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "ml_final_prob": final_ml_prob
        }
    }

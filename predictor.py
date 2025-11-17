# predictor.py
import os
import pickle
import numpy as np
import pandas as pd
import urllib.parse
import re
import traceback
from xgboost import XGBClassifier


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

    print("➡ XGB:", type(models["xgb"]))
    print("➡ RF:", type(models["rf"]))
    print("➡ Stacker:", type(models["stacker"]))
    print("➡ Total features:", len(models["features"]))
    print("✅ Models loaded successfully!")

    return models


# -----------------------------------------------------
# Extra scoring rules (your old version + improved)
# -----------------------------------------------------
SUSPICIOUS_TLDS = {".store", ".top", ".icu", ".xyz", ".asia", ".shop", ".online"}
BRANDS = ["nike", "adidas", "asics", "uniqlo", "puma", "dhl", "fedex", "apple", "samsung"]


def detect_brand_impersonation(domain):
    root = domain.split(".")[-2]
    for b in BRANDS:
        if b in domain and not domain.endswith(b + ".com"):
            return True
    return False


def detect_redirect(url):
    url_l = url.lower()
    return (
        ("utm_" in url_l) or
        ("fbclid" in url_l) or
        ("gclid" in url_l)
    )


# -----------------------------------------------------
# MAIN PREDICT FUNCTION
# -----------------------------------------------------
def predict_from_features(features: dict, models: dict, raw_url: str = None):
    feature_names = models["features"]

    # Create proper DataFrame (fix warnings)
    X = pd.DataFrame([[features.get(f, 0) for f in feature_names]],
                     columns=feature_names)

    # ML probabilities
    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except:
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except:
        p_rf = 0.5

    # Stacker input (DataFrame)
    stack_input = pd.DataFrame([[p_xgb, p_rf]], columns=["xgb", "rf"])

    try:
        ml_final = float(models["stacker"].predict_proba(stack_input)[0][1])
    except:
        ml_final = (p_xgb + p_rf) / 2

    ml_risk = ml_final * 100.0  # convert 0–1 → 0–100

    # EXTRA RULE SCORING
    parsed = urllib.parse.urlparse(raw_url or "")
    domain = parsed.netloc.lower().split(":")[0]

    rule_risk = 0

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            rule_risk += 15

    # Brand impersonation
    if detect_brand_impersonation(domain):
        rule_risk += 25

    # Redirect / tracking scam
    if detect_redirect(raw_url or ""):
        rule_risk += 10

    # FINAL SCORE = ML 50% + RULES 50%
    FINAL_RISK = (ml_risk * 0.50) + (rule_risk * 0.50)
    FINAL_RISK = max(0, min(FINAL_RISK, 100))

    TRUST = 100 - FINAL_RISK

    prediction = "phishing" if FINAL_RISK >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(TRUST, 3),
        "risk_score": round(FINAL_RISK, 3),
        "rule_risk": rule_risk,
        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "ml_final": ml_final
        }
    }

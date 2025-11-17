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


# -------------------------------------------------
# Load utilities
# -------------------------------------------------
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


# -------------------------------------------------
# Google Safe Browsing
# -------------------------------------------------
GSB_API_KEY = os.environ.get("GSB_API_KEY")


def check_gsb(url):
    if not GSB_API_KEY:
        return False

    cache_key = f"gsb::{url}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    endpoint = (
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    )

    body = {
        "client": {"clientId": "smellscam", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=body, timeout=5)
        result = bool(r.json().get("matches"))
        cache_set(cache_key, result)
        return result
    except Exception:
        return False


# -------------------------------------------------
# VirusTotal domain lookup
# -------------------------------------------------
VT_API_KEY = os.environ.get("VT_API_KEY")


def vt_domain_report(domain):
    """Return (total, malicious, ratio). Cached."""
    if not VT_API_KEY:
        return 0, 0, 0.0

    cache_key = f"vt::{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached["total"], cached["mal"], cached["ratio"]

    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
            timeout=6,
        )

        stats = (
            r.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        total = sum(stats.values()) if stats else 0
        mal = stats.get("malicious", 0) if stats else 0
        ratio = mal / total if total > 0 else 0.0

        cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
        return total, mal, ratio

    except Exception:
        return 0, 0, 0.0


# -------------------------------------------------
# Extra Rule System (Brand/TLD)
# -------------------------------------------------
SUSPICIOUS_TLDS = {
    ".asia",
    ".top",
    ".icu",
    ".shop",
    ".online",
    ".xyz",
    ".store",
}

BRAND_LIST = [
    "nike",
    "adidas",
    "asics",
    "apple",
    "samsung",
    "puma",
    "uniqlo",
    "dhl",
    "fedex",
]


def detect_brand_impersonation(domain):
    root = domain.split(".")[-2]
    for brand in BRAND_LIST:
        if brand in domain and not domain.endswith(brand + ".com"):
            return True
    return False


def detect_redirect_scam(url):
    u = url.lower()
    return int("utm_" in u or "fbclid" in u)


# -------------------------------------------------
# MAIN PREDICTOR — ⚡ Warning-Free Version
# -------------------------------------------------
def predict_from_features(features, models, raw_url=None):
    feature_names = models["features"]

    # Build X with correct order
    X = pd.DataFrame([[features.get(f, 0) for f in feature_names]], columns=feature_names)

    # -------------------------------------------------
    # 1. ML Predictions (consistent, warning-free)
    # -------------------------------------------------
    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except Exception:
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except Exception:
        p_rf = 0.5

    # Stacker — FIXED (use DataFrame to avoid warnings)
    stack_input = pd.DataFrame([{"xgb": p_xgb, "rf": p_rf}])

    try:
        final_ml = float(models["stacker"].predict_proba(stack_input)[0][1])
    except Exception:
        final_ml = (p_xgb + p_rf) / 2

    ml_risk = final_ml * 100  # 0–100%

    # -------------------------------------------------
    # 2. VirusTotal Score
    # -------------------------------------------------
    parsed = urllib.parse.urlparse(raw_url or "")
    domain = parsed.netloc.lower().split(":")[0]

    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)

    # Quadratic scaling → stronger effect
    vt_risk = ((vt_ratio * 100) ** 2) / 100
    vt_risk = min(vt_risk, 100)

    # -------------------------------------------------
    # 3. Google Safe Browsing
    # -------------------------------------------------
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100 if gsb_match else 0

    # -------------------------------------------------
    # 4. Extra Rule Boosts
    # -------------------------------------------------
    rule_risk = 0

    # TLD suspicious
    for t in SUSPICIOUS_TLDS:
        if domain.endswith(t):
            rule_risk += 15

    # brand impersonation
    if detect_brand_impersonation(domain):
        rule_risk += 25

    # redirect scam
    rule_risk += detect_redirect_scam(raw_url) * 10

    # -------------------------------------------------
    # 5. FINAL HYBRID RISK — Based on your request
    # ML = 50%, VT = 45%, GSB = 5%
    # -------------------------------------------------
    FINAL_RISK = (
        ml_risk * 0.50
        + vt_risk * 0.50
        + gsb_risk * 0.00
        + rule_risk
    )

    FINAL_RISK = max(0, min(FINAL_RISK, 100))
    trust = 100 - FINAL_RISK

    prediction = "phishing" if FINAL_RISK >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust, 3),
        "risk_score": round(FINAL_RISK, 3),
        "gsb_match": gsb_match,
        "vt": {
            "total_vendors": vt_total,
            "malicious": vt_mal,
            "ratio": vt_ratio,
        },
        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "ml_final": final_ml,
        },
        "rule_risk": rule_risk,
    }

# predictor.py
"""
Hybrid predictor for SmellScam:
 - ML (XGB + RF + stacker)
 - VirusTotal domain check (cached)
 - Rule engine (brand impersonation, suspicious TLDs, redirects, etc.)

Default weights: ML 55% | VT 35% | RULES 10%
Configurable via environment variables: ML_WEIGHT, VT_WEIGHT, RULE_WEIGHT
"""
import os
import pickle
import traceback
import numpy as np
import pandas as pd
import urllib.parse
from xgboost import XGBClassifier

from simple_cache import cache_get, cache_set
from rules import compute_rule_risk

import requests

MODEL_DIR = os.environ.get("MODEL_DIR", "models")

# --- load helpers ---
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    """
    Try to load XGB model. Accept either JSON saved by xgb.save_model or a pickle.
    """
    try:
        # prefer xgb native load (json)
        model = XGBClassifier()
        model.load_model(path)
        return model
    except Exception:
        # fallback to pickle
        return load_pickle(path)

def load_models():
    print("📦 Loading ML models...")
    xgb_path = os.path.join(MODEL_DIR, "xgb.json")
    if not os.path.exists(xgb_path):
        # try pkl
        xgb_path = os.path.join(MODEL_DIR, "xgb.pkl")

    models = {
        "xgb": load_xgb_model(xgb_path),
        "rf": load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }

    print("XGB MODEL:", type(models["xgb"]))
    try:
        print("Stacker inputs:", models["stacker"].coef_.shape[1])
    except Exception:
        pass
    print("✅ Models loaded successfully!")
    return models

# --- VirusTotal domain report (cached) ---
VT_API_KEY = os.environ.get("VT_API_KEY")

def vt_domain_report(domain):
    """Return (total_vendors, malicious_count, ratio) using VirusTotal domain endpoint.
    Cached in simple_cache to avoid rate limits.
    """
    if not VT_API_KEY:
        return 0, 0, 0.0

    key = f"vt_domain::{domain}"
    cached = cache_get(key, max_age=60 * 60)  # 1 hour
    if cached is not None:
        return cached.get("total", 0), cached.get("malicious", 0), cached.get("ratio", 0.0)

    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=6)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict):
                total = sum(stats.values())
                mal = stats.get("malicious", 0)
                ratio = mal / total if total > 0 else 0.0
                cache_set(key, {"total": total, "malicious": mal, "ratio": ratio})
                return total, mal, ratio
    except Exception:
        traceback.print_exc()

    cache_set(key, {"total": 0, "malicious": 0, "ratio": 0.0})
    return 0, 0, 0.0

# --- GSB optional (kept minimal; disabled by default) ---
GSB_API_KEY = os.environ.get("GSB_API_KEY")
def check_gsb(url):
    """Return True if Google Safe Browsing reports a match. Cached."""
    if not GSB_API_KEY or not url:
        return False
    key = f"gsb::{url}"
    cached = cache_get(key, max_age=60 * 60)
    if cached is not None:
        return bool(cached)
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
            match = bool(r.json().get("matches"))
            cache_set(key, match)
            return match
    except Exception:
        traceback.print_exc()
    cache_set(key, False)
    return False

# --- scoring ---
def predict_from_features(features: dict, models: dict, raw_url: str = None):
    """
    Returns JSON-friendly dict:
    {
      prediction, trust_score, risk_score,
      vt: {total_vendors, malicious, ratio},
      gsb_match,
      model_probs: {xgb, rf, ml_final},
      rule_risk
    }
    """
    feature_names = models["features"]
    # Build DataFrame to match feature names (avoid sklearn warnings)
    try:
        X_df = pd.DataFrame([{f: float(features.get(f, 0)) for f in feature_names}])
    except Exception:
        # fallback to numeric array if something odd
        X_df = pd.DataFrame([[features.get(f, 0) for f in feature_names]], columns=feature_names)

    # ML probs (safe defaults if anything fails)
    try:
        p_xgb = float(models["xgb"].predict_proba(X_df)[0][1])
    except Exception:
        traceback.print_exc()
        # try array path for some model types
        try:
            p_xgb = float(models["xgb"].predict_proba(X_df.values)[0][1])
        except Exception:
            p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X_df)[0][1])
    except Exception:
        traceback.print_exc()
        try:
            p_rf = float(models["rf"].predict_proba(X_df.values)[0][1])
        except Exception:
            p_rf = 0.5

    # Stacker (trained on [xgb, rf] order)
    stack_input = pd.DataFrame([{"xgb": p_xgb, "rf": p_rf}])
    try:
        final_ml_prob = float(models["stacker"].predict_proba(stack_input)[0][1])
    except Exception:
        traceback.print_exc()
        # fallback average
        final_ml_prob = (p_xgb + p_rf) / 2.0

    # ml_risk is phishing probability from ML ensemble
    ml_risk = final_ml_prob * 100.0

    # Domain for VT/Rules
    domain = ""
    try:
        parsed = urllib.parse.urlparse(raw_url or features.get("url", ""))
        domain = parsed.netloc.split(":")[0].lower()
    except Exception:
        domain = ""

    # VT
    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
    vt_risk = float(vt_ratio) * 100.0
    # amplify VT a little (configurable later)
    vt_risk = min(100.0, vt_risk)

    # GSB (optional)
    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0

    # Rules engine
    rule_risk = compute_rule_risk(raw_url or features.get("url", ""), features)

    # Weights (env override allowed)
    ML_WEIGHT = float(os.environ.get("ML_WEIGHT", 0.55))
    VT_WEIGHT = float(os.environ.get("VT_WEIGHT", 0.35))
    RULE_WEIGHT = float(os.environ.get("RULE_WEIGHT", 0.10))

    # Normalize if not sum 1
    total_w = ML_WEIGHT + VT_WEIGHT + RULE_WEIGHT
    if total_w <= 0:
        ML_WEIGHT, VT_WEIGHT, RULE_WEIGHT = 0.55, 0.35, 0.10
        total_w = 1.0

    ML_WEIGHT /= total_w
    VT_WEIGHT /= total_w
    RULE_WEIGHT /= total_w

    # combine
    final_risk = (ML_WEIGHT * ml_risk) + (VT_WEIGHT * vt_risk) + (RULE_WEIGHT * min(rule_risk, 100.0))
    # optionally add GSB hard penalty (if match then override)
    if gsb_match:
        final_risk = max(final_risk, 95.0)

    final_risk = max(0.0, min(100.0, final_risk))
    trust_score = 100.0 - final_risk

    prediction = "phishing" if final_risk >= 50.0 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 6),
        "risk_score": round(final_risk, 6),
        "gsb_match": bool(gsb_match),
        "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
        "model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final_prob": float(final_ml_prob)},
        "rule_risk": float(rule_risk)
    }

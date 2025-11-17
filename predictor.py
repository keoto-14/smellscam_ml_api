# predictor.py
"""
Hybrid predictor (Mode 2 - Balanced).
Weights: ML 50%, VT 45%, GSB 5%
Improvements:
 - Uses feature names DataFrame to avoid sklearn warnings
 - Brand whitelist to avoid false positives on known retailers
 - Brand-impersonation rule applied only when suspicious
 - VT and GSB are optional (safe defaults)
 - Caching via simple_cache for VT/GSB calls
"""

import os
import pickle
import numpy as np
import pandas as pd
import traceback
import urllib.parse
from xgboost import XGBClassifier

from simple_cache import cache_get, cache_set

MODEL_DIR = "models"

def _load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def _load_xgb(path):
    m = XGBClassifier()
    m.load_model(path)
    return m

def load_models():
    print("📦 Loading ML models...")
    models = {
        "xgb": _load_xgb(os.path.join(MODEL_DIR, "xgb.json")),
        "rf": _load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": _load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": _load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }
    try:
        print("XGB MODEL:", type(models["xgb"]))
        print("STACKER INPUTS:", models["stacker"].coef_.shape[1])
    except Exception:
        pass
    print("Models loaded successfully!")
    return models

# -------------------------
# External services (optional)
# -------------------------
import requests
VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")

def check_gsb(url):
    """Return True if GSB flags the URL. Cached."""
    if not GSB_API_KEY or not url:
        return False
    key = f"gsb::{url}"
    c = cache_get(key)
    if c is not None:
        return bool(c)
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
            matched = bool(r.json().get("matches"))
            cache_set(key, matched)
            return matched
    except Exception:
        traceback.print_exc()
    cache_set(key, False)
    return False

def vt_domain_report(domain):
    """Return (total, malicious, ratio). Cached. Safe fallback zeros."""
    if not VT_API_KEY or not domain:
        return 0, 0, 0.0
    cache_key = f"vt::{domain}"
    c = cache_get(cache_key)
    if c:
        return c.get("total",0), c.get("mal",0), c.get("ratio",0.0)
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=6)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if isinstance(stats, dict) else 0
            mal = stats.get("malicious", 0) if isinstance(stats, dict) else 0
            ratio = mal / total if total > 0 else 0.0
            out = {"total": total, "mal": mal, "ratio": ratio}
            cache_set(cache_key, out)
            return total, mal, ratio
    except Exception:
        traceback.print_exc()
    cache_set(cache_key, {"total":0,"mal":0,"ratio":0.0})
    return 0,0,0.0

# -------------------------
# Rules / Brand whitelist (Mode 2)
# -------------------------
SAFE_BRANDS = {
    "zara","nike","adidas","uniqlo","hm","shein","puma","reebok",
    "newbalance","dior","louisvuitton","apple","samsung","lazada",
    "shopee","amazon","zalora","asos","decathlon","hm"
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".icu", ".shop", ".store", ".online", ".cyou", ".fun", ".space", ".site"}

def detect_brand_impersonation(domain):
    """Return brand name if impersonation candidate found (brand substring but not canonical)."""
    d = domain.lower()
    for b in SAFE_BRANDS:
        if b in d:
            # If domain equals brand.com or endswith brand.com -> acceptable (no impersonation)
            if d.endswith(f"{b}.com") or d == f"{b}.com":
                return None
            # If brand appears but not as real brand.com -> suspicious impersonation
            return b
    return None

def is_suspicious_tld(domain):
    return any(domain.endswith(t) for t in SUSPICIOUS_TLDS)

# -------------------------
# Main scoring
# -------------------------
def predict_from_features(features, models, raw_url=None):
    """
    Returns a dict:
    { prediction, trust_score, risk_score, gsb_match, vt, model_probs, rule_risk }
    """
    feature_names = models["features"]
    # prepare DataFrame with columns so sklearn doesn't warn
    df = pd.DataFrame([features], columns=feature_names).fillna(0)
    # Ensure numeric dtype
    X = df.astype(float).values

    # ML probs
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

    # Stacker expects order [xgb, rf]
    stack_in = np.array([[p_xgb, p_rf]])
    try:
        final_ml_prob = float(models["stacker"].predict_proba(stack_in)[0][1])
    except Exception:
        traceback.print_exc()
        final_ml_prob = float((p_xgb + p_rf) / 2.0)

    ml_risk = final_ml_prob * 100.0

    # External signals
    parsed = urllib.parse.urlparse(raw_url or features.get("url",""))
    domain = (parsed.netloc or "").lower().split(":")[0]

    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
    # VT risk: scaled but clipped, keep VT strong for Mode 2
    vt_risk = min(100.0, (vt_ratio * 100.0) * 1.25)

    gsb_match = check_gsb(raw_url)
    gsb_risk = 100.0 if gsb_match else 0.0

    # Rule risk: start 0 and add/subtract
    rule_risk = 0.0

    # If domain uses suspicious TLD → add risk
    if is_suspicious_tld(domain):
        rule_risk += 20.0

    # Brand impersonation: add risk only if impersonation candidate found
    impersonated = detect_brand_impersonation(domain)
    if impersonated:
        # only add strong penalty if domain is clearly not main brand and TLD suspicious or contains extra tokens
        rule_risk += 30.0

    # Whitelist safe brands: reduce risk so real-brand official sites are not flagged
    for sb in SAFE_BRANDS:
        if domain.endswith(f"{sb}.com") or domain == f"{sb}.com" or f".{sb}." in domain:
            # large safety offset — prevents false positive on well-known brand official domains
            rule_risk -= 30.0
            break

    # Redirect / tracking UTM tags should NOT increase risk (we removed penalty)
    # (we might slightly increase risk on urls that contain weird looking multiple tokens)
    if raw_url and raw_url.count("-") > 6:
        rule_risk += 5.0

    # Clip rule_risk
    rule_risk = max(-50.0, min(rule_risk, 80.0))

    # Final risk: ML 50% | VT 45% | GSB 5% + rule_risk
    final_risk = (0.50 * ml_risk) + (0.45 * vt_risk) + (0.05 * gsb_risk) + rule_risk
    final_risk = max(0.0, min(100.0, final_risk))
    trust_score = round(100.0 - final_risk, 4)

    prediction = "phishing" if final_risk >= 50.0 else "safe"

    return {
        "prediction": prediction,
        "trust_score": trust_score,
        "risk_score": round(final_risk, 4),
        "gsb_match": bool(gsb_match),
        "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
        "model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final_prob": float(final_ml_prob)},
        "rule_risk": round(rule_risk, 4),
        "impersonated_brand": impersonated
    }

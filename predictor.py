import os
import pickle
import numpy as np
import re
import urllib.parse
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set
import traceback
import requests

MODEL_DIR = "models"


# -----------------------------------------------------------
# Load models
# -----------------------------------------------------------
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


# -----------------------------------------------------------
# Google Safe Browsing
# -----------------------------------------------------------
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
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=body, timeout=5)
        found = bool(r.json().get("matches"))
        cache_set(cache_key, found)
        return found
    except:
        return False


# -----------------------------------------------------------
# VirusTotal Domain Lookups
# -----------------------------------------------------------
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


# -----------------------------------------------------------
# ONLINE SHOPPING DETECTOR (CRITICAL)
# -----------------------------------------------------------
SHOPPING_KEYWORDS = [
    "shop", "store", "product", "cart", "checkout", "sale", "buy",
    "sell", "item", "collection", "category", "bag", "wishlist",
    "clothes", "shoes", "fashion", "brand", "official", "order"
]

PRODUCT_HINTS = [
    "nike", "adidas", "asics", "uniqlo", "zara", "h&m", "puma",
    "jordan", "apple", "samsung", "xiaomi", "laptop", "phone",
    "sneaker", "tshirt", "hoodie", "watch", "bag"
]

BAD_TLDS = {".xyz", ".top", ".site", ".online", ".rest", ".info", ".monster"}


def is_shopping_site(url):
    """
    Returns:
        score (0–100)
    If < 30 → "not shopping website"
    """

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    score = 0

    # Keywords in domain
    for k in SHOPPING_KEYWORDS:
        if k in host:
            score += 25
            break

    # Product hints
    for p in PRODUCT_HINTS:
        if p in url.lower():
            score += 20
            break

    # e-commerce patterns
    if any(x in path for x in ["/product", "/products", "/shop", "/store"]):
        score += 30

    if "checkout" in path or "cart" in path:
        score += 40

    # bad TLD reduces confidence
    for t in BAD_TLDS:
        if host.endswith(t):
            score -= 20

    return max(0, min(100, score))


# -----------------------------------------------------------
# MAIN PREDICTION ENGINE
# -----------------------------------------------------------
def predict_from_features(features, models, raw_url=None):

    # -------------------------------------------
    # 1) Online shopping filter FIRST
    # -------------------------------------------
    shop_score = is_shopping_site(raw_url or "")

    if shop_score < 30:
        return {
            "prediction": "not_shopping_site",
            "trust_score": None,
            "reason": "URL is not an online shopping website",
            "shopping_score": shop_score
        }

    # -------------------------------------------
    # 2) ML features → XGB + RF + Stacker
    # -------------------------------------------
    feature_names = models["features"]
    X = np.array([[features.get(f, 0) for f in feature_names]], dtype=float)

    try:
        p_xgb = float(models["xgb"].predict_proba(X)[0][1])
    except:
        p_xgb = 0.5

    try:
        p_rf = float(models["rf"].predict_proba(X)[0][1])
    except:
        p_rf = 0.5

    stack_input = np.array([[p_xgb, p_rf]])

    try:
        final_ml = float(models["stacker"].predict_proba(stack_input)[0][1])
    except:
        final_ml = (p_xgb + p_rf) / 2

    ml_risk = final_ml * 100

    # -------------------------------------------
    # 3) VirusTotal
    # -------------------------------------------
    parsed = urllib.parse.urlparse(raw_url)
    domain = parsed.netloc.lower().split(":")[0]

    vt_total, vt_mal, vt_ratio = vt_domain_report(domain)
    vt_risk = min((vt_ratio * 100) ** 2 / 100, 100)

    # -------------------------------------------
    # 4) Google Safe Browsing
    # -------------------------------------------
    gsb_hit = check_gsb(raw_url)
    gsb_risk = 100 if gsb_hit else 0

    # -------------------------------------------
    # 5) FINAL HYBRID SCORE (your weights)
    # ML = 50    VT = 45    GSB = 5
    # -------------------------------------------
    TOTAL_RISK = (
        ml_risk * 0.40 +
        vt_risk * 0.60 +
        gsb_risk * 0.00
    )

    TOTAL_RISK = max(0, min(100, TOTAL_RISK))
    trust_score = 100 - TOTAL_RISK

    prediction = "phishing" if TOTAL_RISK >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust_score, 2),
        "risk_score": round(TOTAL_RISK, 2),

        "shopping_score": shop_score,

        "vt": {
            "total_vendors": vt_total,
            "malicious": vt_mal,
            "ratio": vt_ratio
        },

        "gsb_match": bool(gsb_hit),

        "model_probs": {
            "xgb": p_xgb,
            "rf": p_rf,
            "stacker_final": final_ml
        }
    }

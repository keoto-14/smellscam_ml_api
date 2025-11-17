import os
import pickle
import urllib.parse
import numpy as np
from xgboost import XGBClassifier
from simple_cache import cache_get, cache_set
from url_feature_extractor import safe_request

###############################################
# LOAD MODELS
###############################################

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
    print("Models loaded successfully!")
    return models


###############################################
# SHOPPING WEBSITE DETECTOR
###############################################

SHOPPING_KEYWORDS = [
    "add to cart", "cart", "checkout", "shop", "store",
    "product", "products", "item", "buy", "buy now",
    "sale", "new arrivals", "order", "wishlist"
]

def is_shopping_website(url, html=""):
    url_l = url.lower()

    # URL-based cues
    for kw in SHOPPING_KEYWORDS:
        if kw.replace(" ", "") in url_l.replace(" ", ""):
            return True

    # HTML-based cues (stronger signal)
    html_l = html.lower()
    for kw in SHOPPING_KEYWORDS:
        if kw in html_l:
            return True

    return False



###############################################
# ML PREDICTOR
###############################################
def predict_from_features(features, models, raw_url=None):

    # ---------------------------------------------------
    # 0) SHOPPING CHECK (HTML + URL)
    # ---------------------------------------------------
    html = safe_request(raw_url, timeout=5)

    if not is_shopping_website(raw_url, html):
        return {
            "error": "not_shopping",
            "message": "Sorry, this link is not an online shopping website.",
            "prediction": "safe",
            "trust_score": 100,
            "risk_score": 0
        }

    # ---------------------------------------------------
    # 1) ML PREDICTION
    # ---------------------------------------------------
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

    trust = 100 - ml_risk
    prediction = "phishing" if ml_risk >= 50 else "safe"

    return {
        "prediction": prediction,
        "trust_score": round(trust, 2),
        "risk_score": round(ml_risk, 2),
        "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": final_ml}
    }

# predictor.py
import pickle
import pandas as pd
import os
from xgboost import XGBClassifier

MODEL_DIR = "models"

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    model = XGBClassifier()
    model.load_model(path)   # <── THE CORRECT WAY
    return model

def load_models():
    print("📦 Loading ML models...")

    models = {
        "lgbm": load_pickle(os.path.join(MODEL_DIR, "lgbm.pkl")),
        "xgb":  load_xgb_model(os.path.join(MODEL_DIR, "xgb.json")),   # <── FIXED
        "rf":   load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }

    print("XGB MODEL TYPE =", type(models["xgb"]))
    print("✅ All models loaded!")
    return models

def predict_from_features(features, models):
    FEATURES = models["features"]

    X = pd.DataFrame([features])

    # ensure all required feature columns exist
    for col in FEATURES:
        if col not in X.columns:
            X[col] = 0

    X = X[FEATURES].fillna(0)

    # Predict probabilities
    p_lgb = models["lgbm"].predict_proba(X)[:, 1][0]
    p_xgb = models["xgb"].predict_proba(X)[:, 1][0]
    p_rf  = models["rf"].predict_proba(X)[:, 1][0]

    stack_input = pd.DataFrame([{
        "lgb": p_lgb,
        "xgb": p_xgb,
        "rf":  p_rf,
    }])

    final_proba = models["stacker"].predict_proba(stack_input)[:, 1][0]

    label = "phishing" if final_proba > 0.5 else "legitimate"

    return {
        "prediction": label,
        "risk_score": round(final_proba * 100, 2),
        "model_probs": {
            "lgbm": p_lgb,
            "xgb": p_xgb,
            "rf": p_rf
        }
    }

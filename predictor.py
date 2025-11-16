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


def predict_from_features(features, models):
    FEATURES = models["features"]

    X = pd.DataFrame([features])

    # Ensure missing columns exist
    for col in FEATURES:
        if col not in X.columns:
            X[col] = 0

    X = X[FEATURES].fillna(0)

    # Base model predictions
    p_xgb = models["xgb"].predict_proba(X)[:, 1][0]
    p_rf  = models["rf"].predict_proba(X)[:, 1][0]

    # Stacker input (only XGB + RF)
    stack_input = pd.DataFrame([{
        "xgb": p_xgb,
        "rf":  p_rf,
    }])

    final_proba = models["stacker"].predict_proba(stack_input)[:, 1][0]
    label = "phishing" if final_proba > 0.5 else "legitimate"

    return {
        "prediction": label,
        "risk_score": round(final_proba * 100, 2),
        "model_probs": {
            "xgb": float(p_xgb),
            "rf": float(p_rf),
        }
    }

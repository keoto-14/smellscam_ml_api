# predictor.py
import pickle
import os
import numpy as np
from xgboost import XGBClassifier

MODEL_DIR = "models"

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    model = XGBClassifier()
    model.load_model(path)  # Modern, version-safe
    return model

def load_models():
    print("📦 Loading ML models...")

    models = {
        "xgb": load_xgb_model(os.path.join(MODEL_DIR, "xgb.json")),
        "rf": load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "lgbm": load_pickle(os.path.join(MODEL_DIR, "lgbm.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }

    print("✅ Models Loaded!")
    return models

def predict_from_features(features, models):
    feature_names = models["features"]

    # Convert feature dict → ordered numpy array
    X = np.array([[features[f] for f in feature_names]])

    # Individual model probabilities
    p_lgb  = models["lgbm"].predict_proba(X)[0][1]
    p_xgb  = models["xgb"].predict_proba(X)[0][1]
    p_rf   = models["rf"].predict_proba(X)[0][1]

    # Meta-model (stacker)
    stacked_input = np.array([[p_lgb, p_xgb, p_rf]])
    final_prob = models["stacker"].predict_proba(stacked_input)[0][1]

    prediction = "scam" if final_prob > 0.5 else "safe"

    return {
        "prediction": prediction,
        "risk_score": round(final_prob * 100, 2),
        "probabilities": {
            "lightgbm": float(p_lgb),
            "xgboost": float(p_xgb),
            "random_forest": float(p_rf),
            "final": float(final_prob),
        }
    }

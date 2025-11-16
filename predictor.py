import pickle
import os
import numpy as np

MODEL_DIR = "models"


def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_models():
    print("📦 Loading ML models...")

    models = {
        "lgbm": load_pickle(os.path.join(MODEL_DIR, "lgbm.pkl")),
        "xgb": load_pickle(os.path.join(MODEL_DIR, "xgb.pkl")),
        "rf": load_pickle(os.path.join(MODEL_DIR, "rf.pkl")),
        "stacker": load_pickle(os.path.join(MODEL_DIR, "stacker.pkl")),
        "features": load_pickle(os.path.join(MODEL_DIR, "features.pkl")),
    }

    print("✅ Models Loaded!")
    return models


def predict_from_features(features, models):
    feature_names = models["features"]

    # Convert dict → model input
    X = np.array([[features[f] for f in feature_names]])

    # Base model probabilities
    p_lgbm = models["lgbm"].predict_proba(X)[0][1]
    p_xgb = models["xgb"].predict_proba(X)[0][1]
    p_rf = models["rf"].predict_proba(X)[0][1]

    # Stacker final model
    stacked_input = np.array([[p_lgbm, p_xgb, p_rf]])
    final_prob = models["stacker"].predict_proba(stacked_input)[0][1]

    prediction = "scam" if final_prob > 0.5 else "safe"

    return {
        "prediction": prediction,
        "risk_score": round(final_prob * 100, 2),
        "probabilities": {
            "lgbm": float(p_lgbm),
            "xgb": float(p_xgb),
            "rf": float(p_rf),
            "final": float(final_prob),
        }
    }

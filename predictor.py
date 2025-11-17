# predictor.py
import os
import pickle
import traceback
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

MODEL_DIR = os.environ.get("MODEL_DIR", "models")

def _load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def _load_xgb(path):
    """
    Load XGBoost model saved with XGBClassifier().save_model("xgb.json")
    Returns an XGBClassifier instance with the model loaded.
    """
    model = XGBClassifier()
    model.load_model(path)
    return model

def load_models():
    """
    Loads models from MODEL_DIR and returns dict.
    Expected files:
      - models/xgb.json          (optional)
      - models/rf.pkl
      - models/stacker.pkl
      - models/features.pkl     (list of feature names in correct order)
    """
    print("📦 Loading ML models...")

    models = {}
    try:
        xgb_path = os.path.join(MODEL_DIR, "xgb.json")
        if os.path.exists(xgb_path):
            models["xgb"] = _load_xgb(xgb_path)
            print(" - xgb loaded:", type(models["xgb"]))
        else:
            print(" - xgb not found:", xgb_path)
            models["xgb"] = None
    except Exception:
        traceback.print_exc()
        models["xgb"] = None

    try:
        rf_path = os.path.join(MODEL_DIR, "rf.pkl")
        models["rf"] = _load_pickle(rf_path)
        print(" - rf loaded:", type(models["rf"]))
    except Exception:
        traceback.print_exc()
        models["rf"] = None

    try:
        stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
        models["stacker"] = _load_pickle(stacker_path)
        print(" - stacker loaded:", type(models["stacker"]))
    except Exception:
        traceback.print_exc()
        models["stacker"] = None

    try:
        features_path = os.path.join(MODEL_DIR, "features.pkl")
        models["features"] = _load_pickle(features_path)
        # features should be a list/iterable of column names used in training
        print(" - features loaded: %d features" % len(models["features"]))
    except Exception:
        traceback.print_exc()
        models["features"] = None

    print("✅ Model load finished.")
    return models


# helper: build stacker input DataFrame matching required column names
def _build_stacker_input_dict(probs_dict, stacker):
    """
    probs_dict: {"xgb": float, "rf": float, "lgb": float, ...}
    stacker: trained sklearn estimator (LogisticRegression, etc.)
    returns: Ordered dict / dataframe row that matches stacker.feature_names_in_ if present
    """
    # Preferred: use feature_names_in_ (sklearn 1.0+)
    if stacker is None:
        # best-effort: return xgb, rf if present
        keys = ["xgb", "rf", "lgb"]
        return {k: float(probs_dict.get(k, 0.5)) for k in keys if k in probs_dict}

    # sklearn exposes .feature_names_in_ for many estimators when trained with DataFrame
    if hasattr(stacker, "feature_names_in_"):
        req = list(stacker.feature_names_in_)
        return {name: float(probs_dict.get(name, 0.5)) for name in req}

    # fallback: try to infer number of inputs from coef_
    try:
        n_in = stacker.coef_.shape[1]
        # common stacking orders: ['xgb','rf','lgb'], or ['lgb','xgb','rf']
        common_orders = [
            ["lgb", "xgb", "rf"],
            ["xgb", "rf", "lgb"],
            ["xgb", "rf"],
            ["rf", "xgb"]
        ]
        for order in common_orders:
            if len(order) == n_in:
                return {k: float(probs_dict.get(k, 0.5)) for k in order}
    except Exception:
        pass

    # last resort: return available probabilities in deterministic order
    out = {}
    for k in sorted(probs_dict.keys()):
        if len(out) >= (stacker.coef_.shape[1] if hasattr(stacker, "coef_") else len(probs_dict)):
            break
        out[k] = float(probs_dict[k])
    return out


def predict_from_features(features: dict, models: dict, raw_url: str = None):
    """
    features: dict mapping feature_name -> value (extracted by url_feature_extractor)
    models: dict from load_models()
    raw_url: original URL string (optional)
    Returns a dict:
      {
        "prediction": "phishing"|"safe"|"legitimate" (string),
        "trust_score": float (0-100),
        "risk_score": float (0-100),
        "gsb_match": bool (if available),
        "vt": {...},
        "model_probs": {...},
        "debug": {...}  # optional
      }
    """
    # Basic validation
    feature_names = models.get("features")
    if not feature_names:
        raise RuntimeError("models['features'] not found. Place features.pkl into models/")

    # Build DataFrame with *exact* column order
    df = pd.DataFrame([{k: features.get(k, 0) for k in feature_names}])

    # Coerce all columns to numeric (non-numeric -> NaN -> fill 0)
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    # Ensure same dtype and shape
    # Now call each model's predict_proba safely
    probs = {}
    debug = {"used_models": []}

    # XGBoost
    xgb_model = models.get("xgb")
    if xgb_model is not None:
        try:
            # XGBClassifier supports DataFrame input; but ensure it's the same columns order
            p = xgb_model.predict_proba(df)[:, 1][0]
            probs["xgb"] = float(p)
            debug["used_models"].append("xgb")
        except Exception:
            # fallback: try with ._leaves / DMatrix? but simplest fallback:
            traceback.print_exc()
            probs["xgb"] = 0.5
    else:
        probs["xgb"] = 0.5

    # RandomForest
    rf_model = models.get("rf")
    if rf_model is not None:
        try:
            p = rf_model.predict_proba(df)[:, 1][0]
            probs["rf"] = float(p)
            debug["used_models"].append("rf")
        except Exception:
            traceback.print_exc()
            # some RF models were fitted on numpy arrays w/o column names;
            # scikit-learn warns but still works; if it fails, attempt numpy array fallback
            try:
                p = rf_model.predict_proba(df.values)[:, 1][0]
                probs["rf"] = float(p)
                debug["used_models"].append("rf(numpy-fallback)")
            except Exception:
                traceback.print_exc()
                probs["rf"] = 0.5
    else:
        probs["rf"] = 0.5

    # (optional) other base models if present (lgb, nb, etc.)
    # add them to probs dict if you have them

    # Build stacker input row using stacker feature names (robust)
    stacker = models.get("stacker")
    stack_input_dict = _build_stacker_input_dict(probs, stacker)
    stack_input_df = pd.DataFrame([stack_input_dict])

    # Coerce numeric
    for c in stack_input_df.columns:
        stack_input_df[c] = pd.to_numeric(stack_input_df[c], errors="coerce").fillna(0)

    # Final stacked probability
    if stacker is not None:
        try:
            final_ml_prob = float(stacker.predict_proba(stack_input_df)[:, 1][0])
            debug["stacker_input_cols"] = list(stack_input_df.columns)
            debug["stacker_used"] = True
        except Exception:
            traceback.print_exc()
            # fallback: simple average of available base probs
            final_ml_prob = np.mean(list(probs.values()))
            debug["stacker_input_cols"] = list(stack_input_df.columns)
            debug["stacker_used"] = False
    else:
        final_ml_prob = np.mean(list(probs.values()))
        debug["stacker_used"] = False

    # ml_risk in 0..100 (higher = more likely phishing)
    ml_risk = float(final_ml_prob) * 100.0

    # If you have additional signals (vt, gsb) integrate them here.
    # For now return ML-only risk & trust score
    risk_score = ml_risk
    trust_score = 100.0 - risk_score

    # Format prediction label
    # threshold 50: phishing
    label = "phishing" if risk_score >= 50.0 else "safe"

    result = {
        "prediction": label,
        "trust_score": round(float(trust_score), 6),
        "risk_score": round(float(risk_score), 6),
        "gsb_match": False,
        "vt": {"total_vendors": 0, "malicious": 0, "ratio": 0.0},
        "model_probs": {k: float(v) for k, v in probs.items()},
        "debug": debug
    }

    return result


# If run as script, quick smoke test (not executed on import)
if __name__ == "__main__":
    print("Quick self-test of predictor.py")
    m = load_models()
    # create fake features from saved features list if available
    if m.get("features"):
        sample = {k: 0 for k in m["features"]}
        # example: a short URL
        sample["length_url"] = 20
        out = predict_from_features(sample, m, raw_url="https://example.com/test")
        import json
        print(json.dumps(out, indent=2))
    else:
        print("No features.pkl found; place it in models/")

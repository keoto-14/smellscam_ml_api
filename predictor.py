from __future__ import annotations
import os
import pickle
import logging
import numpy as np
import urllib.parse

# XGBoost optional
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"
MODEL_DIR = os.environ.get("MODEL_DIR", "models")

# -------------------------------------------------------
# Logging
# -------------------------------------------------------
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s [Predictor] %(message)s"))
    logger.addHandler(h)


# -------------------------------------------------------
# Loading helpers
# -------------------------------------------------------
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    model = XGBClassifier()
    model.load_model(path)
    return model


# -------------------------------------------------------
# Predictor class
# -------------------------------------------------------
class Predictor:
    def __init__(self):
        self.models = {}
        self.feature_names = []
        self._loaded = False

        # FAST_MODE removes VT/GSB weighting
        if FAST_MODE:
            self.weights = {"ml": 0.65, "live": 0.35}
        else:
            # Normally you'd include VT, GSB
            self.weights = {"ml": 0.60, "live": 0.40}

    # ---------------------------------------------------
    # Load models
    # ---------------------------------------------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf_path = os.path.join(MODEL_DIR, "rf.pkl")
            stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
            features_path = os.path.join(MODEL_DIR, "features.pkl")

            rf = load_pickle(rf_path)
            stacker = load_pickle(stacker_path)
            features = load_pickle(features_path)

            if HAS_XGB:
                xgb = load_xgb_model(os.path.join(MODEL_DIR, "xgb.json"))
            else:
                xgb = None

            if not isinstance(features, list):
                raise RuntimeError("features.pkl must contain a list")

            self.models = {
                "rf": rf,
                "stacker": stacker,
                "xgb": xgb,
            }

            self.feature_names = features
            self._loaded = True

            logger.info(f"Models loaded (FAST_MODE={FAST_MODE}) (features={len(features)})")

        except Exception as e:
            logger.exception("Model loading failed")
            raise RuntimeError(str(e))

    # ---------------------------------------------------
    # LIVE base score (simple)
    # ---------------------------------------------------
    def _live_score(self, feats):
        age = feats.get("domain_age_days", 365)
        traffic = feats.get("web_traffic", 100)

        score = 1.0
        if age < 30: score *= 0.6
        elif age < 180: score *= 0.85
        else: score *= 1.15

        if traffic >= 500: score *= 1.15
        elif traffic < 100: score *= 0.9

        score = max(0.2, min(score, 1.7))
        return score / 1.7

    # ---------------------------------------------------
    # Predict
    # ---------------------------------------------------
    def predict_from_features(self, feats: dict, raw_url: str = None):
        self.load_models()

        # Build feature vector (STRICT ORDER)
        X = np.array([[float(feats.get(f, 0.0)) for f in self.feature_names]])

        # RF prediction
        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception:
            p_rf = 0.5

        # XGB prediction
        if self.models["xgb"] is not None:
            try:
                p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
            except Exception:
                p_xgb = 0.5
        else:
            p_xgb = 0.5

        # Stacker
        try:
            meta = np.array([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except Exception:
            p_final = (p_xgb + p_rf) / 2

        ml_component = 1 - p_final
        live_component = self._live_score(feats)

        # final weighted score
        w = self.weights
        trust = (
            w["ml"] * ml_component +
            w["live"] * live_component
        )

        trust = max(0, min(trust, 1))
        trust_score = round(trust * 100, 2)

        if trust_score < 50:
            label = "PHISHING"
        elif trust_score < 75:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"

        return {
            "trust_score": trust_score,
            "label": label,
            "model_probs": {
                "rf": p_rf,
                "xgb": p_xgb,
                "stack_final": p_final
            },
            "live_component": round(live_component, 4)
        }


# -------------------------------------------------------
# Global instance
# -------------------------------------------------------
_PRED = None

def load_models():
    global _PRED
    if _PRED is None:
        _PRED = Predictor()
        _PRED.load_models()
    return _PRED

def predict_from_features(features, predictor, raw_url=None):
    return predictor.predict_from_features(features, raw_url)

# predictor.py  (2025 Clean Production Version)

from __future__ import annotations
import os
import pickle
import logging
import numpy as np
from typing import Dict, Any, Tuple

# -------------------------------------------------------------------
# Optional XGBoost
# -------------------------------------------------------------------
HAS_XGB = True
try:
    from xgboost import XGBClassifier
except Exception:
    HAS_XGB = False

FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"
MODEL_DIR = os.environ.get("MODEL_DIR", "models")

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)


# -------------------------------------------------------------------
# Load Pickle Helper
# -------------------------------------------------------------------
def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


# -------------------------------------------------------------------
# Load XGBoost Helper
# -------------------------------------------------------------------
def load_xgb_model(path: str):
    if not HAS_XGB:
        raise RuntimeError("XGBoost not installed")
    model = XGBClassifier()
    model.load_model(path)
    return model


# -------------------------------------------------------------------
# MAIN PREDICTOR CLASS
# -------------------------------------------------------------------
class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # Hybrid weights
        if FAST_MODE:
            # VT & GSB disabled → weight moves to ML
            self.weights = {"ml": 0.65, "vt": 0.35, "gsb": 0.0}
        else:
            self.weights = {"ml": 0.35, "vt": 0.60, "gsb": 0.05}

    # ---------------------------------------------------------------
    # Load models (RF + optional XGB + Stacker)
    # ---------------------------------------------------------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf_path = os.path.join(MODEL_DIR, "rf.pkl")
            stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
            features_path = os.path.join(MODEL_DIR, "features.pkl")
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")

            # Load RF + stacker
            rf = load_pickle(rf_path)
            stacker = load_pickle(stacker_path)

            # Feature list
            features = load_pickle(features_path)
            if not isinstance(features, list):
                raise ValueError("features.pkl must contain a list")

            # Optional XGBoost
            if HAS_XGB:
                xgb = load_xgb_model(xgb_path)
            else:
                xgb = None

            # Save all
            self.models = {
                "rf": rf,
                "xgb": xgb,
                "stacker": stacker,
                "features": features
            }
            self.feature_names = features
            self._loaded = True

            logger.info(
                "Models loaded successfully (FAST_MODE=%s) (features=%d)",
                FAST_MODE, len(features)
            )

        except Exception as e:
            logger.exception("Model loading failed")
            raise RuntimeError(str(e))

    # ---------------------------------------------------------------
    # External checks removed in FAST_MODE
    # ---------------------------------------------------------------
    def check_gsb(self, url: str) -> bool:
        return False  # Disabled for Railway speed

    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        return 0, 0, 0.0  # Disabled for Railway speed

    # ---------------------------------------------------------------
    # Lightweight live score
    # ---------------------------------------------------------------
    def _live_component(self, feats: dict):
        age = feats.get("domain_age_days", 365)
        traffic = feats.get("web_traffic", 100)

        score = 1.0

        # Age
        if age < 30:
            score *= 0.6
        elif age < 180:
            score *= 0.85
        else:
            score *= 1.10

        # Traffic
        if traffic >= 500:
            score *= 1.05
        elif traffic < 100:
            score *= 0.90

        score = max(0.2, min(score, 1.7))
        return score / 1.7

    # ---------------------------------------------------------------
    # MAIN PREDICTION
    # ---------------------------------------------------------------
    def predict_from_features(self, feats: dict, raw_url: str = None):
        self.load_models()

        # Build numpy vector STRICTLY matching features.pkl
        X = np.asarray([[float(feats.get(f, 0.0)) for f in self.feature_names]])

        # ----------------------------------------------------------
        # Model predictions
        # ----------------------------------------------------------
        # XGB
        if self.models["xgb"] is not None:
            try:
                p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
            except Exception:
                p_xgb = 0.5
        else:
            p_xgb = 0.5

        # RF
        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception:
            p_rf = 0.5

        # Stacker
        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except Exception:
            p_final = (p_xgb + p_rf) / 2

        ml_component = 1 - p_final

        # No VT/GSB in FAST_MODE → always neutral
        vt_component = 1.0
        gsb_component = 1.0

        # Live score
        live_component = self._live_component(feats)

        # Hybrid weighting
        w = self.weights
        live_w = 1 - (w["ml"] + w["vt"] + w["gsb"])

        combined = (
            w["ml"] * ml_component +
            w["vt"] * vt_component +
            w["gsb"] * gsb_component +
            live_w * live_component
        )

        combined = min(max(combined, 0), 1)
        trust_score = round(combined * 100, 2)

        # Label
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
                "xgb": p_xgb,
                "rf": p_rf,
                "ml_final": p_final
            },
            "live_component": round(live_component, 4),
        }


# -------------------------------------------------------------------
# GLOBAL SINGLETON
# -------------------------------------------------------------------
_GLOBAL_PREDICTOR = None


def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR


def predict_from_features(features: dict, models_obj, raw_url: str = None):
    return models_obj.predict_from_features(features, raw_url=raw_url)

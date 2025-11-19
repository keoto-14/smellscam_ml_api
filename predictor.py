from __future__ import annotations
import os
import pickle
import urllib.parse
import logging
import time
from typing import Dict, Any, Tuple

import numpy as np

# If XGBoost is available
HAS_XGB = True
try:
    from xgboost import XGBClassifier
except Exception:
    HAS_XGB = False

# FAST MODE ENABLED ON RAILWAY
FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

MODEL_DIR = os.environ.get("MODEL_DIR", "models")


# ------------------------ LOAD MODELS ------------------------

class ModelLoadError(Exception):
    pass


def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
    if not HAS_XGB:
        raise RuntimeError("XGBoost not installed")

    model = XGBClassifier()
    model.load_model(path)
    return model


class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # Adjusted weights for FAST MODE (no VT/GSB)
        if FAST_MODE:
            self.weights = {"ml": 0.90, "vt": 0.0, "gsb": 0.0}
        else:
            self.weights = {"ml": 0.35, "vt": 0.60, "gsb": 0.05}

    def load_models(self):
        if self._loaded:
            return

        try:
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")
            rf_path = os.path.join(MODEL_DIR, "rf.pkl")
            stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
            features_path = os.path.join(MODEL_DIR, "features.pkl")

            rf = load_pickle(rf_path)
            stacker = load_pickle(stacker_path)
            features = load_pickle(features_path)

            if not isinstance(features, list):
                raise ModelLoadError("features.pkl must be a list")

            # XGBoost only if installed
            if HAS_XGB:
                xgb = load_xgb_model(xgb_path)
            else:
                xgb = None

            self.models = {
                "xgb": xgb,
                "rf": rf,
                "stacker": stacker,
                "features": features
            }

            self.feature_names = features
            self._loaded = True

            logger.info("Models loaded (FAST_MODE=%s) (features=%d)",
                        FAST_MODE, len(features))

        except Exception as e:
            logger.exception("Failed to load models")
            raise ModelLoadError(str(e))

    # ------------------------ EXTERNAL CHECKS (DISABLED IN FAST MODE) ------------------------

    def check_gsb(self, url: str) -> bool:
        if FAST_MODE:
            return False
        return False  # disabled for Railway speed

    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        if FAST_MODE:
            return 0, 0, 0.0
        return 0, 0, 0.0  # disabled for Railway speed

    # ------------------------ LIVE COMPONENT ------------------------

    def _live_component(self, feats: dict):
        if FAST_MODE:
            # simple approximation for speed
            age = feats.get("domain_age_days", 365)
            traffic = feats.get("web_traffic", 100)

            score = 1.0
            if age < 30: score *= 0.6
            elif age < 180: score *= 0.85
            else: score *= 1.1

            if traffic >= 500: score *= 1.05
            elif traffic < 100: score *= 0.9

            score = max(0.2, min(score, 1.6))
            return score / 1.6

        # If not FAST_MODE → original logic
        quad9 = int(feats.get("quad9_blocked", 0))
        ssl = int(feats.get("ssl_valid", 0))
        age = int(feats.get("domain_age_days", 0))
        traffic = int(feats.get("web_traffic", 100))

        score = 1.0
        score *= 0.25 if quad9 else 1.05
        score *= 1.02 if ssl else 0.9

        if age < 30:
            score *= 0.6
        elif age < 180:
            score *= 0.85
        elif age < 1000:
            score *= 1.05
        else:
            score *= 1.12

        if traffic >= 1000: score *= 1.15
        elif traffic >= 500: score *= 1.05
        elif traffic < 100: score *= 0.85

        score = max(0.05, min(score, 2.5))
        return score / 2.5

    # ------------------------ PREDICT ------------------------

    def predict_from_features(self, feats: dict, raw_url: str = None):
        self.load_models()

        if raw_url is None:
            raw_url = feats.get("url", "")

        # Build feature vector
        X = np.asarray([[float(feats.get(f, 0.0)) for f in self.feature_names]])

        # Base model predictions
        if self.models["xgb"] is not None:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        else:
            p_xgb = 0.5

        p_rf = float(self.models["rf"].predict_proba(X)[0][1])

        # Stacking
        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        ml_component = 1 - p_final

        # External checks (disabled in FAST MODE)
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(raw_url)
        vt_component = 1 - vt_ratio

        gsb_hit = self.check_gsb(raw_url)
        gsb_component = 0.0 if gsb_hit else 1.0

        live_component = self._live_component(feats)

        # Weighted score
        w = self.weights
        combined = (
            w["ml"] * ml_component +
            w["vt"] * vt_component +
            w["gsb"] * gsb_component +
            (1 - sum(w.values())) * live_component
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
            "vt": {
                "total_vendors": vt_total,
                "malicious": vt_mal,
                "ratio": vt_ratio
            },
            "gsb_match": bool(gsb_hit),
            "live_component": round(live_component, 4)
        }


# ------------------------ GLOBAL ------------------------

_GLOBAL_PREDICTOR = None


def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR


def predict_from_features(features: dict, models_obj, raw_url: str = None):
    return models_obj.predict_from_features(features, raw_url=raw_url)

# ==============================================================
#  predictor.py – Railway-Optimized (FAST, No Warnings)
# ==============================================================

from __future__ import annotations
import os
import pickle
import urllib.parse
import logging
import time
from typing import Dict, Any, Tuple

import numpy as np

# Try XGBoost
HAS_XGB = True
try:
    from xgboost import XGBClassifier
except Exception:
    HAS_XGB = False

FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

MODEL_DIR = os.environ.get("MODEL_DIR", "models")


# ==============================================================
# LOAD OBJECT HELPERS
# ==============================================================

class ModelLoadError(Exception):
    pass


def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
    """
    Load XGBoost in safe, Railway-compatible form.
    """
    if not HAS_XGB:
        raise RuntimeError("XGBoost not installed")

    model = XGBClassifier()
    model.load_model(path)

    # Fix: disable internal label encoder (prevents warning)
    if hasattr(model, "_le"):
        model._le = None

    return model


# ==============================================================
#  PREDICTOR CLASS
# ==============================================================

class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # FAST_MODE = no VT/GSB
        if FAST_MODE:
            self.weights = {"ml": 0.10, "vt": 0.90, "gsb": 0.0}
        else:
            self.weights = {"ml": 0.10, "vt": 0.90, "gsb": 0.00}

    # ----------------------------------------------------------
    # Load all models
    # ----------------------------------------------------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf = load_pickle(os.path.join(MODEL_DIR, "rf.pkl"))
            stacker = load_pickle(os.path.join(MODEL_DIR, "stacker.pkl"))
            features = load_pickle(os.path.join(MODEL_DIR, "features.pkl"))

            if not isinstance(features, list):
                raise ModelLoadError("features.pkl must be a list of feature names")

            # load XGB only if available
            if HAS_XGB:
                xgb = load_xgb_model(os.path.join(MODEL_DIR, "xgb.json"))
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

    # ----------------------------------------------------------
    # External checks (DISABLED in FAST MODE)
    # ----------------------------------------------------------
    def check_gsb(self, url: str) -> bool:
        return False

    def vt_domain_report(self, domain: str):
        return (0, 0, 0.0)

    # ----------------------------------------------------------
    # Compute live_component (used even in FAST_MODE)
    # ----------------------------------------------------------
    def _live_component(self, feats: dict):
        if FAST_MODE:
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

        return 1.0

    # ----------------------------------------------------------
    # Main Prediction
    # ----------------------------------------------------------
    def predict_from_features(self, feats: dict, raw_url: str = None):
        self.load_models()

        if raw_url is None:
            raw_url = feats.get("url", "")

        # Build X EXACTLY in saved order, forced float32
        X = np.array(
            [[feats.get(f, 0.0) for f in self.feature_names]],
            dtype=np.float32
        )

        # -----------------------------
        # XGB prediction
        # -----------------------------
        if self.models["xgb"] is not None:
            try:
                p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
            except Exception as e:
                logger.warning("XGB predict_proba failed, fallback=0.5: %s", e)
                p_xgb = 0.5
        else:
            p_xgb = 0.5

        # -----------------------------
        # RandomForest prediction
        # -----------------------------
        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        # -----------------------------
        # Stacker (LogisticRegression)
        # always use ndarray to avoid warnings
        # -----------------------------
        try:
            meta = np.array([[p_xgb, p_rf]], dtype=np.float32)
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        # ML score: lower = malicious
        ml_component = 1 - p_final

        # External (disabled)
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(raw_url)
        vt_component = 1 - vt_ratio

        gsb_hit = self.check_gsb(raw_url)
        gsb_component = 0.0 if gsb_hit else 1.0

        live_component = self._live_component(feats)

        # -----------------------------
        # Weighted score
        # -----------------------------
        w = self.weights
        live_weight = 1.0 - (w["ml"] + w["vt"] + w["gsb"])

        combined = (
            w["ml"] * ml_component +
            w["vt"] * vt_component +
            w["gsb"] * gsb_component +
            live_weight * live_component
        )

        combined = min(max(combined, 0), 1)
        trust_score = round(combined * 100, 2)

        # -----------------------------
        # Labeling
        # -----------------------------
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


# ==============================================================
# GLOBAL HELPERS
# ==============================================================

_GLOBAL_PREDICTOR = None


def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR


def predict_from_features(features: dict, models_obj, raw_url: str = None):
    return models_obj.predict_from_features(features, raw_url=raw_url)

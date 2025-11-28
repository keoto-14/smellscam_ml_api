# predictor.py  — UPDATED CLEAN VERSION (Option 1)

from __future__ import annotations
import os
import pickle
import logging
import time
import urllib.parse
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd

# Optional XGBoost
HAS_XGB = True
try:
    from xgboost import XGBClassifier
except Exception:
    HAS_XGB = False

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

MODEL_DIR = os.environ.get("MODEL_DIR", "models")
VT_API_KEY = os.environ.get("VT_API_KEY")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
FAST_MODE = os.environ.get("FAST_MODE", "0") == "1"


# ---------------------- simple cache ----------------------
_CACHE: Dict[str, tuple] = {}

def cache_get(k: str, max_age: int = 3600):
    v = _CACHE.get(k)
    if not v:
        return None
    ts, val = v
    return val if (time.time() - ts) <= max_age else None

def cache_set(k: str, v: Any):
    _CACHE[k] = (time.time(), v)


# ---------------------- Loading helpers -------------------
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


# ==========================================================
#                PREDICTOR CLASS
# ==========================================================
class Predictor:
    def __init__(self):
        self.models = {}
        self.feature_names = []
        self._loaded = False

        # Base model weight
        self.weights = {
            "ml": float(os.getenv("ML_WEIGHT", 0.60)),
            "vt": float(os.getenv("VT_WEIGHT", 0.35)),
            "gsb": float(os.getenv("GSB_WEIGHT", 0.05)),
        }

        s = sum(self.weights.values())
        if s > 1:
            for k in self.weights:
                self.weights[k] /= s

    # ------------------------------------------------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf = load_pickle(os.path.join(MODEL_DIR, "rf.pkl"))
            stacker = load_pickle(os.path.join(MODEL_DIR, "stacker.pkl"))
            features = load_pickle(os.path.join(MODEL_DIR, "features.pkl"))

            if HAS_XGB and os.path.exists(os.path.join(MODEL_DIR, "xgb.json")):
                try:
                    xgb = load_xgb_model(os.path.join(MODEL_DIR, "xgb.json"))
                except Exception:
                    xgb = None
            else:
                xgb = None

            self.models = {"rf": rf, "stacker": stacker, "xgb": xgb}
            self.feature_names = list(features)

        except Exception as e:
            raise ModelLoadError(str(e))

        self._loaded = True

    # ==========================================================
    #                   VIRUSTOTAL
    # ==========================================================
    def vt_domain_report(self, domain: str):
        if FAST_MODE or not VT_API_KEY:
            return 0, 0, 0.0

        cached = cache_get(f"vt::{domain}")
        if cached:
            return cached["total"], cached["mal"], cached["ratio"]

        try:
            import requests
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=5)

            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values())
                mal = stats.get("malicious", 0)
                ratio = mal / total if total else 0.0

                cache_set(f"vt::{domain}", {"total": total, "mal": mal, "ratio": ratio})
                return total, mal, ratio
        except:
            pass

        cache_set(f"vt::{domain}", {"total": 0, "mal": 0, "ratio": 0.0})
        return 0, 0, 0.0

    # ==========================================================
    #                   GOOGLE SAFE BROWSING
    # ==========================================================
    def check_gsb(self, url: str):
        if FAST_MODE or not GSB_API_KEY:
            return False

        cached = cache_get(f"gsb::{url}")
        if cached is not None:
            return bool(cached)

        try:
            import requests
            api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
            body = {
                "client": {"clientId": "smellscam", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            r = requests.post(api, json=body, timeout=5)
            matches = bool(r.json().get("matches"))
            cache_set(f"gsb::{url}", matches)
            return matches

        except:
            cache_set(f"gsb::{url}", False)
            return False

    # ==========================================================
    #                LIVE COMPONENT
    # ==========================================================
    def _live_component(self, feats):
        quad9 = feats.get("quad9_blocked", 0)
        ssl = feats.get("ssl_valid", 0)
        age = feats.get("domain_age_days", 0)
        traffic = feats.get("web_traffic", 100)

        score = 1.0

        if quad9:
            score *= 0.3
        if not ssl:
            score *= 0.75

        if age < 30:
            score *= 0.6
        elif age < 180:
            score *= 0.8
        else:
            score *= 1.05

        if traffic > 1000:
            score *= 1.15
        elif traffic > 500:
            score *= 1.05
        elif traffic < 100:
            score *= 0.85

        return max(0.1, min(score, 2.0)) / 2.0

    # ==========================================================
    #     ⭐ SELLER SCORE ADJUSTMENT (new for marketplaces)
    # ==========================================================
    def adjust_seller(self, trust: float, feats: dict):
        seller = feats.get("seller_status", 0)

        if seller == 1:            # Verified seller
            trust = max(trust, 80)

        elif seller == 0:          # Unknown seller
            trust -= 10

        elif seller == 2:          # Suspicious seller
            trust -= 20

        return max(1, min(trust, 100))

    # ==========================================================
    #                    MAIN PREDICT FUNCTION
    # ==========================================================
    def predict_from_features(self, feats, models_obj=None, raw_url=None):
        self.load_models()

        raw_url = raw_url or feats.get("url", "")
        domain = urllib.parse.urlparse(raw_url).netloc.split(":")[0].lower()

        # ML INPUT
        X_vec = [float(feats.get(f, 0.0)) for f in self.feature_names]
        X_df = pd.DataFrame([X_vec], columns=self.feature_names)

        # Base model proba
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X_df)[0][1]) if self.models["xgb"] else 0.5
        except:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X_df)[0][1])
        except:
            p_rf = 0.5

        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        # ML -> trust
        ml_trust = 1.0 - p_final

        # External checks
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)
        gsb_hit = self.check_gsb(raw_url)

        # VT component
        if vt_total == 0:
            vt_comp = 1.0
        elif vt_total < 5:
            vt_comp = 0.7
        else:
            vt_comp = 1.0 - vt_ratio

        gsb_comp = 0.0 if gsb_hit else 1.0
        live_comp = self._live_component(feats)

        # Weighted combine
        w_ml = self.weights["ml"]
        w_vt = self.weights["vt"]
        w_gsb = self.weights["gsb"]
        leftover = 1 - (w_ml + w_vt + w_gsb)

        combined = (
            w_ml * ml_trust +
            w_vt * vt_comp +
            w_gsb * gsb_comp +
            leftover * live_comp
        )

        trust = round(combined * 100, 2)

        # FINAL SELLER ADJUSTMENT
        trust = self.adjust_seller(trust, feats)

        # LABEL
        if trust < 50:
            label = "PHISHING"
        elif trust < 75:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"

        return {
            "trust_score": trust,
            "label": label,
            "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
            "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
            "gsb_match": gsb_hit,
            "seller_status": feats.get("seller_status", 0),
            "live_component": round(live_comp, 4),
        }


# ==========================================================
# GLOBAL HELPERS
# ==========================================================
_GLOBAL_PREDICTOR = None

def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR

def predict_from_features(features, models_obj=None, raw_url=None):
    if hasattr(models_obj, "predict_from_features"):
        return models_obj.predict_from_features(features, raw_url=raw_url)
    pred = load_models()
    return pred.predict_from_features(features, raw_url=raw_url)

# predictor.py
from __future__ import annotations
import os
import pickle
import urllib.parse
import logging
import math
import time
from typing import Dict, Any, Tuple

import numpy as np
import requests

from url_feature_extractor import extract_all_features

# suppress sklearn warnings
import warnings
from sklearn.exceptions import DataConversionWarning
warnings.filterwarnings("ignore", category=DataConversionWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# optional file-backed simple cache
try:
    from simple_cache import cache_get, cache_set
except Exception:
    _CACHE = {}
    def cache_get(k, max_age=3600):
        v = _CACHE.get(k)
        if not v: return None
        ts, val = v
        if time.time() - ts > max_age:
            return None
        return val

    def cache_set(k, v):
        _CACHE[k] = (time.time(), v)

# ------------------------ LOAD MODELS ------------------------

class ModelLoadError(Exception):
    pass

def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path: str):
    try:
        from xgboost import XGBClassifier
    except Exception as e:
        raise RuntimeError("xgboost not installed") from e
    model = XGBClassifier()
    model.load_model(path)
    return model


class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False
        # DEFAULT Hybrid weights (ML=50, VT=45, GSB=5)
        self.weights = {"ml": 0.35, "vt": 0.60, "gsb": 0.05}

    def load_models(self):
        if self._loaded:
            return
        try:
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")
            rf_path = os.path.join(MODEL_DIR, "rf.pkl")
            stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
            features_path = os.path.join(MODEL_DIR, "features.pkl")

            xgb = load_xgb_model(xgb_path)
            rf = load_pickle(rf_path)
            stacker = load_pickle(stacker_path)
            features = load_pickle(features_path)

            if not isinstance(features, (list, tuple)):
                raise ModelLoadError("features.pkl must be a list of feature names")

            self.models = {
                "xgb": xgb,
                "rf": rf,
                "stacker": stacker,
                "features": features
            }
            self.feature_names = list(features)
            self._loaded = True
            logger.info("Models loaded successfully (features=%d)", len(self.feature_names))

        except Exception as e:
            logger.exception("Failed to load models")
            raise ModelLoadError(str(e))

    # ------------------------ GSB CHECK ------------------------

    def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False

        cache_key = f"gsb::{url}"
        cached = cache_get(cache_key)
        if cached is not None:
            return bool(cached)

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

        try:
            r = requests.post(api, json=body, timeout=6)
            r.raise_for_status()
            result = bool(r.json().get("matches"))
            cache_set(cache_key, result)
            return result
        except:
            return False

    # ------------------------ VIRUSTOTAL CHECK ------------------------

    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        if not VT_API_KEY:
            return 0, 0, 0.0

        cache_key = f"vt::{domain}"
        cached = cache_get(cache_key)
        if cached:
            return cached["total"], cached["mal"], cached["ratio"]

        try:
            headers = {"x-apikey": VT_API_KEY}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            r = requests.get(url, headers=headers, timeout=6)
            r.raise_for_status()

            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            mal = stats.get("malicious", 0)
            ratio = mal / total if total > 0 else 0.0

            cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
            return total, mal, ratio

        except:
            return 0, 0, 0.0

    # ------------------------ WEIGHTS ------------------------

    def _weights_from_env(self):
        ml = float(os.getenv("ML_WEIGHT", self.weights["ml"]))
        vt = float(os.getenv("VT_WEIGHT", self.weights["vt"]))
        gsb = float(os.getenv("GSB_WEIGHT", self.weights["gsb"]))

        total = ml + vt + gsb
        if total > 1:
            ml /= total
            vt /= total
            gsb /= total
            live = 0
        else:
            live = 1 - total

        return {"ml": ml, "vt": vt, "gsb": gsb, "live": live}

    # ------------------------ LIVE SCORES ------------------------

    def _live_component(self, feats: dict):
        quad9 = int(feats.get("quad9_blocked", 0))
        ssl = int(feats.get("ssl_valid", 0))
        age = int(feats.get("domain_age_days", 0))
        traffic = int(feats.get("web_traffic", 100))

        score = 1.0
        # Quad9
        score *= 0.25 if quad9 else 1.05
        # SSL
        score *= 1.02 if ssl else 0.9
        # Domain age
        if age < 30:
            score *= 0.6
        elif age < 180:
            score *= 0.85
        elif age < 1000:
            score *= 1.05
        else:
            score *= 1.12
        # Traffic
        if traffic >= 1000: score *= 1.15
        elif traffic >= 500: score *= 1.05
        elif traffic < 100: score *= 0.85

        score = max(0.05, min(score, 2.5))
        return score / 2.5

    # ------------------------ PREDICT FROM FEATURES ------------------------

    def predict_from_features(self, feats: dict, raw_url: str = None):
        self.load_models()

        if raw_url is None:
            raw_url = feats.get("url", "")

        # Feature vector
        X = np.asarray([[float(feats.get(f, 0.0)) for f in self.feature_names]])

        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except:
            p_xgb = 0.5
        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        ml_mal_prob = min(max(p_final, 0), 1)
        ml_component = 1 - ml_mal_prob

        # Domain parsing
        parsed = urllib.parse.urlparse(raw_url)
        domain = (parsed.netloc or raw_url).lower().split(":")[0]

        # External checks
        gsb_hit = self.check_gsb(raw_url)
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)

        vt_component = 1 - min(max(vt_ratio, 0), 1)
        gsb_component = 0.0 if gsb_hit else 1.0
        live_component = self._live_component(feats)

        w = self._weights_from_env()
        combined = (
            w["ml"] * ml_component +
            w["vt"] * vt_component +
            w["gsb"] * gsb_component +
            w["live"] * live_component
        )

        combined = min(max(combined, 0), 1)
        trust_score = round(combined * 100, 2)

        # Labeling
        if trust_score < 50: label = "PHISHING"
        elif trust_score < 75: label = "SUSPICIOUS"
        else: label = "LEGITIMATE"

        return {
            "trust_score": trust_score,
            "label": label,
            "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
            "vt": {
                "total_vendors": vt_total,
                "malicious": vt_mal,
                "ratio": vt_ratio
            },
            "gsb_match": bool(gsb_hit),
            "live_component": round(live_component, 4),
            "weights": w,
            "breakdown": {
                "ml_component": round(ml_component, 4),
                "vt_component": round(vt_component, 4),
                "gsb_component": round(gsb_component, 4),
                "live_component": round(live_component, 4)
            }
        }


# ------------------------ GLOBAL HELPERS ------------------------

_GLOBAL_PREDICTOR = None

def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR

def predict_from_features(features: dict, models_obj, raw_url: str = None):
    if hasattr(models_obj, "predict_from_features"):
        return models_obj.predict_from_features(features, raw_url=raw_url)

    # fallback wrapper
    temp = Predictor()
    temp.models = models_obj
    temp.feature_names = models_obj.get("features", [])
    temp._loaded = True

    return temp.predict_from_features(features, raw_url=raw_url)

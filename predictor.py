# predictor.py
from __future__ import annotations
import os
import pickle
import urllib.parse
import logging
import math
import time

import numpy as np
import requests

from typing import Dict, Any, Tuple

# import extractor
from url_feature_extractor import extract_all_features

# suppress sklearn warnings when importing (optional)
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

# optional file-backed simple cache if available in project
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
        # weights specified by user (ml=50, vt=45, gsb=5)
        self.weights = {"ml": 0.50, "vt": 0.45, "gsb": 0.05}

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

            # ensure features is list-like
            if not isinstance(features, (list, tuple)):
                raise ModelLoadError("features.pkl must be a list of feature names")

            self.models = {"xgb": xgb, "rf": rf, "stacker": stacker, "features": features}
            self.feature_names = list(features)
            self._loaded = True
            logger.info("Models loaded successfully. Features count=%d", len(self.feature_names))
        except FileNotFoundError as e:
            logger.exception("Model file not found")
            raise ModelLoadError(str(e))
        except Exception as e:
            logger.exception("Error loading models")
            raise ModelLoadError(str(e))

    # ---------------- Google Safe Browsing (synchronous) ----------------
    def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False
        cache_key = f"gsb::{url}"
        cached = cache_get(cache_key)
        if cached is not None:
            return bool(cached)
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
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
            r = requests.post(endpoint, json=body, timeout=6)
            r.raise_for_status()
            matches = bool(r.json().get("matches"))
            cache_set(cache_key, matches)
            return matches
        except Exception:
            return False

    # ---------------- VirusTotal domain report (synchronous) ----------------
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
            mal = stats.get("malicious", 0) if stats else 0
            ratio = mal / total if total > 0 else 0.0
            cache_set(cache_key, {"total": total, "mal": mal, "ratio": ratio})
            return total, mal, ratio
        except Exception:
            return 0, 0, 0.0

    # ---------------- Main prediction (synchronous) ----------------
    def predict_url(self, raw_url: str) -> Dict[str, Any]:
        # ensure models loaded
        self.load_models()

        # extract features (40 features)
        feats = extract_all_features(raw_url)
        is_shopping = bool(feats.get("is_shopping", 0))

        if not is_shopping:
            # shopping-only mode: return explicit not-shopping response
            return {
                "is_shopping": False,
                "trust_score": 0.0,
                "gsb_match": False,
                "vt": {"total_vendors": 0, "malicious": 0, "ratio": 0.0},
                "model_probs": {"xgb": 0.0, "rf": 0.0, "ml_final": 0.0},
            }

        # build numeric vector ordered by features.pkl
        X = np.asarray([[float(feats.get(f, 0.0)) for f in self.feature_names]], dtype=float)

        # model probabilities with safe fallbacks
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except Exception:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception:
            p_rf = 0.5

        # stacked meta-model
        try:
            stack_in = np.asarray([[p_xgb, p_rf]], dtype=float)
            p_final = float(self.models["stacker"].predict_proba(stack_in)[0][1])
        except Exception:
            p_final = (p_xgb + p_rf) / 2.0

        ml_risk = p_final * 100.0

        # domain parsing
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.lower().split(":")[0]

        # external checks (synchronous)
        gsb_match = self.check_gsb(raw_url)
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)

        vt_risk = min(((vt_ratio * 100.0) ** 2) / 100.0, 100.0)
        gsb_risk = 100.0 if gsb_match else 0.0

        FINAL_RISK = (
            ml_risk * self.weights["ml"] +
            vt_risk * self.weights["vt"] +
            gsb_risk * self.weights["gsb"]
        )

        FINAL_RISK = max(0.0, min(FINAL_RISK, 100.0))
        trust = round(max(0.0, min(100.0, 100.0 - FINAL_RISK)), 3)

        # final result matching the JSON schema user requested
        result = {
            "is_shopping": True,
            "trust_score": trust,
            "gsb_match": bool(gsb_match),
            "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
            "model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final": float(p_final)},
        }
        return result

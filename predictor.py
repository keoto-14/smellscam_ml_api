# predictor.py
from __future__ import annotations
import os
import pickle
import logging
import time
import urllib.parse
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd

# try to import xgboost (optional)
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

# ---------------- Cache ------------------
_CACHE: Dict[str, tuple] = {}

def cache_get(k: str, max_age: int = 3600):
    v = _CACHE.get(k)
    if not v:
        return None
    ts, val = v
    return val if (time.time() - ts) <= max_age else None

def cache_set(k: str, v: Any):
    _CACHE[k] = (time.time(), v)

# ---------------- Model loaders ------------------
class ModelLoadError(Exception):
    pass

def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path: str):
    if not HAS_XGB:
        raise RuntimeError("XGBoost not installed")
    m = XGBClassifier()
    m.load_model(path)
    return m

# ======================================================
#                     PREDICTOR CLASS
# ======================================================
class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # Weights for hybrid model
        self.weights = {
            "ml": float(os.getenv("ML_WEIGHT", 0.60)),
            "vt": float(os.getenv("VT_WEIGHT", 0.35)),
            "gsb": float(os.getenv("GSB_WEIGHT", 0.05)),
        }

        # Normalize if > 1
        s = sum(self.weights.values())
        if s > 1:
            for k in self.weights:
                self.weights[k] = self.weights[k] / s
            logger.info("Normalized weights: %s", self.weights)

    # ---------------- Load ML models ----------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf = load_pickle(os.path.join(MODEL_DIR, "rf.pkl"))
            stacker = load_pickle(os.path.join(MODEL_DIR, "stacker.pkl"))
            features = load_pickle(os.path.join(MODEL_DIR, "features.pkl"))

            # XGB optional
            xgb = None
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")
            if HAS_XGB and os.path.exists(xgb_path):
                try:
                    xgb = load_xgb_model(xgb_path)
                except:
                    xgb = None

            self.models = {
                "rf": rf,
                "stacker": stacker,
                "xgb": xgb
            }
            self.feature_names = list(features)
            self._loaded = True

        except Exception as e:
            raise ModelLoadError(str(e))

    # ---------------- VirusTotal ----------------
    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        if FAST_MODE or not VT_API_KEY:
            return 0,0,0.0

        key = f"vt::{domain}"
        cached = cache_get(key)
        if cached:
            return cached["total"], cached["mal"], cached["ratio"]

        try:
            import requests
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_API_KEY},
                timeout=5
            )
            if r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                mal = stats.get("malicious", 0)
                ratio = mal / total if total>0 else 0.0
                cache_set(key, {"total":total,"mal":mal,"ratio":ratio})
                return total, mal, ratio
        except:
            pass

        cache_set(key, {"total":0,"mal":0,"ratio":0.0})
        return 0,0,0.0

    # ---------------- Google Safe Browsing ----------------
    def check_gsb(self, url: str) -> bool:
        if FAST_MODE or not GSB_API_KEY:
            return False

        key = f"gsb::{url}"
        cached = cache_get(key)
        if cached is not None:
            return bool(cached)

        try:
            import requests
            api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
            body = {
                "client":{"clientId":"smellscam","clientVersion":"1.0"},
                "threatInfo":{
                    "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                    "platformTypes":["ANY_PLATFORM"],
                    "threatEntryTypes":["URL"],
                    "threatEntries":[{"url":url}]
                }
            }
            r = requests.post(api,json=body,timeout=5)
            matches = bool(r.json().get("matches"))
            cache_set(key,matches)
            return matches
        except:
            cache_set(key,False)
            return False

    # --------------- Live Component ----------------
    def _live_component(self, feats: dict) -> float:
        age = int(feats.get("domain_age_days", 365))
        traffic = int(feats.get("web_traffic", 100))
        ssl = int(feats.get("ssl_valid", 0))
        quad9 = int(feats.get("quad9_blocked", 0))
        domain_exists = int(feats.get("domain_exists", 1))

        score = 1.0

        # Blocked by Quad9 = strong penalty
        score *= 0.25 if quad9 else 1.05

        # Domain does NOT exist
        if domain_exists == 0:
            score *= 0.4

        # SSL
        score *= 1.05 if ssl else 0.9

        # Domain age
        if age < 30:
            score *= 0.6
        elif age < 180:
            score *= 0.85
        elif age > 1000:
            score *= 1.12

        # Traffic
        if traffic >= 1000:
            score *= 1.15
        elif traffic >= 500:
            score *= 1.05
        elif traffic < 100:
            score *= 0.85

        return max(0.05, min(score, 2.5)) / 2.5

    # --------------- Seller Adjustment ----------------
    def adjust_for_seller(self, trust_score: float, seller_status: int) -> float:
        """
        seller_status:
            1 = verified
            0 = unknown
            2 = suspicious
        """
        if seller_status == 1:
            trust_score = max(trust_score, 80)

        elif seller_status == 0:
            trust_score -= 10

        elif seller_status == 2:
            trust_score -= 20

        return max(1, min(trust_score, 100))

    # ======================================================
    #                    MAIN PREDICT
    # ======================================================
    def predict_from_features(self, feats: dict, models_obj=None, raw_url: str=None):
        self.load_models()
        raw_url = raw_url or feats.get("url","")

        # Build ML input
        X_vec = [float(feats.get(f,0.0)) for f in self.feature_names]
        X_df = pd.DataFrame([X_vec], columns=self.feature_names)

        # Base model predictions
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
            p_final = (p_xgb + p_rf) / 2.0

        ml_mal = min(max(p_final, 0.0), 1.0)
        ml_component = 1.0 - ml_mal  # convert to trust

        # VirusTotal + GSB
        parsed = urllib.parse.urlparse(raw_url)
        domain = (parsed.netloc or raw_url).lower().split(":")[0]

        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)
        gsb_hit = self.check_gsb(raw_url)

        vt_component = (
            1.0 if vt_total == 0 else
            0.7 if vt_total < 5 else
            1.0 - min(max(vt_ratio,0.0),1.0)
        )

        gsb_component = 0.0 if gsb_hit else 1.0

        # Live component
        live_component = self._live_component(feats)

        # Combine weighted
        w_ml = self.weights["ml"]
        w_vt = self.weights["vt"]
        w_gsb = self.weights["gsb"]
        leftover = 1.0 - (w_ml + w_vt + w_gsb)

        combined = (
            w_ml * ml_component +
            w_vt * vt_component +
            w_gsb * gsb_component +
            leftover * live_component
        )

        combined = min(max(combined,0.0),1.0)
        trust_score = round(combined*100,2)

        # ------------------ Apply Seller Adjustments ------------------
        seller_status = int(feats.get("seller_status",0))
        trust_score = self.adjust_for_seller(trust_score, seller_status)

        # ------------------ Apply Domain Exists Override ------------------
        if feats.get("domain_exists",1) == 0:
            trust_score = min(trust_score, 40)

        # Label mapping
        label = (
            "PHISHING" if trust_score < 50 else
            "SUSPICIOUS" if trust_score < 75 else
            "LEGITIMATE"
        )

        return {
            "trust_score": trust_score,
            "label": label,
            "model_probs": {"xgb":p_xgb, "rf":p_rf, "ml_final":p_final},
            "vt":{"total_vendors":vt_total,"malicious":vt_mal,"ratio":vt_ratio},
            "gsb_match": gsb_hit,
            "seller_status": seller_status,
            "live_component": round(live_component,4)
        }

# ---------------- global helper ----------------
_GLOBAL_PREDICTOR = None

def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR

def predict_from_features(features: dict, models_obj=None, raw_url: str=None):
    pred = load_models()
    return pred.predict_from_features(features, raw_url=raw_url)

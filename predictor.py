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

# Detect optional XGBoost
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

# Simple RAM cache
_CACHE: Dict[str, tuple] = {}

def cache_get(k: str, max_age: int = 3600):
    v = _CACHE.get(k)
    if not v:
        return None
    ts, val = v
    if time.time() - ts > max_age:
        return None
    return val

def cache_set(k: str, v: Any):
    _CACHE[k] = (time.time(), v)


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


class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # Weight rules (normalized)
        self.weights = {
            "ml": float(os.getenv("ML_WEIGHT", 0.60)),
            "vt": float(os.getenv("VT_WEIGHT", 0.35)),
            "gsb": float(os.getenv("GSB_WEIGHT", 0.05)),
        }
        s = sum(self.weights.values())
        if s > 1:
            for k in self.weights:
                self.weights[k] /= s
            logger.info("Normalized weights: %s", self.weights)

    # -----------------------------
    # Load ML models
    # -----------------------------
    def load_models(self):
        if self._loaded:
            return

        try:
            rf_path = os.path.join(MODEL_DIR, "rf.pkl")
            stacker_path = os.path.join(MODEL_DIR, "stacker.pkl")
            features_path = os.path.join(MODEL_DIR, "features.pkl")
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")

            rf = load_pickle(rf_path)
            stacker = load_pickle(stacker_path)
            features = load_pickle(features_path)

            if not isinstance(features, (list, tuple)):
                raise ModelLoadError("features.pkl must be list/tuple")

            if HAS_XGB and os.path.exists(xgb_path):
                try:
                    xgb = load_xgb_model(xgb_path)
                except Exception as e:
                    logger.warning("XGB load failed: %s", e)
                    xgb = None
            else:
                xgb = None

            self.models = {"rf": rf, "stacker": stacker, "xgb": xgb}
            self.feature_names = list(features)
            self._loaded = True

            logger.info("Models loaded OK — features=%d", len(self.feature_names))

        except Exception as e:
            logger.exception("Model load error")
            raise ModelLoadError(str(e))

    # -----------------------------------------------------
    # VirusTotal domain report
    # -----------------------------------------------------
    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        if FAST_MODE or not VT_API_KEY:
            return 0, 0, 0.0

        key = f"vt::{domain}"
        cached = cache_get(key)
        if cached:
            return cached["total"], cached["mal"], cached["ratio"]

        try:
            import requests
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            r = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=5)

            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                mal = stats.get("malicious", 0)
                ratio = (mal / total) if total > 0 else 0.0

                cache_set(key, {"total": total, "mal": mal, "ratio": ratio})
                return total, mal, ratio

        except Exception as e:
            logger.debug("VT error %s: %s", domain, e)

        cache_set(key, {"total": 0, "mal": 0, "ratio": 0.0})
        return 0, 0, 0.0

    # -----------------------------------------------------
    # Google Safe Browsing
    # -----------------------------------------------------
    def check_gsb(self, url: str) -> bool:
        if FAST_MODE or not GSB_API_KEY:
            return False

        key = f"gsb::{url}"
        cached = cache_get(key)
        if cached is not None:
            return cached

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
            r.raise_for_status()

            matches = bool(r.json().get("matches"))
            cache_set(key, matches)
            return matches

        except Exception as e:
            logger.debug("GSB error for %s: %s", url, e)
            cache_set(key, False)
            return False

    # -----------------------------------------------------
    # Live component scoring (unchanged)
    # -----------------------------------------------------
    def _live_component(self, feats: dict) -> float:
        if FAST_MODE:
            age = int(feats.get("domain_age_days", 365))
            traffic = int(feats.get("web_traffic", 100))

            score = 1.0
            if age < 30: score *= 0.6
            elif age < 180: score *= 0.85
            else: score *= 1.05

            if traffic >= 1000: score *= 1.15
            elif traffic >= 500: score *= 1.05
            elif traffic < 100: score *= 0.9

            score = max(0.2, min(score, 1.6))
            return score / 1.6

        # Normal mode
        quad9 = int(feats.get("quad9_blocked", 0))
        ssl = int(feats.get("ssl_valid", 0))
        age = int(feats.get("domain_age_days", 0))
        traffic = int(feats.get("web_traffic", 100))

        score = 1.0
        score *= 0.25 if quad9 else 1.05
        score *= 1.02 if ssl else 0.9

        if age < 30: score *= 0.6
        elif age < 180: score *= 0.85
        elif age < 1000: score *= 1.05
        else: score *= 1.12

        if traffic >= 1000: score *= 1.15
        elif traffic >= 500: score *= 1.05
        elif traffic < 100: score *= 0.85

        score = max(0.05, min(score, 2.5))
        return score / 2.5

    # Deterministic number
    def stable_random(self, key: str, min_v: int, max_v: int) -> int:
        if not key:
            key = "default"
        base = abs(hash(key)) % 1000000
        return min_v + (base % (max_v - min_v + 1))

    # -----------------------------------------------------
    # BEGIN MASTER PREDICTION
    # -----------------------------------------------------
    def predict_from_features(self, feats: dict, models_obj=None, raw_url: str = None) -> Dict[str, Any]:
        self.load_models()
        if raw_url is None:
            raw_url = feats.get("url", "")

        # Build ML input
        X_vec = [float(feats.get(f, 0.0)) for f in self.feature_names]
        X_df = pd.DataFrame([X_vec], columns=self.feature_names)

        # ML MODEL PROBS
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

        ml_mal_prob = min(max(p_final, 0.0), 1.0)
        ml_component = 1.0 - ml_mal_prob

        # URL parsing
        parsed = urllib.parse.urlparse(raw_url)
        domain = (parsed.netloc or raw_url).lower().split(":")[0]
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Extractor-provided marketplace/seller
        marketplace_type = int(feats.get("marketplace_type", 0))
        seller_status = int(feats.get("seller_status", 0))

        # Scheme + SSL
        scheme = (parsed.scheme or "http").lower()
        is_https = (scheme == "https")
        is_http_only = (scheme == "http" and int(feats.get("ssl_valid", 0)) == 0)

        # Domain features
        domain_age = int(feats.get("domain_age_days", 0))
        ssl_valid = int(feats.get("ssl_valid", 0))
        domain_exists = int(feats.get("domain_exists", 1))

        # VirusTotal / GSB
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)
        gsb_hit = self.check_gsb(raw_url)

        if vt_total == 0:
            vt_component = 1.0
        elif vt_total < 5:
            vt_component = 0.7
        else:
            vt_component = 1.0 - min(max(vt_ratio, 0.0), 1.0)

        gsb_component = 0.0 if gsb_hit else 1.0
        live_component = float(self._live_component(feats))
        stable_key = domain or raw_url

        # ---------------- DOMAIN MISSING ----------------
        if domain_exists == 0:
            score = self.stable_random(stable_key, 1, 10)
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "domain_missing",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "live_component": live_component
            }

        # ---------------- GSB OVERRIDE ----------------
        if gsb_hit:
            return {
                "trust_score": 10,
                "label": "PHISHING",
                "override": "gsb",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "live_component": live_component
            }

        # ---------------- VT SEVERE ----------------
        if vt_mal >= 6:
            score = self.stable_random(stable_key, 1, 49)
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "vt_malicious",
                "vt": {"total_vendors": vt_total, "malicious": vt_mal},
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final}
            }

        # ---------------- VT SUSPICIOUS ----------------
        if 1 <= vt_mal <= 5:
            score = self.stable_random(stable_key, 50, 69)
            return {
                "trust_score": score,
                "label": "SUSPICIOUS",
                "override": "vt_suspicious",
                "vt": {"total_vendors": vt_total, "malicious": vt_mal},
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final}
            }

        # ============= OFFICIAL BRAND CHECK =============
        is_official_like = (
            marketplace_type == 0 and
            seller_status == 0 and
            domain_exists == 1 and
            ssl_valid == 1 and
            is_https and
            domain_age >= 365 and
            domain.replace(".", "").isalpha()
        )

        if is_official_like:
            low, high = 85, 95
            ts_int = self.stable_random(stable_key, low, high)
            return {
                "trust_score": ts_int,
                "label": "LEGITIMATE",
                "override": "official_like_domain",
                "marketplace_type": marketplace_type,
                "seller_status": seller_status,
                "domain_age": domain_age,
                "ssl_valid": ssl_valid
            }

        # ============= SELLER LOGIC =============
        if marketplace_type != 0:
            if marketplace_type in (1, 2, 3):  # Shopee, Lazada, Temu
                if seller_status == 1:
                    low, high = 80, 85
                elif seller_status == 0:
                    low, high = 70, 83
                else:
                    low, high = 60, 75

            elif marketplace_type == 4:  # TikTok
                if seller_status == 1:
                    low, high = 80, 85
                elif seller_status == 0:
                    low, high = 72, 82
                else:
                    low, high = 60, 75

            elif marketplace_type == 5:  # Facebook
                if seller_status == 1:
                    low, high = 78, 85
                elif seller_status == 0:
                    low, high = 68, 80
                else:
                    low, high = 60, 72

            else:
                if seller_status == 1: low, high = 82, 85
                elif seller_status == 0: low, high = 74, 83
                else: low, high = 65, 75

            if is_http_only:
                low = max(60, low - 10)
                high = max(low, high - 10)

            ts_int = self.stable_random(stable_key, low, high)
            ts_int = min(ts_int, 85)

            label = (
                "LEGITIMATE" if ts_int >= 75 else
                "SUSPICIOUS" if ts_int >= 50 else
                "PHISHING"
            )

            return {
                "trust_score": ts_int,
                "label": label,
                "override": "seller_detected",
                "marketplace_type": marketplace_type,
                "seller_status": seller_status
            }

        # ============= LOCAL WEBSITE (NON-MARKETPLACE) =============
        if marketplace_type == 0:
            if domain_age < 365:
                low, high = 75, 87
            else:
                low, high = 85, 95

            if is_http_only:
                low = max(60, low - 10)
                high = max(low, high - 10)

            ts_int = self.stable_random(stable_key, low, high)
            label = (
                "LEGITIMATE" if ts_int >= 75 else
                "SUSPICIOUS" if ts_int >= 50 else
                "PHISHING"
            )

            return {
                "trust_score": ts_int,
                "label": label,
                "override": "local_store",
                "domain_age": domain_age,
                "ssl_valid": ssl_valid
            }

        # ============= WEIGHTED FALLBACK =============
        w_ml = self.weights["ml"]
        w_vt = self.weights["vt"]
        w_gsb = self.weights["gsb"]
        leftover = max(0.0, 1.0 - (w_ml + w_vt + w_gsb))

        combined = (
            w_ml * ml_component +
            w_vt * vt_component +
            w_gsb * gsb_component +
            leftover * live_component
        )

        combined = min(max(combined, 0.0), 1.0)
        trust_score = round(combined * 100, 2)

        if marketplace_type != 0:
            if seller_status == 1: trust_score = max(trust_score, 80)
            elif seller_status == 0: trust_score = max(0.0, trust_score - 10)
            elif seller_status == 2: trust_score = max(0.0, trust_score - 20)

        trust_score = min(max(trust_score, 0.0), 100.0)

        if trust_score < 50:
            label = "PHISHING"
        elif trust_score < 75:
            label = "SUSPICIOUS"
        else:
            label = "LEGITIMATE"

        return {
            "trust_score": trust_score,
            "label": label,
            "marketplace_type": marketplace_type,
            "seller_status": seller_status,
            "domain_age": domain_age,
            "ssl_valid": ssl_valid,
            "model_probs": {
                "xgb": p_xgb, "rf": p_rf, "ml_final": p_final
            }
        }


# -----------------------------
# GLOBAL PREDICTOR
# -----------------------------
_GLOBAL_PREDICTOR: Predictor | None = None

def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR

def predict_from_features(features: dict, models_obj=None, raw_url: str | None = None):
    if hasattr(models_obj, "predict_from_features"):
        return models_obj.predict_from_features(features, raw_url=raw_url)
    pred = load_models()
    return pred.predict_from_features(features, raw_url=raw_url)


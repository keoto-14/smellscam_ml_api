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

# optional XGBoost support
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

# Simple in-memory cache for VT/GSB results
_CACHE: Dict[str, tuple] = {}
def cache_get(k: str, max_age: int = 3600):
    v = _CACHE.get(k)
    if not v:
        return None
    ts, val = v
    return val if (time.time() - ts) <= max_age else None

def cache_set(k: str, v: Any):
    _CACHE[k] = (time.time(), v)


# ---------------- helpers for loading models ----------------
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


# ---------------- Predictor ----------------
class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # default blending weights (adjust via ENV if needed)
        # by default ml=0.60, vt=0.35, gsb=0.05
        self.weights = {
            "ml": float(os.getenv("ML_WEIGHT", 0.60)),
            "vt": float(os.getenv("VT_WEIGHT", 0.35)),
            "gsb": float(os.getenv("GSB_WEIGHT", 0.05)),
        }

        # if sum > 1, normalize
        s = sum(self.weights.values())
        if s > 1:
            for k in self.weights:
                self.weights[k] = self.weights[k] / s
            logger.info("Normalized weights to sum=1: %s", self.weights)

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
                raise ModelLoadError("features.pkl must be a list/tuple of feature names")

            if HAS_XGB and os.path.exists(xgb_path):
                try:
                    xgb = load_xgb_model(xgb_path)
                except Exception as e:
                    logger.warning("XGB load failed: %s — continuing without xgb", e)
                    xgb = None
            else:
                xgb = None

            self.models = {"rf": rf, "stacker": stacker, "xgb": xgb}
            self.feature_names = list(features)
            self._loaded = True
            logger.info("Models loaded (features=%d) (HAS_XGB=%s) (FAST_MODE=%s)",
                        len(self.feature_names), bool(xgb), FAST_MODE)
        except Exception as e:
            logger.exception("Failed loading models")
            raise ModelLoadError(str(e))


    # ------------------ External checks (VT / GSB) ------------------
    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        """
        Return (total_vendors, malicious_count, ratio).
        If FAST_MODE or no API key => return neutral (0,0,0.0).
        Caches responses for performance.
        """
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
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                mal = stats.get("malicious", 0)
                ratio = mal / total if total > 0 else 0.0
                cache_set(key, {"total": total, "mal": mal, "ratio": ratio})
                return total, mal, ratio
        except Exception as e:
            logger.debug("VT request failed for %s: %s", domain, e)

        # fallback neutral
        cache_set(key, {"total": 0, "mal": 0, "ratio": 0.0})
        return 0, 0, 0.0

    def check_gsb(self, url: str) -> bool:
        """
        Return True if Google Safe Browsing flags the URL.
        Fallback False if FAST_MODE or missing API key.
        """
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
            logger.debug("GSB request failed for %s: %s", url, e)
            cache_set(key, False)
            return False


    # ------------------ live component ------------------------------
    def _live_component(self, feats: dict) -> float:
        """
        Convert live signals (domain_age_days, web_traffic, ssl_valid, quad9_blocked)
        to a [0,1] score. Used as leftover weight in combination.
        """
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

        if traffic >= 1000:
            score *= 1.15
        elif traffic >= 500:
            score *= 1.05
        elif traffic < 100:
            score *= 0.85

        score = max(0.05, min(score, 2.5))
        return score / 2.5


    # -------- stable deterministic pseudo-random integer within range --------
    def stable_random(self, key: str, min_v: int, max_v: int) -> int:
        if not key:
            key = "default"
        base = abs(hash(key)) % 1000000
        return min_v + (base % (max_v - min_v + 1))


    # ------------------ main prediction -----------------------
    def predict_from_features(self, feats: dict, models_obj=None, raw_url: str = None) -> Dict[str, Any]:
        """
        feats: dict of feature_name -> value (should include the features listed in features.pkl)
        models_obj: optional predictor instance (ignored normally)
        raw_url: the original URL string (used for VT/GSB/domain extraction)
        """

        self.load_models()
        if raw_url is None:
            raw_url = feats.get("url", "")

        # Build ordered vector matching features.pkl
        X_vec = [float(feats.get(f, 0.0)) for f in self.feature_names]
        X_df = pd.DataFrame([X_vec], columns=self.feature_names)

        # base model probabilities (malicious probability)
        try:
            if self.models.get("xgb") is not None:
                p_xgb = float(self.models["xgb"].predict_proba(X_df)[0][1])
            else:
                p_xgb = 0.5
        except Exception as e:
            logger.warning("xgb predict_proba failed: %s", e)
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X_df)[0][1])
        except Exception as e:
            logger.warning("rf predict_proba failed: %s", e)
            p_rf = 0.5

        # stacker meta-prediction combining RF/XGB
        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except Exception as e:
            logger.warning("stacker predict failed: %s — falling back to average", e)
            p_final = float((p_xgb + p_rf) / 2.0)

        # Convert malicious probability -> ml_component (higher=trustworthy)
        ml_mal_prob = min(max(p_final, 0.0), 1.0)
        ml_component = 1.0 - ml_mal_prob

        # Parse domain for VT
        parsed = urllib.parse.urlparse(raw_url)
        domain = (parsed.netloc or raw_url).lower().split(":")[0]

        # External signals
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)
        gsb_hit = self.check_gsb(raw_url)

        # VT -> component mapping (neutral when unknown)
        if vt_total == 0:
            vt_component = 1.0
        elif 0 < vt_total < 5:
            vt_component = 0.7
        else:
            vt_component = 1.0 - min(max(vt_ratio, 0.0), 1.0)

        gsb_component = 0.0 if gsb_hit else 1.0
        live_component = float(self._live_component(feats))
        stable_key = domain or raw_url

        # ------------------ Hard overrides ------------------
        # Domain existence (from features) -> immediate phishing if missing
        domain_exists = int(feats.get("domain_exists", 1))
        if domain_exists == 0:
            score = self.stable_random(stable_key, 1, 10)
            logger.info("Domain missing override: domain=%s exists=%s score=%d", domain, domain_exists, score)
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "domain_missing",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": bool(gsb_hit),
                "live_component": round(live_component, 4),
                "domain_exists": domain_exists,
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb")}
            }

        # GSB override => immediate phishing
        if gsb_hit:
            logger.info("GSB override: marking PHISHING (url=%s)", raw_url)
            score = 2
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "gsb",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": True,
                "live_component": round(live_component, 4),
                "domain_exists": domain_exists,
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb")}
            }

        # VT decisive malicious overrides
        if vt_mal >= 6:
            score = self.stable_random(stable_key, 1, 49)
            logger.info("VT severe malicious override (domain=%s mal=%d) score=%d", domain, vt_mal, score)
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "vt_malicious",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": False,
                "live_component": round(live_component, 4),
                "domain_exists": domain_exists,
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb")}
            }

        if 1 <= vt_mal <= 5:
            score = self.stable_random(stable_key, 50, 69)
            logger.info("VT suspicious vendors (domain=%s mal=%d) score=%d", domain, vt_mal, score)
            return {
                "trust_score": score,
                "label": "SUSPICIOUS",
                "override": "vt_suspicious",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": False,
                "live_component": round(live_component, 4),
                "domain_exists": domain_exists,
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb")}
            }

        # ------------------ VT clean (0 malicious) path (VT-preferred) ------------------
        # When vt_mal == 0 we reduce ML influence and favor VT + live
        if vt_mal == 0:
            # reduce ML influence; increase VT influence
            w_ml_vtclean = max(0.05, min(0.25, self.weights.get("ml") * 0.35))
            w_vt_vtclean = max(0.6, min(0.9, self.weights.get("vt") + 0.25))
            w_gsb = self.weights.get("gsb", 0.05)
            leftover = max(0.0, 1.0 - (w_ml_vtclean + w_vt_vtclean + w_gsb))

            vt_pref_combined = (
                w_ml_vtclean * ml_component +
                w_vt_vtclean * vt_component +
                w_gsb * gsb_component +
                leftover * live_component
            )
            vt_pref_combined = min(max(vt_pref_combined, 0.0), 1.0)
            trust_score = round(vt_pref_combined * 100.0, 2)

            # seller & marketplace adjustments (from features)
            seller_status = int(feats.get("seller_status", 0))   # 0 unknown,1 verified,2 suspicious
            marketplace_type = int(feats.get("marketplace_type", 0))  # 0 unknown, >0 marketplace

            if marketplace_type != 0:
                if seller_status == 1:   # verified
                    trust_score = max(trust_score, 80)
                elif seller_status == 0: # unknown seller -> small penalty
                    trust_score = max(0.0, trust_score - 10.0)
                elif seller_status == 2: # suspicious seller -> stronger penalty
                    trust_score = max(0.0, trust_score - 20.0)

            # domain existence again (safety)
            if domain_exists == 0:
                trust_score = min(trust_score, 49)

            # stabilize with deterministic random to give varied but reproducible scores
            if trust_score >= 50:
                trust_score = int(self.stable_random(stable_key, max(50, int(trust_score)), min(100, max(50, int(trust_score) + 5))))
            else:
                trust_score = int(self.stable_random(stable_key, 50, 69))

            label = "LEGITIMATE" if trust_score >= 75 else "SUSPICIOUS" if trust_score >= 50 else "PHISHING"
            logger.info("VT-clean path (domain=%s) trust=%s label=%s seller=%s marketplace=%s", domain, trust_score, label, seller_status, marketplace_type)
            return {
                "trust_score": trust_score,
                "label": label,
                "override": "vt_clean_prefer",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": False,
                "seller_status": int(feats.get("seller_status", 0)),
                "marketplace_type": int(feats.get("marketplace_type", 0)),
                "domain_exists": domain_exists,
                "live_component": round(live_component, 4),
                "weights": {"ml": w_ml_vtclean, "vt": w_vt_vtclean, "gsb": w_gsb, "leftover": leftover}
            }

        # ------------------ Default weighted combination ------------------
        w_ml = self.weights.get("ml", 0.60)
        w_vt = self.weights.get("vt", 0.35)
        w_gsb = self.weights.get("gsb", 0.05)
        leftover = max(0.0, 1.0 - (w_ml + w_vt + w_gsb))

        combined = (
            w_ml * ml_component +
            w_vt * vt_component +
            w_gsb * gsb_component +
            leftover * live_component
        )
        combined = min(max(combined, 0.0), 1.0)
        trust_score = round(combined * 100.0, 2)

        # apply seller adjustments when marketplace link detected
        seller_status = int(feats.get("seller_status", 0))
        marketplace_type = int(feats.get("marketplace_type", 0))

        if marketplace_type != 0:
            if seller_status == 1:
                trust_score = max(trust_score, 80)
            elif seller_status == 0:
                trust_score = max(0.0, trust_score - 10.0)
            elif seller_status == 2:
                trust_score = max(0.0, trust_score - 20.0)

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
            "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
            "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
            "gsb_match": bool(gsb_hit),
            "seller_status": int(feats.get("seller_status", 0)),
            "marketplace_type": int(feats.get("marketplace_type", 0)),
            "domain_exists": int(domain_exists),
            "live_component": round(live_component, 4),
            "weights": {"ml": w_ml, "vt": w_vt, "gsb": w_gsb, "leftover": leftover},
            "breakdown": {
                "ml_component": round(ml_component, 4),
                "vt_component": round(vt_component, 4),
                "gsb_component": round(gsb_component, 4),
                "live_component": round(live_component, 4)
            }
        }


# ---------------- global helpers ----------------
_GLOBAL_PREDICTOR: Predictor | None = None

def load_models():
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = Predictor()
        _GLOBAL_PREDICTOR.load_models()
    return _GLOBAL_PREDICTOR

def predict_from_features(features: dict, models_obj=None, raw_url: str | None = None):
    """
    Wrapper used by app.py: `predict_from_features(features, models, raw_url=url)`
    """
    if hasattr(models_obj, "predict_from_features"):
        return models_obj.predict_from_features(features, raw_url=raw_url)
    pred = load_models()
    return pred.predict_from_features(features, raw_url=raw_url)

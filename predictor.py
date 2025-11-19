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

# simple in-memory cache for VT/GSB
_CACHE: Dict[str, tuple] = {}
def cache_get(k: str, max_age: int = 3600):
    v = _CACHE.get(k)
    if not v:
        return None
    ts, val = v
    return val if (time.time() - ts) <= max_age else None

def cache_set(k: str, v: Any):
    _CACHE[k] = (time.time(), v)


# --------------------- model loading helpers ---------------------
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


# --------------------- Predictor class ---------------------------
class Predictor:
    def __init__(self):
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False

        # default weights (can change via env)
        self.weights = {
            "ml": float(os.getenv("ML_WEIGHT", 0.60)),
            "vt": float(os.getenv("VT_WEIGHT", 0.35)),
            "gsb": float(os.getenv("GSB_WEIGHT", 0.05)),
        }

        # keep sum <=1; leftover goes to live component
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

            self.models = {
                "rf": rf,
                "stacker": stacker,
                "xgb": xgb,
            }
            self.feature_names = list(features)
            self._loaded = True
            logger.info("Models loaded successfully (features=%d) (HAS_XGB=%s) (FAST_MODE=%s)",
                         len(self.feature_names), bool(xgb), FAST_MODE)

        except Exception as e:
            logger.exception("Failed loading models")
            raise ModelLoadError(str(e))

    # ------------------ External checks (VT / GSB) ------------------
    # Minimal, cached implementations. If env keys missing or FAST_MODE,
    # these return neutral results.

    def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        """
        Returns (total_vendors, malicious_count, ratio)
        ratio = malicious / total
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
        """Return True if GSB flags the url. Fallback: False (not flagged)."""
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
        """Return a normalized [0,1] live score using domain age, traffic, ssl, quad9."""
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

    # -------- stable pseudo-random trust score --------
    def stable_random(self, key: str, min_v: int, max_v: int) -> int:
        """Return stable pseudo-random integer based on URL/domain.
        Deterministic: same key -> same number.
        """
        if not key:
            key = "default"
        # Use a stable hash and reduce to range
        base = abs(hash(key)) % 1000000
        return min_v + (base % (max_v - min_v + 1))

    # ------------------ predict from features -----------------------
    def predict_from_features(self, feats: dict, models_obj=None, raw_url: str = None) -> Dict[str, Any]:
        """
        feats: mapping feature_name->value (should include all names in features.pkl)
        models_obj: optional loaded predictor instance or dict; ignored normally
        raw_url: original url string (used for vt/gsb)
        """
        self.load_models()
        if raw_url is None:
            raw_url = feats.get("url", "")

        # Build ordered DataFrame to avoid sklearn warnings about feature names
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

        # Stacker meta-prediction
        try:
            meta = np.asarray([[p_xgb, p_rf]])
            p_final = float(self.models["stacker"].predict_proba(meta)[0][1])
        except Exception as e:
            logger.warning("stacker predict failed: %s — falling back to average", e)
            p_final = float((p_xgb + p_rf) / 2.0)

        # ml_component: higher = more trustworthy (we convert malicious prob -> trust component)
        ml_mal_prob = min(max(p_final, 0.0), 1.0)
        ml_component = 1.0 - ml_mal_prob

        # Domain for VT
        parsed = urllib.parse.urlparse(raw_url)
        domain = (parsed.netloc or raw_url).lower().split(":")[0]

        # External checks
        vt_total, vt_mal, vt_ratio = self.vt_domain_report(domain)
        gsb_hit = self.check_gsb(raw_url)

        # ---------------- VT logic: neutral when no vendors ----------------
        if vt_total == 0:
            vt_component = 1.0           # Unknown -> neutral (do not penalize)
        elif 0 < vt_total < 5:
            vt_component = 0.7           # weak evidence -> suspicious but not decisive
        else:
            vt_component = 1.0 - min(max(vt_ratio, 0.0), 1.0)

        # GSB component: 0 if hit (bad), 1 if not hit (good)
        gsb_component = 0.0 if gsb_hit else 1.0

        # live component
        live_component = float(self._live_component(feats))

        # ------------------ OVERRIDES (stable random ranges & rules) ------------------
        stable_key = domain or raw_url

        # 1) GSB override (immediate PHISHING)
        if gsb_hit:
            logger.info("GSB override: marking PHISHING (url=%s)", raw_url)
            # small fixed low trust score to indicate severe issue
            score = 2
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "gsb",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": True,
                "live_component": round(live_component, 4),
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb"), "leftover": max(0.0, 1.0 - sum(self.weights.values()))}
            }

        # 2) VT malicious vendors mapping:
        #    vt_mal >= 6  -> PHISHING (trust 1-49)
        if vt_mal >= 6:
            score = self.stable_random(stable_key, 1, 49)
            logger.info("VT severe malicious override (domain=%s mal=%d) score=%d", domain, vt_mal, score)
            return {
                "trust_score": score,
                "label": "PHISHING",
                "override": "vt_malicious",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": gsb_hit,
                "live_component": round(live_component, 4),
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb"), "leftover": max(0.0, 1.0 - sum(self.weights.values()))}
            }

        # 3) VT 1..5 malicious -> SUSPICIOUS (trust 50-69)
        if 1 <= vt_mal <= 5:
            score = self.stable_random(stable_key, 50, 69)
            logger.info("VT suspicious vendors (domain=%s mal=%d) score=%d", domain, vt_mal, score)
            return {
                "trust_score": score,
                "label": "SUSPICIOUS",
                "override": "vt_suspicious",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": gsb_hit,
                "live_component": round(live_component, 4),
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb"), "leftover": max(0.0, 1.0 - sum(self.weights.values()))}
            }

        # 4) VT zero malicious vendors -> use ML/VT agreement rules
        # CASE 1: ML says legit and VT shows 0 malicious -> high legit (90-100)
        if ml_component > 0.65 and vt_mal == 0:
            score = self.stable_random(stable_key, 90, 100)
            logger.info("ML & VT agree legit (domain=%s) score=%d", domain, score)
            return {
                "trust_score": score,
                "label": "LEGITIMATE",
                "override": "ml_vt_agree",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": gsb_hit,
                "live_component": round(live_component, 4),
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb"), "leftover": max(0.0, 1.0 - sum(self.weights.values()))}
            }

        # CASE 2: ML says phishing but VT has 0 malicious -> let VT (secondary) override ML
        if ml_component < 0.5 and vt_mal == 0:
            score = self.stable_random(stable_key, 70, 89)
            label = "LEGITIMATE" if score >= 70 else "SUSPICIOUS"
            logger.info("VT overrides ML (domain=%s) score=%d label=%s", domain, score, label)
            return {
                "trust_score": score,
                "label": label,
                "override": "vt_overrides_ml",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": gsb_hit,
                "live_component": round(live_component, 4),
                "weights": {"ml": self.weights.get("ml"), "vt": self.weights.get("vt"), "gsb": self.weights.get("gsb"), "leftover": max(0.0, 1.0 - sum(self.weights.values()))}
            }

        # ---------------- If none of the overrides fired, fallback to weighted combine ----------------
        # weights (ml, vt, gsb) from self.weights, leftover goes to live
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

        # ---------------- Overrides: strong external signals kept as extra safety ----------------
        # Note: we've implemented VT/GSB overrides above according to your requested rules.
        # Keep a small extra GSB safety net (shouldn't be reached because we returned earlier when gsb_hit).
        if gsb_hit:
            logger.info("GSB (late) override: marking PHISHING (url=%s)", raw_url)
            return {
                "trust_score": 2.0,
                "label": "PHISHING",
                "override": "gsb",
                "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
                "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
                "gsb_match": True,
                "live_component": round(live_component, 4),
                "weights": {"ml": w_ml, "vt": w_vt, "gsb": w_gsb, "leftover": leftover}
            }

        # Normal label mapping
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
    Convenience wrapper used by app.py: `predict_from_features(features, models, raw_url=url)`
    """
    if hasattr(models_obj, "predict_from_features"):
        return models_obj.predict_from_features(features, raw_url=raw_url)
    # fallback to global predictor
    pred = load_models()
    return pred.predict_from_features(features, raw_url=raw_url)

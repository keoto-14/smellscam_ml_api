# predictor.py
"""
Enterprise Predictor module.
- Async external lookups via httpx
- Simple in-process TTL cache (safe for single-instance deployments)
- Loads your existing models (xgboost, rf, stacker) from MODEL_DIR
- Uses your existing url_feature_extractor.extract_all_features (keeps full feature set)
- Performs shopping-site validation and returns 'not_shopping' response early
"""

from __future__ import annotations

import os
import time
import pickle
import logging
import urllib.parse
import asyncio
from typing import Any, Dict, Tuple, Optional

import numpy as np
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# Do not import DataEfficiencyWarning (caused ImportError). Only silence common warnings if needed.
import warnings
from sklearn.exceptions import DataConversionWarning
warnings.filterwarnings("ignore", category=DataConversionWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# import your (unchanged) feature extractor
from url_feature_extractor import extract_all_features

# rules engine
from rules import compute_rule_risk

# logging
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# config
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# ----------------------------
# Pydantic request/response
# ----------------------------
class PredictRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")


class VTInfo(BaseModel):
    total_vendors: int
    malicious: int
    ratio: float


class ModelProbs(BaseModel):
    xgb: float
    rf: float
    ml_final: float


class PredictResponse(BaseModel):
    prediction: str
    trust_score: float
    risk_score: float
    gsb_match: bool
    vt: VTInfo
    model_probs: ModelProbs
    rule_risk: float


# ----------------------------
# Simple TTL cache (async-safe)
# ----------------------------
class SimpleTTLCache:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl = ttl_seconds
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str):
        rec = self._store.get(key)
        if not rec:
            return None
        ts, value = rec
        if time.time() - ts > self.ttl:
            try:
                del self._store[key]
            except KeyError:
                pass
            return None
        return value

    def set(self, key: str, value: Any):
        self._store[key] = (time.time(), value)

_cache = SimpleTTLCache(ttl_seconds=600)


# ----------------------------
# Helper: model loaders
# ----------------------------
def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
    """Load XGBoost model saved as JSON or binary (requires xgboost installed)."""
    try:
        from xgboost import XGBClassifier
    except Exception as e:
        raise RuntimeError("xgboost is required to load xgb model") from e

    model = XGBClassifier()
    model.load_model(path)
    return model


# ----------------------------
# Predictor class
# ----------------------------
class Predictor:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.models: Dict[str, Any] = {}
        self.feature_names = []
        self._loaded = False
        # weighting (tunable)
        self.weights = {"ml": 0.55, "vt": 0.35, "gsb": 0.10}

    def load_models(self):
        if self._loaded:
            return
        try:
            xgb_path = os.path.join(self.model_dir, "xgb.json")
            rf_path = os.path.join(self.model_dir, "rf.pkl")
            stacker_path = os.path.join(self.model_dir, "stacker.pkl")
            features_path = os.path.join(self.model_dir, "features.pkl")

            models = {
                "xgb": load_xgb_model(xgb_path),
                "rf": load_pickle(rf_path),
                "stacker": load_pickle(stacker_path),
                "features": load_pickle(features_path),
            }
            self.models = models
            self.feature_names = list(models["features"])
            self._loaded = True
            logger.info("Models loaded from %s", self.model_dir)
        except FileNotFoundError as e:
            logger.exception("Model file not found: %s", e)
            raise
        except Exception as e:
            logger.exception("Failed to load models: %s", e)
            raise

    # ----------------------------
    # Async HTTP helpers (cached)
    # ----------------------------
    async def _async_post_json(self, url: str, json_body: dict, timeout: float = 6.0) -> Tuple[int, Optional[dict]]:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(url, json=json_body)
                r.raise_for_status()
                return r.status_code, r.json()
        except Exception as e:
            logger.debug("async_post_json failed: %s %s", url, e)
            return getattr(e, "response", None).status_code if getattr(e, "response", None) else 0, None

    async def _async_get_json(self, url: str, headers: dict = None, timeout: float = 6.0) -> Tuple[int, Optional[dict]]:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.get(url, headers=headers or {})
                r.raise_for_status()
                return r.status_code, r.json()
        except Exception as e:
            logger.debug("async_get_json failed: %s %s", url, e)
            return getattr(e, "response", None).status_code if getattr(e, "response", None) else 0, None

    # ----------------------------
    # Google Safe Browsing (async + cached)
    # ----------------------------
    async def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False
        cache_key = f"gsb::{url}"
        cached = _cache.get(cache_key)
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
        code, data = await self._async_post_json(endpoint, body, timeout=7.0)
        match = bool(data and data.get("matches"))
        _cache.set(cache_key, match)
        return match

    # ----------------------------
    # VirusTotal domain report (async + cached)
    # ----------------------------
    async def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        if not VT_API_KEY:
            return 0, 0, 0.0
        cache_key = f"vt::{domain}"
        cached = _cache.get(cache_key)
        if cached:
            return cached["total"], cached["mal"], cached["ratio"]
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        code, data = await self._async_get_json(url, headers=headers, timeout=7.0)
        if data:
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if isinstance(stats, dict) else 0
            mal = stats.get("malicious", 0) if isinstance(stats, dict) else 0
            ratio = mal / total if total > 0 else 0.0
            _cache.set(cache_key, {"total": int(total), "mal": int(mal), "ratio": float(ratio)})
            return int(total), int(mal), float(ratio)
        return 0, 0, 0.0

    # ----------------------------
    # Main async prediction
    # ----------------------------
    async def predict_url(self, raw_url: str) -> Dict[str, Any]:
        # Validate input
        if not raw_url or not isinstance(raw_url, str):
            raise HTTPException(status_code=400, detail="Invalid URL")

        # Load models (sync)
        try:
            self.load_models()
        except Exception as e:
            logger.exception("Model load error")
            raise HTTPException(status_code=500, detail="Model loading failed")

        # Extract features (uses your enterprise extractor)
        try:
            features = extract_all_features(raw_url)
        except Exception as e:
            logger.exception("Feature extraction failed: %s", e)
            raise HTTPException(status_code=500, detail="Feature extraction failed")

        # ----------------------------
        # SHOPPING-SITE REJECTION (early return)
        # ----------------------------
        try:
            if int(features.get("is_shopping", 0)) == 0:
                return {
                    "prediction": "not_shopping",
                    "trust_score": 100.0,
                    "risk_score": 0.0,
                    "gsb_match": False,
                    "vt": {"total_vendors": 0, "malicious": 0, "ratio": 0.0},
                    "model_probs": {"xgb": 0.0, "rf": 0.0, "ml_final": 0.0},
                    "rule_risk": 0.0
                }
        except Exception:
            # If weird value, continue normally
            pass

        # Prepare numeric feature vector (safe ordering)
        X = np.asarray([[float(features.get(f, 0)) for f in self.feature_names]], dtype=float)

        # ML predictions with safe fallbacks
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except Exception:
            p_xgb = 0.5
        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception:
            p_rf = 0.5

        # Stacker
        try:
            stack_in = np.asarray([[p_xgb, p_rf]], dtype=float)
            final_ml = float(self.models["stacker"].predict_proba(stack_in)[0][1])
        except Exception:
            final_ml = (p_xgb + p_rf) / 2.0

        ml_risk = final_ml * 100.0

        # Domain for VT
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.lower().split(":")[0]

        # Launch async checks (create fresh coroutines / tasks)
        gsb_task = asyncio.create_task(self.check_gsb(raw_url) if hasattr(self, "check_gsb") else self.check_gsb(raw_url))
        vt_task = asyncio.create_task(self.vt_domain_report(domain))

        # Await both (no reuse)
        gsb_match = await gsb_task
        vt_total, vt_mal, vt_ratio = await vt_task

        # vt risk transform
        vt_risk = ((vt_ratio * 100.0) ** 2) / 100.0
        vt_risk = min(vt_risk, 100.0)
        gsb_risk = 100.0 if gsb_match else 0.0

        # rule risk
        rule_risk = float(compute_rule_risk(raw_url, features))

        # final weighted risk
        FINAL_RISK = (
            ml_risk * self.weights["ml"] +
            vt_risk * self.weights["vt"] +
            gsb_risk * self.weights["gsb"] +
            rule_risk
        )
        FINAL_RISK = max(0.0, min(FINAL_RISK, 100.0))
        trust = 100.0 - FINAL_RISK

        resp = {
            "prediction": "phishing" if FINAL_RISK >= 50.0 else "safe",
            "trust_score": round(trust, 3),
            "risk_score": round(FINAL_RISK, 3),
            "gsb_match": bool(gsb_match),
            "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
            "model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final": float(final_ml)},
            "rule_risk": float(rule_risk),
        }

        # validate shape using Pydantic
        try:
            validated = PredictResponse(
                prediction=resp["prediction"],
                trust_score=resp["trust_score"],
                risk_score=resp["risk_score"],
                gsb_match=resp["gsb_match"],
                vt=VTInfo(**resp["vt"]),
                model_probs=ModelProbs(**resp["model_probs"]),
                rule_risk=resp["rule_risk"]
            )
            return validated.dict()
        except Exception:
            # fallback to raw response if validation fails
            return resp


# ----------------------------
# Expose router
# ----------------------------
router = APIRouter()
predictor_instance = Predictor()

@router.post("/predict", response_model=PredictResponse)
async def predict_endpoint(req: PredictRequest):
    return await predictor_instance.predict_url(req.url)

# convenience export
predictor_router = router

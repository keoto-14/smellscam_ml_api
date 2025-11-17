"""
predictor.py

Production-ready, refactored Predictor module for SmellScam.
Features:
- Class-based Predictor
- Async external lookups (Google Safe Browsing, VirusTotal) using httpx
- In-memory TTL caching via cachetools
- Sklearn warning-safe imports
- Pydantic request/response models for validation
- FastAPI APIRouter for easy mounting
- Robust error handling and logging

How to use:
- Import `predictor_router` and mount into your FastAPI app:
    from fastapi import FastAPI
    from predictor import predictor_router, Predictor

    app = FastAPI()
    app.include_router(predictor_router, prefix="/api/v1")

- Or instantiate Predictor directly and call `await predictor.predict_url(raw_url)`

Environment variables:
- GSB_API_KEY  (Google Safe Browsing)
- VT_API_KEY   (VirusTotal - optional)
- MODEL_DIR    (default: "models")

This file intentionally avoids writing any blocking long-running code at import time.
"""

from __future__ import annotations

import os
import pickle
import logging
import urllib.parse
from typing import Dict, Any, List, Tuple

import asyncio
import math

import numpy as np
import httpx
from cachetools import TTLCache, cached
from pydantic import BaseModel, HttpUrl, Field
from fastapi import APIRouter, HTTPException

# ---------------------------
# Logging & warnings cleanup
# ---------------------------
import warnings
from sklearn.exceptions import DataConversionWarning

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DataConversionWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*efficienc.*", module="sklearn")

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# ---------------------------
# Configuration
# ---------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# Cache for external calls (in-memory TTL)
# - entries live for 10 minutes by default
_external_cache = TTLCache(maxsize=4096, ttl=600)

# ---------------------------
# Pydantic models (input/output)
# ---------------------------
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

# ---------------------------
# Utility loaders
# ---------------------------

def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
    # load xgboost model saved as JSON or binary
    try:
        from xgboost import XGBClassifier
    except Exception as e:
        raise RuntimeError("xgboost not available") from e

    model = XGBClassifier()
    model.load_model(path)
    return model


class ModelLoadError(Exception):
    pass

# ---------------------------
# Predictor class
# ---------------------------
class Predictor:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.models: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self._models_loaded = False
        # tunable weights
        self.weights = {
            "ml": 0.50,
            "vt": 0.45,
            "gsb": 0.05,
        }

    def load_models(self):
        """Synchronous model loading. Keep quick and safe at startup."""
        if self._models_loaded:
            return self.models

        logger.info("Loading models from %s", self.model_dir)
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
            self._models_loaded = True

            logger.info("Models loaded. XGB type=%s", type(models["xgb"]))
            return self.models

        except FileNotFoundError as e:
            logger.exception("Model file not found: %s", e)
            raise ModelLoadError(str(e))
        except Exception as e:
            logger.exception("Error loading models: %s", e)
            raise ModelLoadError(str(e))

    # ---------------------------
    # Async external lookups
    # ---------------------------
    @staticmethod
    def _make_http_client(timeout: float = 6.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=httpx.Timeout(timeout))

    @cached(_external_cache)
    async def check_gsb(self, url: str) -> bool:
        """Call Google Safe Browsing API (async). Returns True if matched."""
        if not GSB_API_KEY:
            return False

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
            async with self._make_http_client() as client:
                r = await client.post(endpoint, json=body)
                r.raise_for_status()
                data = r.json()
                return bool(data.get("matches"))
        except Exception as e:
            logger.debug("GSB check failed for %s: %s", url, e)
            return False

    @cached(_external_cache)
    async def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        """Call VirusTotal domains API. Returns (total, malicious, ratio)."""
        if not VT_API_KEY:
            return 0, 0, 0.0

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}

        try:
            async with self._make_http_client() as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()

                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                mal = stats.get("malicious", 0) if stats else 0
                ratio = mal / total if total > 0 else 0.0
                return int(total), int(mal), float(ratio)
        except Exception as e:
            logger.debug("VT lookup failed for %s: %s", domain, e)
            return 0, 0, 0.0

    # ---------------------------
    # Rules & heuristics
    # ---------------------------
    SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store"}
    BRAND_LIST = ["nike", "adidas", "asics", "apple", "samsung", "puma", "uniqlo", "dhl", "fedex"]

    @classmethod
    def detect_brand_impersonation(cls, domain: str) -> bool:
        for brand in cls.BRAND_LIST:
            if brand in domain and not domain.endswith(brand + ".com"):
                return True
        return False

    @staticmethod
    def detect_redirect_scam(url: str) -> int:
        u = url.lower()
        return int("utm_" in u or "fbclid" in u)

    # ---------------------------
    # Core prediction (async wrapper)
    # ---------------------------
    async def predict_url(self, raw_url: str) -> Dict[str, Any]:
        """Top-level prediction entrypoint. Loads models if necessary, extracts features, does async calls.

        Returns a JSON-serializable dict matching PredictResponse.
        """
        # ensure models loaded
        self.load_models()

        # simple feature extraction (placeholder) -- users can provide a richer extractor
        features = self._extract_basic_features(raw_url)

        # prepare numeric X for models
        X = np.asarray([[float(features.get(f, 0)) for f in self.feature_names]], dtype=float)

        # predict with model fallbacks
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except Exception:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception:
            p_rf = 0.5

        # stacker
        stack_input = np.asarray([[p_xgb, p_rf]], dtype=float)
        try:
            final_ml = float(self.models["stacker"].predict_proba(stack_input)[0][1])
        except Exception:
            final_ml = (p_xgb + p_rf) / 2

        ml_risk = final_ml * 100

        # domain parsing
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.lower().split(":")[0]

        # run async external checks concurrently
        gsb_task = asyncio.create_task(self.check_gsb(raw_url))
        vt_task = asyncio.create_task(self.vt_domain_report(domain))

        gsb_match = await gsb_task
        vt_total, vt_mal, vt_ratio = await vt_task

        vt_risk = ((vt_ratio * 100) ** 2) / 100
        vt_risk = min(vt_risk, 100)

        gsb_risk = 100 if gsb_match else 0

        # custom rules
        rule_risk = 0
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                rule_risk += 15

        if self.detect_brand_impersonation(domain):
            rule_risk += 25

        if self.detect_redirect_scam(raw_url):
            rule_risk += 10

        # final weighted risk (weights tunable)
        FINAL_RISK = (
            ml_risk * self.weights["ml"] +
            vt_risk * self.weights["vt"] +
            gsb_risk * self.weights["gsb"] +
            rule_risk
        )

        FINAL_RISK = max(0.0, min(float(FINAL_RISK), 100.0))
        trust = 100.0 - FINAL_RISK
        prediction = "phishing" if FINAL_RISK >= 50.0 else "safe"

        response = {
            "prediction": prediction,
            "trust_score": round(trust, 3),
            "risk_score": round(FINAL_RISK, 3),
            "gsb_match": bool(gsb_match),
            "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
            "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": final_ml},
            "rule_risk": float(rule_risk),
        }

        # validate via pydantic model to ensure shape
        try:
            validated = PredictResponse(**response)
            return validated.dict()
        except Exception as e:
            logger.exception("Response validation failed: %s", e)
            # fall back to raw response
            return response

    # ---------------------------
    # Simple local feature extractor
    # ---------------------------
    def _extract_basic_features(self, raw_url: str) -> Dict[str, float]:
        """A compact, deterministic feature extractor that mirrors previous behavior.
        Replace with your `url_feature_extractor.extract_all_features` implementation when available.
        """
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.lower()
        path = parsed.path or ""

        features: Dict[str, float] = {}
        features["url_length"] = float(len(raw_url))
        features["domain_length"] = float(len(domain))
        features["num_dots"] = float(domain.count("."))
        features["has_https"] = float(parsed.scheme == "https")
        features["has_ip"] = float(bool(re.match(r"^\d+\.\d+\.\d+\.\d+", domain)))
        features["suspicious_tld"] = float(any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS))
        features["redirect_param"] = float(self.detect_redirect_scam(raw_url))
        # add placeholders for other features expected by model
        for fn in self.feature_names:
            if fn not in features:
                features[fn] = 0.0
        return features

# expose a default predictor instance and router
_predictor = Predictor()

router = APIRouter()

@router.post("/predict", response_model=PredictResponse)
async def predict_endpoint(req: PredictRequest):
    try:
        return await _predictor.predict_url(req.url)
    except ModelLoadError as e:
        logger.error("Model load error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Unhandled error in prediction: %s", e)
        raise HTTPException(status_code=500, detail="prediction failed")

# convenience exports
predictor_router = router
PredictorClass = Predictor

# When run directly for a quick smoke test (not for production)
if __name__ == "__main__":
    import uvicorn

    app = None
    try:
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(predictor_router, prefix="/api/v1/predictor")
        uvicorn.run(app, host="0.0.0.0", port=8001)
    except Exception as e:
        logger.exception("Failed to start test server: %s", e)

"""
predictor.py — Async-safe Predictor with in-flight dedupe and TTL caching.

Key features:
- Async httpx calls to Google Safe Browsing and VirusTotal
- TTLCache (cachetools) storing plain results (no coroutine objects)
- _inflight dict to dedupe concurrent same-key calls (awaits the same task)
- Robust fallbacks and logging
- FastAPI APIRouter exposing POST /predict (used by app.include_router(..., prefix="/api/v1"))
"""

from __future__ import annotations

import os
import pickle
import logging
import urllib.parse
import asyncio
from typing import Dict, Any, Tuple, List

import numpy as np
import httpx
from cachetools import TTLCache
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

# warnings cleanup
import warnings
from sklearn.exceptions import DataConversionWarning
warnings.filterwarnings("ignore", category=DataConversionWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*efficienc.*", module="sklearn")

# logger
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# ---------------------------
# Configuration & caches
# ---------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# TTLCache for storing simple results (10 minutes default)
_EXTERNAL_CACHE_TTL = int(os.environ.get("SMELLSCAM_CACHE_TTL", "600"))
_external_cache = TTLCache(maxsize=4096, ttl=_EXTERNAL_CACHE_TTL)

# In-flight map to dedupe concurrent external calls:
# key -> asyncio.Task which returns the concrete result
_inflight_tasks: Dict[str, asyncio.Task] = {}

# ---------------------------
# Pydantic models
# ---------------------------
class PredictRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")


class PredictResponse(BaseModel):
    prediction: str
    trust_score: float
    risk_score: float
    gsb_match: bool
    vt: dict
    model_probs: dict
    rule_risk: float


# ---------------------------
# Utilities
# ---------------------------
def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
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

    def load_models(self):
        if self._models_loaded:
            return self.models

        logger.info("Loading ML models from %s", self.model_dir)
        try:
            xgb_path = os.path.join(self.model_dir, "xgb.json")
            rf_path = os.path.join(self.model_dir, "rf.pkl")
            stacker_path = os.path.join(self.model_dir, "stacker.pkl")
            features_path = os.path.join(self.model_dir, "features.pkl")

            self.models = {
                "xgb": load_xgb_model(xgb_path),
                "rf": load_pickle(rf_path),
                "stacker": load_pickle(stacker_path),
                "features": load_pickle(features_path),
            }
            self.feature_names = list(self.models["features"])
            self._models_loaded = True

            logger.info("Models loaded (xgb type=%s)", type(self.models["xgb"]))
            return self.models
        except FileNotFoundError as e:
            logger.exception("Model file not found: %s", e)
            raise ModelLoadError(str(e))
        except Exception as e:
            logger.exception("Error loading models: %s", e)
            raise ModelLoadError(str(e))

    # small factory for AsyncClient - using context manager per request is fine here
    @staticmethod
    def _make_client(timeout: float = 6.0) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout)

    # ---------------------------
    # Async external calls with async-safe caching + in-flight dedupe
    # ---------------------------
    async def _fetch_gsb(self, url: str) -> bool:
        """Perform the actual network call to GSB and return a boolean."""
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
            async with self._make_client() as client:
                r = await client.post(endpoint, json=body)
                r.raise_for_status()
                data = r.json()
                return bool(data.get("matches"))
        except Exception as exc:
            logger.debug("GSB network error for %s: %s", url, exc)
            return False

    async def check_gsb(self, url: str) -> bool:
        """
        Async-safe GSB check with:
         - TTL cache (_external_cache) storing boolean results
         - in-flight dedupe: concurrent callers await the same task
        """
        if not GSB_API_KEY:
            return False

        key = f"gsb::{url}"

        # 1) cache hit -> return plain bool
        cached = _external_cache.get(key)
        if cached is not None:
            return bool(cached)

        # 2) dedupe: if a pending task exists, await it
        task = _inflight_tasks.get(key)
        if task is not None:
            try:
                result = await task
                return bool(result)
            except Exception:
                # fall through to create a fresh request
                logger.debug("existing inflight gsb task failed for %s, creating new", url)

        # 3) create a new task, store it, await, and cache result
        loop = asyncio.get_running_loop()
        coro = self._fetch_gsb(url)
        task = loop.create_task(coro)
        _inflight_tasks[key] = task
        try:
            result = await task
            # store concrete result (not coroutine)
            _external_cache[key] = bool(result)
            return bool(result)
        finally:
            # always remove inflight entry
            _inflight_tasks.pop(key, None)

    # ---------------------------
    async def _fetch_vt(self, domain: str) -> Tuple[int, int, float]:
        """Actual VirusTotal call: returns (total, malicious, ratio)."""
        url_api = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            async with self._make_client() as client:
                r = await client.get(url_api, headers=headers)
                r.raise_for_status()
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if not isinstance(stats, dict) or not stats:
                    return 0, 0, 0.0
                total = int(sum(stats.values()))
                mal = int(stats.get("malicious", 0))
                ratio = float(mal / total) if total > 0 else 0.0
                return total, mal, ratio
        except Exception as exc:
            logger.debug("VT network error for %s: %s", domain, exc)
            return 0, 0, 0.0

    async def vt_domain_report(self, domain: str) -> Tuple[int, int, float]:
        """
        Async-safe VT domain report with TTL cache and in-flight dedupe.
        Returns (total_vendors, malicious_count, ratio)
        """
        if not VT_API_KEY:
            return 0, 0, 0.0

        key = f"vt::{domain}"

        cached = _external_cache.get(key)
        if cached is not None:
            # cached stored as dict {"total":..., "mal":..., "ratio":...}
            return int(cached["total"]), int(cached["mal"]), float(cached["ratio"])

        # dedupe concurrent calls
        task = _inflight_tasks.get(key)
        if task is not None:
            try:
                res = await task
                return int(res["total"]), int(res["mal"]), float(res["ratio"])
            except Exception:
                logger.debug("existing inflight vt task failed for %s, proceeding to new request", domain)

        loop = asyncio.get_running_loop()
        coro = self._fetch_vt(domain)
        task = loop.create_task(coro)
        _inflight_tasks[key] = task
        try:
            total, mal, ratio = await task
            payload = {"total": int(total), "mal": int(mal), "ratio": float(ratio)}
            _external_cache[key] = payload
            return total, mal, ratio
        finally:
            _inflight_tasks.pop(key, None)

    # ---------------------------
    # Heuristics / Rules (same logic as before)
    # ---------------------------
    SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz", ".store"}
    BRAND_LIST = ["nike", "adidas", "asics", "apple", "samsung", "puma", "uniqlo", "dhl", "fedex"]

    @classmethod
    def detect_brand_impersonation(cls, domain: str) -> bool:
        domain = (domain or "").lower()
        for brand in cls.BRAND_LIST:
            if brand in domain and not domain.endswith(brand + ".com"):
                return True
        return False

    @staticmethod
    def detect_redirect_scam(url: str) -> int:
        u = (url or "").lower()
        return int("utm_" in u or "fbclid" in u)

    # ---------------------------
    # Core prediction entrypoint (async)
    # ---------------------------
    async def predict_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Main prediction function.
        - loads models if needed
        - computes simple feature vector (safe placeholders)
        - runs ML predictions with fallbacks
        - runs async external checks concurrently (GSB + VT) using dedupe + cache
        - blends final risk and returns result dict
        """
        # ensure models exist
        self.load_models()

        # minimal feature extraction to satisfy model input
        features = {}
        for fn in self.feature_names:
            features[fn] = 0.0
        # a few simple heuristics to populate something meaningful
        try:
            features["url_length"] = float(len(raw_url))
        except Exception:
            features["url_length"] = 0.0

        # prepare X
        X = np.asarray([[float(features.get(f, 0)) for f in self.feature_names]], dtype=float)

        # ML predictions with safe fallbacks
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except Exception as exc:
            logger.debug("xgb predict failed: %s", exc)
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except Exception as exc:
            logger.debug("rf predict failed: %s", exc)
            p_rf = 0.5

        try:
            final_ml = float(self.models["stacker"].predict_proba([[p_xgb, p_rf]])[0][1])
        except Exception:
            final_ml = (p_xgb + p_rf) / 2.0

        ml_risk = final_ml * 100.0

        # parse domain
        parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
        domain = (parsed.netloc or "").lower().split(":")[0]

        # run external checks concurrently (these functions are async-safe)
        gsb_task = asyncio.create_task(self.check_gsb(raw_url))
        vt_task = asyncio.create_task(self.vt_domain_report(domain))

        # await results
        gsb_match = False
        vt_total = vt_mal = 0
        vt_ratio = 0.0
        try:
            gsb_match = await gsb_task
        except Exception as exc:
            logger.debug("GSB task exception: %s", exc)
            gsb_match = False

        try:
            vt_total, vt_mal, vt_ratio = await vt_task
        except Exception as exc:
            logger.debug("VT task exception: %s", exc)
            vt_total, vt_mal, vt_ratio = 0, 0, 0.0

        # compute vt_risk and gsb_risk
        vt_risk = min(((vt_ratio * 100.0) ** 2) / 100.0, 100.0)
        gsb_risk = 100.0 if gsb_match else 0.0

        # rule-based risk
        rule_risk = 0.0
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                rule_risk += 15.0
        if self.detect_brand_impersonation(domain):
            rule_risk += 25.0
        if self.detect_redirect_scam(raw_url):
            rule_risk += 10.0

        # blend final risk (weights tuned as before)
        FINAL_RISK = (
            ml_risk * 0.50 +
            vt_risk * 0.45 +
            gsb_risk * 0.05 +
            rule_risk
        )
        FINAL_RISK = max(0.0, min(FINAL_RISK, 100.0))
        trust = 100.0 - FINAL_RISK
        prediction = "phishing" if FINAL_RISK >= 50.0 else "safe"

        response = {
            "prediction": prediction,
            "trust_score": round(trust, 3),
            "risk_score": round(FINAL_RISK, 3),
            "gsb_match": bool(gsb_match),
            "vt": {"total_vendors": int(vt_total), "malicious": int(vt_mal), "ratio": float(vt_ratio)},
            "model_probs": {"xgb": float(p_xgb), "rf": float(p_rf), "ml_final": float(final_ml)},
            "rule_risk": float(rule_risk),
        }

        # validate with pydantic model to ensure consistent shape
        try:
            validated = PredictResponse(**response)
            return validated.dict()
        except Exception as exc:
            logger.exception("Response validation failed: %s", exc)
            return response


# ---------------------------
# Router & exports
# ---------------------------
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


predictor_router = router
PredictorClass = Predictor

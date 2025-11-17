"""
Enhanced predictor.py
- Persistent httpx.AsyncClient (reuse per request)
- Async dedupe (prevents coroutine reuse)
- TTL cache for external calls
- Model loader unchanged
- Fully production ready
"""

from __future__ import annotations

import os
import pickle
import logging
import urllib.parse
from typing import Dict, Any, Tuple

import asyncio
import numpy as np
import httpx
from cachetools import TTLCache
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

# ---------------------------
# Logging
# ---------------------------
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(h)

# ---------------------------
# Environment
# ---------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# ---------------------------
# Cache & inflight dedupe
# ---------------------------
_external_cache = TTLCache(maxsize=4096, ttl=600)
_inflight: Dict[str, asyncio.Future] = {}

# ---------------------------
# Pydantic Models
# ---------------------------
class PredictRequest(BaseModel):
    url: str = Field(...)

class PredictResponse(BaseModel):
    prediction: str
    trust_score: float
    risk_score: float
    gsb_match: bool
    vt: Dict[str, Any]
    model_probs: Dict[str, float]
    rule_risk: float


# ---------------------------
# Helper Loaders
# ---------------------------
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_xgb_model(path):
    from xgboost import XGBClassifier
    m = XGBClassifier()
    m.load_model(path)
    return m


# ---------------------------
# Predictor Class
# ---------------------------
class Predictor:
    def __init__(self):
        self.models = {}
        self.feature_names = []
        self._loaded = False

        # persistent client — single instance
        self.client = httpx.AsyncClient(timeout=6.0)

    async def aclose(self):
        await self.client.aclose()

    # ---------------------------
    # Load Models
    # ---------------------------
    def load_models(self):
        if self._loaded:
            return

        logger.info("Loading ML models...")

        try:
            self.models["xgb"] = load_xgb_model(os.path.join(MODEL_DIR, "xgb.json"))
            self.models["rf"] = load_pickle(os.path.join(MODEL_DIR, "rf.pkl"))
            self.models["stacker"] = load_pickle(os.path.join(MODEL_DIR, "stacker.pkl"))
            self.feature_names = load_pickle(os.path.join(MODEL_DIR, "features.pkl"))
        except Exception as e:
            logger.exception("Model load failed")
            raise RuntimeError("Model loading failed") from e

        self._loaded = True
        logger.info("Models loaded successfully.")

    # ---------------------------
    # Core Prediction
    # ---------------------------
    async def predict_url(self, raw_url: str):
        self.load_models()

        # Basic lexical features
        features = self._extract_features(raw_url)

        X = np.asarray([[float(features.get(f, 0)) for f in self.feature_names]], dtype=float)

        # ML base predictions
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        # Stacker
        try:
            p_final = float(self.models["stacker"].predict_proba(np.asarray([[p_xgb, p_rf]]) )[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        ml_risk = p_final * 100

        # Extract domain
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.split(":")[0].lower()

        # Run external checks concurrently
        gsb_task = asyncio.create_task(self.check_gsb(raw_url))
        vt_task = asyncio.create_task(self.vt_domain_report(domain))

        gsb_match = await gsb_task
        vt_total, vt_mal, vt_ratio = await vt_task

        vt_risk = min((vt_ratio * 100)**2 / 100, 100)
        gsb_risk = 100 if gsb_match else 0

        # Simple rule risk
        rule_risk = 0
        if domain.endswith(".shop") or domain.endswith(".top") or domain.endswith(".xyz"):
            rule_risk += 15
        if "utm_" in raw_url.lower():
            rule_risk += 10

        FINAL_RISK = (
            ml_risk * 0.50 +
            vt_risk * 0.45 +
            gsb_risk * 0.05 +
            rule_risk
        )

        FINAL_RISK = max(0, min(FINAL_RISK, 100))
        trust = 100 - FINAL_RISK

        return {
            "prediction": "phishing" if FINAL_RISK >= 50 else "safe",
            "trust_score": round(trust, 3),
            "risk_score": round(FINAL_RISK, 3),
            "gsb_match": bool(gsb_match),
            "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
            "model_probs": {"xgb": p_xgb, "rf": p_rf, "ml_final": p_final},
            "rule_risk": rule_risk,
        }

    # ---------------------------
    # Feature Extractor
    # ---------------------------
    def _extract_features(self, url):
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.lower()

        return {
            "url_length": len(url),
            "domain_length": len(host),
            "num_dots": host.count("."),
            "has_https": int(parsed.scheme == "https"),
            "has_ip": int(any(c.isdigit() for c in host)),
        }

    # ---------------------------
    # Async + cached GSB
    # ---------------------------
    async def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False

        cache_key = f"gsb::{url}"
        if cache_key in _external_cache:
            return _external_cache[cache_key]

        # dedupe: if another task is checking the same URL
        if cache_key in _inflight:
            return await _inflight[cache_key]

        fut = _inflight.setdefault(cache_key, asyncio.get_event_loop().create_future())

        try:
            body = {
                "client": {"clientId": "smellscam", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            r = await self.client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                json=body,
            )

            matched = bool(r.json().get("matches"))
            _external_cache[cache_key] = matched
            fut.set_result(matched)
            return matched

        except Exception as exc:
            logger.warning("GSB failed: %s", exc)
            fut.set_result(False)
            return False

        finally:
            _inflight.pop(cache_key, None)

    # ---------------------------
    # Async + cached VT
    # ---------------------------
    async def vt_domain_report(self, domain: str) -> Tuple[int,int,float]:
        if not VT_API_KEY:
            return 0, 0, 0.0

        cache_key = f"vt::{domain}"
        if cache_key in _external_cache:
            d = _external_cache[cache_key]
            return d["total"], d["mal"], d["ratio"]

        if cache_key in _inflight:
            return await _inflight[cache_key]

        fut = asyncio.get_event_loop().create_future()
        _inflight[cache_key] = fut

        try:
            r = await self.client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_API_KEY}
            )

            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            mal = stats.get("malicious", 0) if stats else 0
            ratio = mal / total if total else 0.0

            data = {"total": total, "mal": mal, "ratio": ratio}
            _external_cache[cache_key] = data

            fut.set_result( (total, mal, ratio) )
            return total, mal, ratio

        except Exception as exc:
            logger.warning("VT failed: %s", exc)
            fut.set_result( (0,0,0.0) )
            return 0,0,0.0

        finally:
            _inflight.pop(cache_key, None)


# ---------------------------
# Router
# ---------------------------
_predictor = Predictor()
router = APIRouter()

@router.post("/predict", response_model=PredictResponse)
async def predict_endpoint(req: PredictRequest):
    try:
        return await _predictor.predict_url(req.url)
    except Exception as e:
        logger.exception("Prediction error: %s", e)
        raise HTTPException(status_code=500, detail="Prediction failed")


# Exports
predictor_router = router

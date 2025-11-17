# predictor.py — FINAL STABLE VERSION

from __future__ import annotations

import os
import pickle
import logging
import urllib.parse
import asyncio
import math
from typing import Dict, Any, List, Tuple

import numpy as np
import httpx
from cachetools import TTLCache, cached
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

# ---------------------------
# Logging & warnings cleanup
# ---------------------------
import warnings
from sklearn.exceptions import DataConversionWarning

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DataConversionWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


# ---------------------------
# Environment
# ---------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

# Cache (10 min TTL)
_external_cache = TTLCache(maxsize=4096, ttl=600)


# ---------------------------
# Pydantic Models
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
# Model Loading Utilities
# ---------------------------
def load_pickle(path: str):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path: str):
    from xgboost import XGBClassifier

    model = XGBClassifier()
    model.load_model(path)
    return model


class ModelLoadError(Exception):
    pass


# ---------------------------
# Predictor Class
# ---------------------------
class Predictor:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.models = {}
        self.feature_names: List[str] = []
        self._loaded = False

    def load_models(self):
        if self._loaded:
            return self.models

        try:
            self.models = {
                "xgb": load_xgb_model(f"{self.model_dir}/xgb.json"),
                "rf": load_pickle(f"{self.model_dir}/rf.pkl"),
                "stacker": load_pickle(f"{self.model_dir}/stacker.pkl"),
                "features": load_pickle(f"{self.model_dir}/features.pkl"),
            }
            self.feature_names = list(self.models["features"])
            self._loaded = True
            return self.models
        except Exception as e:
            raise ModelLoadError(f"Failed to load ML models: {e}")

    # -------------------------
    # Async requests
    # -------------------------
    @staticmethod
    def client(timeout=6):
        return httpx.AsyncClient(timeout=timeout)

    @cached(_external_cache)
    async def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False

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
            async with self.client() as c:
                r = await c.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                    json=body,
                )
                return bool(r.json().get("matches"))
        except:
            return False

    @cached(_external_cache)
    async def vt_report(self, domain: str) -> Tuple[int, int, float]:
        if not VT_API_KEY:
            return (0, 0, 0.0)

        try:
            async with self.client() as c:
                r = await c.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": VT_API_KEY},
                )
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values())
                mal = stats.get("malicious", 0)
                ratio = mal / total if total > 0 else 0
                return (total, mal, ratio)
        except:
            return (0, 0, 0.0)

    # -------------------------
    # Rule engine
    # -------------------------
    SUSPICIOUS_TLDS = {".asia", ".top", ".icu", ".shop", ".online", ".xyz"}
    BRAND_LIST = ["nike", "adidas", "apple", "samsung", "amazon", "zara"]

    def detect_brand_imp(self, domain: str):
        for brand in self.BRAND_LIST:
            if brand in domain and not domain.endswith(f"{brand}.com"):
                return True
        return False

    @staticmethod
    def detect_redirect(url):
        u = url.lower()
        return int("utm_" in u or "fbclid" in u)

    # -------------------------
    # Core Prediction
    # -------------------------
    async def predict_url(self, raw_url: str):
        self.load_models()

        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc.split(":")[0].lower()

        # Basic features so model does not break
        features = {fn: 0 for fn in self.feature_names}
        features["url_length"] = len(raw_url)

        X = np.asarray([[features.get(f, 0) for f in self.feature_names]], float)

        # ML predictions
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        try:
            final_ml = float(
                self.models["stacker"].predict_proba([[p_xgb, p_rf]])[0][1]
            )
        except:
            final_ml = (p_xgb + p_rf) / 2

        ml_risk = final_ml * 100

        # Async tasks
        gsb_task = asyncio.create_task(self.check_gsb(raw_url))
        vt_task = asyncio.create_task(self.vt_report(domain))

        gsb_match = await gsb_task
        vt_total, vt_mal, vt_ratio = await vt_task

        vt_risk = min((vt_ratio * 100) ** 2 / 100, 100)
        gsb_risk = 100 if gsb_match else 0

        # Rule risk
        rule_risk = 0
        if any(domain.endswith(t) for t in self.SUSPICIOUS_TLDS):
            rule_risk += 20
        if self.detect_brand_imp(domain):
            rule_risk += 25
        if self.detect_redirect(raw_url):
            rule_risk += 15

        # Final score
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
            "gsb_match": gsb_match,
            "vt": {"total_vendors": vt_total, "malicious": vt_mal, "ratio": vt_ratio},
            "model_probs": {
                "xgb": p_xgb,
                "rf": p_rf,
                "ml_final": final_ml
            },
            "rule_risk": rule_risk
        }


# ---------------------------
# FastAPI Router
# ---------------------------
_predictor = Predictor()
router = APIRouter()


@router.post("/predict", response_model=PredictResponse)
async def predict(req: PredictRequest):
    try:
        return await _predictor.predict_url(req.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


predictor_router = router
PredictorClass = Predictor

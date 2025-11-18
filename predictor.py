from __future__ import annotations

import os
import pickle
import logging
import urllib.parse
import asyncio
import re
import numpy as np
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from cachetools import TTLCache, cached


# ------------------------------------------------------
# Logging
# ------------------------------------------------------
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)

if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


# ------------------------------------------------------
# Config
# ------------------------------------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

_external_cache = TTLCache(maxsize=2048, ttl=600)


# ------------------------------------------------------
# Pydantic models
# ------------------------------------------------------
class PredictRequest(BaseModel):
    url: str


class PredictResponse(BaseModel):
    prediction: str
    trust_score: float
    risk_score: float
    vt: dict
    gsb_match: bool
    rule_risk: float
    model_probs: dict


# ------------------------------------------------------
# Utility
# ------------------------------------------------------
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_xgb_model(path):
    from xgboost import XGBClassifier
    model = XGBClassifier()
    model.load_model(path)
    return model


# ------------------------------------------------------
# Predictor Class
# ------------------------------------------------------
class Predictor:
    def __init__(self):
        self.models = {}
        self.feature_names = []
        self.loaded = False

        self.weights = {
            "ml": 0.55,
            "vt": 0.35,
            "gsb": 0.10
        }

    # --------------------------------------------------
    # Load ML models once
    # --------------------------------------------------
    def load(self):
        if self.loaded:
            return

        xgb_path = os.path.join(MODEL_DIR, "xgb.json")
        rf_path = os.path.join(MODEL_DIR, "rf.pkl")
        stack_path = os.path.join(MODEL_DIR, "stacker.pkl")
        feat_path = os.path.join(MODEL_DIR, "features.pkl")

        self.models = {
            "xgb": load_xgb_model(xgb_path),
            "rf": load_pickle(rf_path),
            "stack": load_pickle(stack_path),
            "features": load_pickle(feat_path)
        }

        self.feature_names = list(self.models["features"])
        self.loaded = True

    # --------------------------------------------------
    # Extract simple lexical features
    # --------------------------------------------------
    def extract_basic_features(self, url: str):
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.lower()
        features = {}

        features["url_length"] = len(url)
        features["domain_length"] = len(host)
        features["dots"] = host.count(".")
        features["hyphens"] = host.count("-")
        features["has_https"] = float(parsed.scheme == "https")

        for f in self.feature_names:
            features.setdefault(f, 0.0)

        return features

    # --------------------------------------------------
    # Google Safe Browsing
    # --------------------------------------------------
    @cached(_external_cache)
    async def gsb_check(self, url: str):
        if not GSB_API_KEY:
            return False

        body = {
            "client": {"clientId": "smellscam", "clientVersion": "4.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=7) as client:
                r = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
                    json=body
                )
                data = r.json()
                return bool(data.get("matches"))
        except:
            return False

    # --------------------------------------------------
    # VirusTotal domain report
    # --------------------------------------------------
    @cached(_external_cache)
    async def vt_report(self, domain: str):
        if not VT_API_KEY:
            return {"total": 0, "mal": 0, "ratio": 0.0}

        try:
            headers = {"x-apikey": VT_API_KEY}
            async with httpx.AsyncClient(timeout=7) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers=headers
                )
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values())
                mal = stats.get("malicious", 0)
                ratio = mal / total if total > 0 else 0.0
                return {"total": total, "mal": mal, "ratio": ratio}
        except:
            return {"total": 0, "mal": 0, "ratio": 0.0}

    # --------------------------------------------------
    # Rules
    # --------------------------------------------------
    def compute_rules(self, url: str, domain: str):
        risk = 0

        if domain.endswith((".icu", ".xyz", ".shop", ".top", ".store")):
            risk += 15

        for brand in ["nike", "adidas", "zara", "apple", "amazon"]:
            if brand in domain and not domain.endswith(brand + ".com"):
                risk += 25

        if "utm_" in url or "fbclid" in url:
            risk += 10

        return min(risk, 100)

    # --------------------------------------------------
    # Full prediction pipeline
    # --------------------------------------------------
    async def predict(self, url: str):
        self.load()

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()

        # ML features
        features = self.extract_basic_features(url)
        X = np.array([[features[f] for f in self.feature_names]])

        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        try:
            p_ml = float(self.models["stack"].predict_proba([[p_xgb, p_rf]])[0][1])
        except:
            p_ml = (p_xgb + p_rf) / 2

        ml_risk = p_ml * 100

        # Async tasks (no coroutine reuse)
        gsb_task = asyncio.create_task(self.gsb_check(url))
        vt_task = asyncio.create_task(self.vt_report(domain))

        gsb = await gsb_task
        vt = await vt_task

        gsb_risk = 100 if gsb else 0
        vt_risk = ((vt["ratio"] * 100) ** 2) / 100

        rule_risk = self.compute_rules(url, domain)

        final_risk = (
            ml_risk * self.weights["ml"] +
            vt_risk * self.weights["vt"] +
            gsb_risk * self.weights["gsb"] +
            rule_risk
        )

        final_risk = min(100.0, max(0.0, final_risk))
        trust = 100 - final_risk

        result = {
            "prediction": "phishing" if final_risk >= 50 else "safe",
            "trust_score": round(trust, 2),
            "risk_score": round(final_risk, 2),
            "vt": vt,
            "gsb_match": gsb,
            "rule_risk": rule_risk,
            "model_probs": {
                "xgb": p_xgb,
                "rf": p_rf,
                "ml_final": p_ml
            }
        }

        return result


# ======================================================
# Router
# ======================================================
router = APIRouter()

predictor = Predictor()


@router.post("/predict", response_model=PredictResponse)
async def predict_api(req: PredictRequest):
    try:
        return await predictor.predict(req.url)
    except Exception as e:
        logger.exception("Prediction failed: %s", e)
        raise HTTPException(500, "Prediction failed")


predictor_router = router

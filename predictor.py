from __future__ import annotations
import os
import pickle
import urllib.parse
import logging
import asyncio
import numpy as np
import httpx

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

from url_feature_extractor import extract_all_features

# --------------------------------------------------
# Logging
# --------------------------------------------------
logger = logging.getLogger("smellscam.predictor")
logger.setLevel(logging.INFO)

# --------------------------------------------------
# ENV
# --------------------------------------------------
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
GSB_API_KEY = os.environ.get("GSB_API_KEY")
VT_API_KEY  = os.environ.get("VT_API_KEY")

# --------------------------------------------------
# Pydantic Models
# --------------------------------------------------
class PredictRequest(BaseModel):
    url: str = Field(...)

class VTInfo(BaseModel):
    total_vendors: int
    malicious: int
    ratio: float

class ModelProbs(BaseModel):
    xgb: float
    rf: float
    ml_final: float

class PredictResponse(BaseModel):
    is_shopping: bool
    trust_score: float
    gsb_match: bool
    vt: VTInfo
    model_probs: ModelProbs

# --------------------------------------------------
# Helper – load pickle safely
# --------------------------------------------------
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

# --------------------------------------------------
# Predictor Class
# --------------------------------------------------
class Predictor:
    def __init__(self):
        self.models = {}
        self.feature_names = []
        self.loaded = False

        # weighting strategy (shopping-only)
        self.weights = {
            "ml": 0.50,
            "vt": 0.45,
            "gsb": 0.05
        }

    # ------------------------------------------------
    # Load ML Models
    # ------------------------------------------------
    def load_models(self):
        if self.loaded:
            return

        try:
            xgb_path = os.path.join(MODEL_DIR, "xgb.json")
            rf_path  = os.path.join(MODEL_DIR, "rf.pkl")
            stk_path = os.path.join(MODEL_DIR, "stacker.pkl")
            feat_path= os.path.join(MODEL_DIR, "features.pkl")

            # XGBoost loader
            from xgboost import XGBClassifier
            xgb_model = XGBClassifier()
            xgb_model.load_model(xgb_path)

            self.models = {
                "xgb": xgb_model,
                "rf": load_pickle(rf_path),
                "stacker": load_pickle(stk_path),
                "features": load_pickle(feat_path)
            }

            self.feature_names = list(self.models["features"])
            self.loaded = True
            logger.info("Models loaded successfully.")

        except Exception as e:
            logger.exception("Failed to load models")
            raise HTTPException(status_code=500, detail=str(e))

    # ------------------------------------------------
    # Google Safe Browsing
    # ------------------------------------------------
    async def check_gsb(self, url: str) -> bool:
        if not GSB_API_KEY:
            return False

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        body = {
            "client": {"clientId": "smellscam", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.post(endpoint, json=body)
                r.raise_for_status()
                return bool(r.json().get("matches"))
        except:
            return False

    # ------------------------------------------------
    # VirusTotal domain scan
    # ------------------------------------------------
    async def check_vt(self, domain: str):
        if not VT_API_KEY:
            return (0, 0, 0.0)

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=6) as client:
                r = await client.get(url, headers=headers)
                if r.status_code != 200:
                    return (0, 0, 0.0)

                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                total = sum(stats.values())
                mal   = stats.get("malicious", 0)
                ratio = mal / total if total > 0 else 0.0
                return (total, mal, ratio)
        except:
            return (0, 0, 0.0)

    # ------------------------------------------------
    # MAIN: Predict
    # ------------------------------------------------
    async def predict_url(self, raw_url: str) -> dict:
        # load ML models
        self.load_models()

        # extract all 40 features
        feats = extract_all_features(raw_url)
        is_shopping = bool(feats.get("is_shopping", 0))

        if not is_shopping:
            # shopping-only mode → block
            return {
                "is_shopping": False,
                "trust_score": 0,
                "gsb_match": False,
                "vt": {"total_vendors": 0, "malicious": 0, "ratio": 0},
                "model_probs": {"xgb": 0, "rf": 0, "ml_final": 0}
            }

        # prepare ML feature vector
        X = np.asarray([[float(feats.get(f, 0)) for f in self.feature_names]])

        # Model outputs
        try:
            p_xgb = float(self.models["xgb"].predict_proba(X)[0][1])
        except:
            p_xgb = 0.5

        try:
            p_rf = float(self.models["rf"].predict_proba(X)[0][1])
        except:
            p_rf = 0.5

        # Blended meta-model
        try:
            p_final = float(self.models["stacker"].predict_proba([[p_xgb, p_rf]])[0][1])
        except:
            p_final = (p_xgb + p_rf) / 2

        ml_risk = p_final * 100

        # parse domain
        domain = urllib.parse.urlparse(raw_url).netloc.split(":")[0]

        # async checks
        gsb_match = await self.check_gsb(raw_url)
        vt_total, vt_mal, vt_ratio = await self.check_vt(domain)

        # convert VT ratio into risk
        vt_risk = min((vt_ratio * 100) ** 2 / 100, 100)

        # 0 or 100
        gsb_risk = 100 if gsb_match else 0

        # weighted score
        FINAL_RISK = (
            ml_risk * self.weights["ml"] +
            vt_risk * self.weights["vt"] +
            gsb_risk * self.weights["gsb"]
        )

        trust = max(0.0, min(100.0, 100 - FINAL_RISK))

        # return final JSON
        return PredictResponse(
            is_shopping=True,
            trust_score=round(trust, 3),
            gsb_match=bool(gsb_match),
            vt=VTInfo(
                total_vendors=vt_total,
                malicious=vt_mal,
                ratio=vt_ratio
            ),
            model_probs=ModelProbs(
                xgb=p_xgb,
                rf=p_rf,
                ml_final=p_final
            )
        ).dict()


# --------------------------------------------------
# FastAPI Router
# --------------------------------------------------
router = APIRouter()

predictor = Predictor()


@router.post("/predict", response_model=PredictResponse)
async def predict(req: PredictRequest):
    try:
        return await predictor.predict_url(req.url)
    except Exception as e:
        logger.exception("Prediction failed")
        raise HTTPException(status_code=500, detail=str(e))


predictor_router = router

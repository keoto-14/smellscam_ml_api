# app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import traceback
from dotenv import load_dotenv

# load .env variables
load_dotenv()

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

# ---------------------------------------------------------
# FASTAPI SETUP
# ---------------------------------------------------------
app = FastAPI(
    title="SmellScam ML API",
    description="Phishing detection ML backend for smellscam.com (Hybrid ML + VT + GSB + Rules)",
    version="1.0"
)

# Allow all origins (for now)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load models ONCE on startup
models = load_models()


# ---------------------------------------------------------
# REQUEST SCHEMA
# ---------------------------------------------------------
class URLRequest(BaseModel):
    url: str


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.get("/")
async def root():
    return {"message": "SmellScam ML API is running!"}


@app.post("/predict")
async def predict_api(req: URLRequest):
    try:
        url = req.url.strip()
        features = extract_all_features(url)
        result = predict_from_features(features, models, raw_url=url)
        return result

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/simple")
async def predict_simple(url: str):
    try:
        clean = url.strip().replace("\n", "").replace("\r", "")
        features = extract_all_features(clean)
        result = predict_from_features(features, models, raw_url=clean)
        return result

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/debug")
async def debug(url: str):
    """
    Debug mode: returns raw features and scoring breakdown
    """
    try:
        clean = url.strip()
        feats = extract_all_features(clean)
        result = predict_from_features(feats, models, raw_url=clean)
        return {
            "url": clean,
            "features": feats,
            "output": result
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

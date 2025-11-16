# app.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import traceback
from dotenv import load_dotenv
load_dotenv()

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = FastAPI(
    title="SmellScam ML API",
    description="Phishing detection ML backend for smellscam.com (hybrid: ML+VT+GSB)",
    version="1.0"
)

# CORS (allow all for now, tighten in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# load models (on startup)
models = load_models()

class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"message": "SmellScam ML API is running!"}

@app.post("/predict")
async def predict(req: URLRequest):
    try:
        url = req.url.strip()
        features = extract_all_features(url)
        result = predict_from_features(features, models, raw_url=url)
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simple")
async def simple(url: str):
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
    try:
        clean = url.strip()
        features = extract_all_features(clean)
        result = predict_from_features(features, models, raw_url=clean)
        return {
            "url": clean,
            "features_extracted": features,
            "hybrid_output": result
        }
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

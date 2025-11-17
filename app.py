# app.py (unchanged from previous message)
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
    description="Phishing detection backend (Hybrid ML + Rules)",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models = load_models()

class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"message": "SmellScam ML API is running!"}

@app.post("/predict")
async def predict_api(req: URLRequest):
    try:
        url = req.url.strip()
        feats = extract_all_features(url)
        return predict_from_features(feats, models, raw_url=url)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simple")
async def simple(url: str):
    try:
        clean = url.strip()
        feats = extract_all_features(clean)
        return predict_from_features(feats, models, raw_url=clean)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/debug")
async def debug(url: str):
    url = url.strip()
    feats = extract_all_features(url)
    result = predict_from_features(feats, models, raw_url=url)
    return {"url": url, "features": feats, "output": result}

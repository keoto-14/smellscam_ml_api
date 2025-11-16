# app.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import traceback

from url_feature_extractor import extract_all_features
from predictor import load_models, predict_from_features

app = FastAPI(
    title="SmellScam ML API",
    description="Phishing detection ML backend for smellscam.com",
    version="1.0"
)

# Enable CORS (important for smellscam.com frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # later: ["https://smellscam.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load ML models
models = load_models()

class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"message": "SmellScam ML API is running!"}

# ------------------------------------------------------------
# JSON INPUT ENDPOINT
# ------------------------------------------------------------
@app.post("/predict")
async def predict(req: URLRequest):
    try:
        url = req.url.strip()
        features = extract_all_features(url)
        result = predict_from_features(features, models)
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------
# SIMPLE RAW STRING ENDPOINT  (for smellscam.com frontend)
# ------------------------------------------------------------
@app.post("/simple")
async def simple(url: str):
    try:
        clean = url.strip().replace("\n", "").replace("\r", "")
        features = extract_all_features(clean)
        result = predict_from_features(features, models)
        return result
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

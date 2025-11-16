# app.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import traceback

from predictor import load_models, predict_from_features
from url_feature_extractor import extract_all_features

app = FastAPI(
    title="SmellScam ML API",
    description="Phishing detection ML backend for smellscam.com",
    version="1.0"
)

# Enable CORS so smellscam.com frontend can call API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later replace with ["https://smellscam.com"]
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
# JSON INPUT ENDPOINT  (POST { "url": "..." })
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
# RAW URL ENDPOINT (POST text/plain)
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

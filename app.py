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

# Enable CORS (you can restrict later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # update later for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load models on startup
models = load_models()

class URLRequest(BaseModel):
    url: str


@app.get("/")
async def root():
    return {"message": "SmellScam ML API is running!"}


# ------------------------------------------------------------
# 1) JSON INPUT ENDPOINT  (POST { "url": "https://..." })
# ------------------------------------------------------------
@app.post("/predict")
async def predict(req: URLRequest):
    try:
        url = req.url.strip()

        # Extract full feature set
        features = extract_all_features(url)

        # Hybrid prediction (ML + VT + GSB)
        result = predict_from_features(features, models, raw_url=url)

        return result

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------
# 2) RAW STRING ENDPOINT (POST text/plain)
# ------------------------------------------------------------
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


# ------------------------------------------------------------
# 3) DEBUG ENDPOINT (GET /debug?url=https://...)
# ------------------------------------------------------------
@app.get("/debug")
async def debug(url: str):
    """
    Debug endpoint: returns ALL extracted features,
    ML model probabilities, VT/GSB results,
    hybrid output, final trust/risk score.
    """
    try:
        clean = url.strip()

        # Extract full 40+ features
        features = extract_all_features(clean)

        # Run hybrid prediction
        result = predict_from_features(features, models, raw_url=clean)

        # Debug output
        return {
            "url": clean,
            "features_extracted": features,
            "prediction": result.get("prediction"),
            "trust_score": result.get("trust_score"),
            "risk_score": result.get("risk_score"),
            "vt": result.get("vt"),
            "gsb_match": result.get("gsb_match"),
            "model_probs": result.get("model_probs"),
            "hybrid_output": result
        }

    except Exception as e:
        traceback.print_exc()
        return {"error": str(e)}

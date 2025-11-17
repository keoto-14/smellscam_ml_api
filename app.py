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
    description="Hybrid ML + VT + GSB with Online Shopping Filtering",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

models = load_models()


class URLRequest(BaseModel):
    url: str


@app.get("/")
async def root():
    return {"message": "SmellScam ML API Running"}


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

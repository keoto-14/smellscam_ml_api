from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

# Predictor router (new API)
from predictor import predictor_router, _predictor, PredictRequest, PredictResponse

app = FastAPI(
    title="SmellScam ML API",
    description="Hybrid ML + VirusTotal + Google Safe Browsing + Heuristics",
    version="3.0"
)

# ------------------------------------------------------
# CORS
# ------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------
# Root endpoint
# ------------------------------------------------------
@app.get("/")
async def root():
    return {"message": "SmellScam ML API Running", "version": "3.0"}


# ------------------------------------------------------
# NEW ENDPOINT
# /api/v1/predict
# ------------------------------------------------------
app.include_router(predictor_router, prefix="/api/v1")


# ------------------------------------------------------
# LEGACY ENDPOINT (for PHP frontend)
# POST /predict
# ------------------------------------------------------
@app.post("/predict", response_model=PredictResponse)
async def legacy_predict(req: PredictRequest):
    """
    Legacy endpoint so old PHP files work without updates.
    Fully identical behavior to /api/v1/predict.
    """
    return await _predictor.predict_url(req.url)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from predictor import predictor_router, Predictor
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="SmellScam ML API",
    description="Hybrid ML + VirusTotal + GSB + Heuristics",
    version="4.0"
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
# Root
# ------------------------------------------------------
@app.get("/")
async def root():
    return {
        "message": "SmellScam ML API Running",
        "version": "4.0",
        "status": "ok"
    }

# ------------------------------------------------------
# Mount predictor router
# ------------------------------------------------------
app.include_router(predictor_router, prefix="/api/v1")

# ------------------------------------------------------
# Backwards-compatible legacy endpoint
# POST /predict  → same as /api/v1/predict
# ------------------------------------------------------
predictor = Predictor()

@app.post("/predict")
async def legacy_predict(req: dict):
    if "url" not in req:
        raise HTTPException(400, "Missing field: url")

    return await predictor.predict(req["url"])

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables (.env)
load_dotenv()

# Import the new predictor router (from canvas version)
from predictor import predictor_router

app = FastAPI(
    title="SmellScam ML API",
    description="Hybrid ML + VirusTotal + Google Safe Browsing + Heuristics",
    version="3.0"
)

# ------------------------------------------------------
# CORS — allow access from any frontend
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
# Mount predictor router
# ------------------------------------------------------
# POST /api/v1/predict  → full ML + VT + GSB + rules
app.include_router(predictor_router, prefix="/api/v1")


# app.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from predictor import  Predictor

load_dotenv()

app = FastAPI(
    title="SmellScam ML API",
    description="Hybrid ML + VirusTotal + Google Safe Browsing + Heuristics (Enterprise)",
    version="5.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# mount the main router
app.include_router(predictor_router, prefix="/api/v1")

# single Predictor instance for legacy endpoint
_predictor = Predictor()

@app.get("/")
async def root():
    return {"message": "SmellScam ML API Running", "version": "5.0"}

# Backwards-compatible legacy endpoint (accepts JSON body {"url": "..."} )
@app.post("/predict")
async def legacy_predict(req: Request):
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    url = body.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' field")
    return await _predictor.predict_url(url)

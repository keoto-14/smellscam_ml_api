from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from predictor import Predictor

app = FastAPI(
    title="SmellScam ML API",
    version="3.0",
    description="Hybrid ML + VirusTotal + GSB trust-score engine"
)

# Load predictor once on startup
_predictor = Predictor()


class URLRequest(BaseModel):
    url: str


@app.get("/")
def root():
    return {"status": "ok", "message": "SmellScam ML API running"}


@app.post("/api/v1/predict")
async def predict_url(req: URLRequest):
    url = req.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        result = await _predictor.predict_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

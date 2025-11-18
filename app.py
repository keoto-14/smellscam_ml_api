from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from predictor import predictor_router, Predictor

app = FastAPI(
    title="SmellScam ML API",
    version="3.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "SmellScam ML API Running", "version": "3.1"}

# Main ML API
app.include_router(predictor_router, prefix="/api/v1")

# Legacy PHP fix — accepts form POST without JSON (fixes 415 fully)
@app.post("/legacy_predict")
async def legacy_predict(url: str = Form(...)):
    predictor = Predictor()
    return await predictor.predict_url(url)

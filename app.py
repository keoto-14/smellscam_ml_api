from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from predictor_v3 import predictor_router

app = FastAPI(
    title="SmellScam ML API",
    description="Hybrid ML + VT + GSB with strict shopping-only filtering",
    version="3.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "SmellScam ML API running", "version": "3.0"}

# mount router
app.include_router(predictor_router, prefix="/api/v1")

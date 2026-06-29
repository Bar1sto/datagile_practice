from fastapi import FastAPI
from app.api.cve_router import router as cve_router

app = FastAPI(
    title="NVD",
    version="1.0",
)

app.include_router(cve_router)

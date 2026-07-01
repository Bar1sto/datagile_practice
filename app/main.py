from fastapi import FastAPI
from app.api.cve import router as cve
from app.api.stats import router as state
from app.api.sync import router as sync

app = FastAPI(
    title="NVD",
    version="1.0",
)

app.include_router(cve)
app.include_router(state)
app.include_router(sync)

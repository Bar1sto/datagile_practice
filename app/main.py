from fastapi import FastAPI, HTTPException
from app.api.cve import router as cve
from app.api.stats import router as state
from app.api.sync import router as sync
from app.api.exceptions import http_exception_handler
from app.web.router import router as ui
from fastapi.staticfiles import StaticFiles
from app.core.logging import configure_logging


configure_logging()
app = FastAPI(
    title="NVD",
    version="1.0",
)

app.add_exception_handler(HTTPException, http_exception_handler)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(cve)
app.include_router(state)
app.include_router(sync)
app.include_router(ui)

import contextlib
from fastapi import FastAPI
from app.api.cve import router as cve
from app.api.stats import router as state
from app.api.sync import router as sync
from app.core.config import Settings
from app.db.database import SessionLocal
from app.scheduler.nvd_sync import NvdSyncScheduler


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings()
    scheduler = NvdSyncScheduler(settings=settings, session_factory=SessionLocal)
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(
    title="NVD",
    version="1.0",
    lifespan=lifespan,
)


app.include_router(cve)
app.include_router(state)
app.include_router(sync)

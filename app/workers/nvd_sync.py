import time
from app.core.config import Settings
from app.schedulers.nvd_sync import NvdSyncScheduler
from app.core.logging import configure_logging
from app.db.database import AsyncSessionLocal


configure_logging()


def main() -> None:
    settings = Settings()
    scheduler = NvdSyncScheduler(
        settings=settings,
        session_factory=AsyncSessionLocal,
    )
    scheduler.start()
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        scheduler.shutdown()


if __name__ == "__main__":
    main()

from app.core.config import Settings
from app.clients.nvd import NvdClient
from app.repositories.sync import create_sync_run, mark_sync_run_failed
from app.services.nvd_sync import NvdSyncService
from apscheduler.schedulers.background import BackgroundScheduler
from collections.abc import Callable
from sqlalchemy.orm import Session


class NvdSyncScheduler:
    def __init__(
        self,
        settings: Settings,
        session_factory: Callable[[], Session],
    ):
        self.settings = settings
        self.session_factory = session_factory
        self.scheduler: BackgroundScheduler | None = None

    def run_nvd_sync(self) -> None:
        client = NvdClient(self.settings.nvd_api_key, self.settings.nvd_base_url)
        service = NvdSyncService(client)
        db = self.session_factory()
        try:
            result = service.sync_recent(db=db, days=1)
            db.commit()
            print(result)
        except Exception:
            db.rollback()
            failed_sync_run = create_sync_run(db=db, source="NVD")
            mark_sync_run_failed(failed_sync_run)
            db.commit()
            raise
        finally:
            db.close()

    def start(self) -> None:
        self.scheduler = BackgroundScheduler()
        self.scheduler.add_job(
            self.run_nvd_sync,
            trigger="interval",
            id="nvd_sync",
            hours=24,
            replace_existing=True,
        )
        self.scheduler.start()

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.shutdown()

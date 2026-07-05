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
        client = NvdClient(
            api_key=self.settings.nvd_api_key,
            base_url=self.settings.nvd_base_url,
            timeout_seconds=self.settings.nvd_timeout_seconds,
            max_retries=self.settings.nvd_max_retries,
            retry_sleep_seconds=self.settings.nvd_retry_sleep_seconds,
            results_per_page=self.settings.nvd_results_per_page,
        )
        service = NvdSyncService(
            client=client,
            initial_load_months=self.settings.nvd_initial_load_months,
            chunk_days=self.settings.nvd_chunk_days,
        )
        db = self.session_factory()
        try:
            result = service.sync_recent(db=db, days=self.settings.nvd_recent_sync_days)
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
            hours=self.settings.nvd_scheduler_interval_hours,
            replace_existing=True,
        )
        self.scheduler.start()

    def shutdown(self) -> None:
        if self.scheduler:
            self.scheduler.shutdown()

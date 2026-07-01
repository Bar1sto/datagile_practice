from app.core.config import Settings
from app.clients.nvd import NvdClient
from app.repositories.sync import create_sync_run, mark_sync_run_failed
from app.services.nvd_sync import NvdSyncService
from app.db.database import SessionLocal
from datetime import datetime, timedelta, timezone

settings = Settings()
client = NvdClient(settings.nvd_api_key, settings.nvd_base_url)
service = NvdSyncService(client)
end_date = datetime.now(timezone.utc)
start_date = end_date - timedelta(days=1)
db = SessionLocal()
try:
    result = service.sync_period(db=db, start_date=start_date, end_date=end_date)
    db.commit()
    print(result)
except:
    db.rollback()
    failed_sync_run = create_sync_run(db=db, source="NVD")
    mark_sync_run_failed(failed_sync_run)
    db.commit()
    raise
finally:
    db.close()

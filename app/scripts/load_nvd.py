import json
from app.db.database import SessionLocal
from app.normalizers.nvd import normalize_nvd
from app.repositories.cve import upsert_cve
from app.repositories.sync import (
    create_sync_run,
    mark_sync_run_failed,
    mark_sync_run_success,
)


with open("docs/first_requests.json", "r") as file:
    cve_data = json.load(file)

payload = cve_data["vulnerabilities"]
db = SessionLocal()
try:
    sync_run = create_sync_run(db, "NVD")
    added_count = 0
    updated_count = 0
    for item in payload:
        result = upsert_cve(db, normalize_nvd(item))
        if result.created:
            added_count += 1
        else:
            updated_count += 1
    mark_sync_run_success(sync_run, added_count, updated_count)
    db.commit()
    print(f"Loaded {len(payload)} cves")
except Exception:
    db.rollback()
    failed_sync_run = create_sync_run(db, "NVD")
    mark_sync_run_failed(failed_sync_run)
    db.commit()
    raise
finally:
    db.close()

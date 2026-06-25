from app.db.database import SessionLocal
from app.repositories.cve_repo import get_by_cve_id


db = SessionLocal()
try:
    cve = get_by_cve_id(db, "CVE-1999-0095")
    if cve is None:
        print("CVE not found")
    else:
        print(
            cve.cve_id,
            cve.description,
            cve.cvss_base_severity,
            cve.cvss_base_score,
            cve.cvss_vector,
        )
finally:
    db.close()

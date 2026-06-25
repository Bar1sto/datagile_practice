import json
from app.db.database import SessionLocal
from app.normalizers.nvd import normalize_nvd
from app.repositories.cve_repo import upsert_cve


with open("docs/first_requests.json", "r") as file:
    cve_data = json.load(file)

payload = cve_data["vulnerabilities"]
db = SessionLocal()
try:
    for item in payload:
        upsert_cve(db, normalize_nvd(item))
    db.commit()
finally:
    db.close()
    print(f"Loaded {len(payload)} cves")

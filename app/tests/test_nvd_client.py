from app.core.config import Settings
from app.clients.nvd import NvdClient
from datetime import datetime, timezone, timedelta

settings = Settings()
nvd_client = NvdClient(settings.nvd_api_key, settings.nvd_base_url)
end_date = datetime.now(timezone.utc)
start_date = end_date - timedelta(days=7)

result = nvd_client.fetch_vulnerabilities(start_date, end_date)
print(len(result))
if result:
    first = result[0]
    print(first["cve"]["id"])

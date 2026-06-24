import json
from app.normalizers.nvd import normalize_nvd


with open("docs/first_requests.json", encoding="utf-8") as file:
    payload = json.load(file)

item = payload["vulnerabilities"][0]
normalized = normalize_nvd(item)

for key, value in normalized.items():
    print(key, "=", value, "|", type(value))

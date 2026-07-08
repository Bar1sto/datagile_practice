import httpx
from typing import Any


class OsvClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: int,
        # retry_seconds: int,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        # self.retry_seconds = retry_seconds

    async def query_package(
        self, ecosystem: str, package_name: str, version: str
    ) -> list[dict[str, Any]]:
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
        }
        headers = {
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout=self.timeout_seconds)
        ) as client:
            response = await client.post(
                url=f"{self.base_url}/v1/query",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulns", [])
            return vulnerabilities

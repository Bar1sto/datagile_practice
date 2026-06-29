from pydantic import BaseModel


class StatsResponse(BaseModel):
    total_cves: int
    count_severity: dict[str, int]

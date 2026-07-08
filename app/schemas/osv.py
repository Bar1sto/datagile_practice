from pydantic import BaseModel, Field


class OsvPackageSyncRequest(BaseModel):
    ecosystem: str = Field(
        description="OSV package ecosystem, for example PyPI, npm, Maven, Go, or crates.io"
    )
    package_name: str = Field(description="Package name to query in OSV")
    version: str = Field(description="Package version to query in OSV")


class OsvPackageSyncQueryResponse(BaseModel):
    total_count: int = Field(
        description="Total number of vulnerabilities returned by OSV"
    )
    added_count: int = Field(description="Number of CVE records created")
    updated_count: int = Field(description="Number of existing CVE records updated")
    skipped_count: int = Field(
        description="Number of OSV records skipped because they had no CVE alias or were duplicates"
    )

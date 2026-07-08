from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str = Field(description="Error code")
    message: str = Field(description="Error message")


class ErrorResponse(BaseModel):
    error: ErrorBody = Field(description="Unified API error body")

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ResponseMetadata(BaseModel):
    provider: str = Field(
        default="assess-only", description="The data provider or mode used to fulfil the request"
    )
    environment: str = Field(
        default="", description="The D365 F&O environment the response relates to"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of when the response was generated",
    )
    duration_ms: int = Field(
        default=0, description="Time taken to produce the response in milliseconds"
    )
    currency: str = Field(
        default="GBP", description="Currency code relevant to any monetary values in the response"
    )


class ToolResponse(BaseModel):
    result: dict | list | None = Field(
        default=None, description="The primary payload returned by the tool"
    )
    metadata: ResponseMetadata = Field(
        default_factory=ResponseMetadata,
        description="Metadata describing the context and provenance of the response",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings generated during request processing",
    )

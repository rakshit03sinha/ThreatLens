"""ThreatLens Common Schemas and Pagination."""

from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number, 1-indexed")
    page_size: int = Field(default=50, ge=1, le=1000, description="Items per page")


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    message: str
    success: bool = True
    details: Optional[dict] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    app_env: str
    timestamp: str


class ReadinessResponse(BaseModel):
    status: str
    database: str
    ai_provider: str
    version: str
    details: dict

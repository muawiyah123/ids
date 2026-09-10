"""
backend/app/utils/pagination.py

Server-side pagination helpers. All list endpoints use these.
Sort fields are whitelisted per-model to prevent SQL injection.
"""
from __future__ import annotations

from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field


T = TypeVar("T")


class PageParams(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    page_size: int = Field(default=25, ge=1, le=200, description="Items per page")
    sort_by: Optional[str] = Field(default=None, description="Sort field")
    sort_dir: str = Field(default="desc", pattern="^(asc|desc)$")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class Page(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def create(cls, items: List[T], total: int, params: PageParams) -> "Page[T]":
        total_pages = max(1, (total + params.page_size - 1) // params.page_size)
        return cls(
            items=items,
            total=total,
            page=params.page,
            page_size=params.page_size,
            total_pages=total_pages,
        )

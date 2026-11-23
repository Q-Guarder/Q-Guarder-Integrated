from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ── Risk Level 허용값 ──
RISK_LEVEL_CODE = Literal["SECURED", "SUSPICIOUS", "BLOCKED"]


# ── Scan Log Summary (대시보드용) ──
class ScanSummary(BaseModel):
    total_scans: int
    secured_count: int
    suspicious_count: int
    blocked_count: int
    reported_count: int


class ScanLogItem(BaseModel):
    scan_id: str
    url: str
    risk_level: str
    final_score: int  # 0~100 정수
    scanned_at: datetime

    model_config = {"from_attributes": True}


class ScanLogsResponse(BaseModel):
    summary: ScanSummary
    logs: list[ScanLogItem]
    total: int


# ── Bookmarks ──
class BookmarkItem(BaseModel):
    bookmark_id: str
    url: str
    title: str | None = None
    risk_level: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class BookmarkListResponse(BaseModel):
    items: list[BookmarkItem]
    total: int


class BookmarkCreateRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    title: str | None = Field(None, max_length=255)


class BookmarkCreateResponse(BaseModel):
    bookmark_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class BookmarkDeleteResponse(BaseModel):
    message: str = "deleted"


# ── Visit History ──
class VisitCreateRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    risk_level: RISK_LEVEL_CODE


class VisitCreateResponse(BaseModel):
    visit_id: str
    visited_at: datetime

    model_config = {"from_attributes": True}


class VisitItem(BaseModel):
    url: str
    risk_level: str
    visited_at: datetime

    model_config = {"from_attributes": True}


class VisitListResponse(BaseModel):
    items: list[VisitItem]
    total: int

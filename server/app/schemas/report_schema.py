from pydantic import BaseModel, Field


# ── Report Request ──
class ReportRequest(BaseModel):
    scan_log_id: str
    url: str = Field(..., max_length=2048)
    reason: str = Field(..., max_length=1000)


# ── Report Response ──
class ReportResponse(BaseModel):
    report_id: str
    status: str = "queued"
    message: str = "신고가 접수되어 추가 검증을 진행합니다."

    model_config = {"from_attributes": True}

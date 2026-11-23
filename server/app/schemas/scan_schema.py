from datetime import datetime

from pydantic import BaseModel, Field, field_validator


# ── Scan Request ──
class ScanUrlRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    source: str | None = None  # camera, clipboard, manual

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL은 http:// 또는 https://로 시작해야 합니다.")
        return v


# ── Risk Level ──
class RiskLevel(BaseModel):
    code: str        # SECURED | SUSPICIOUS | BLOCKED
    label: str       # 안전 | 주의 | 위험
    description: str  # 사용자 안내 문구


# ── XAI Feature Detail ──
class XaiFeatureDetail(BaseModel):
    title: str        # 한글 피처명
    description: str  # 사용자 설명 문구
    severity: str     # high | medium | low
    contribution: int  # 기여도 (0~100 정수)


# ── Scan Response ──
class ScanUrlResponse(BaseModel):
    scan_id: str
    url: str
    risk_level: RiskLevel
    final_score: int  # 0~100 정수
    vt_total_engines: int | None = None
    vt_detected_engines: int | None = None
    xai_features: list[XaiFeatureDetail]
    scanned_at: datetime

    model_config = {"from_attributes": True}

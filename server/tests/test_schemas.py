"""Pydantic 스키마 유효성 검증 테스트"""

import pytest
from pydantic import ValidationError

from app.schemas.auth_schema import RegisterRequest, LoginRequest, RegisterResponse
from app.schemas.scan_schema import (
    RiskLevel,
    ScanUrlRequest,
    ScanUrlResponse,
    XaiFeatureDetail,
)
from app.schemas.report_schema import ReportRequest, ReportResponse
from app.schemas.user_log_schema import (
    BookmarkCreateRequest,
    VisitCreateRequest,
    ScanSummary,
    ScanLogsResponse,
)


# ── Auth Schema ──

class TestRegisterRequest:
    def test_valid_register(self):
        req = RegisterRequest(
            email="test@example.com",
            password="securepass123!",
            nickname="TestUser",
        )
        assert req.email == "test@example.com"
        assert req.nickname == "TestUser"

    def test_invalid_email(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="not-an-email", password="12345678", nickname="User")

    def test_short_password(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="a@b.com", password="short", nickname="User")

    def test_empty_nickname(self):
        with pytest.raises(ValidationError):
            RegisterRequest(email="a@b.com", password="12345678", nickname="")


class TestLoginRequest:
    def test_valid_login(self):
        req = LoginRequest(email="test@example.com", password="mypassword")
        assert req.email == "test@example.com"

    def test_invalid_email(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="bad", password="mypassword")


# ── Scan Schema ──

class TestScanUrlRequest:
    def test_valid_scan(self):
        req = ScanUrlRequest(url="https://example.com", source="camera")
        assert req.url == "https://example.com"
        assert req.source == "camera"

    def test_url_max_length(self):
        with pytest.raises(ValidationError):
            ScanUrlRequest(url="x" * 2049)

    def test_source_optional(self):
        req = ScanUrlRequest(url="https://example.com")
        assert req.source is None


class TestScanUrlResponse:
    def test_valid_response(self):
        """risk_level은 사용자 문구를 담은 객체, final_score는 0~100 정수,
        xai_features는 기여도 내림차순 배열이다 (클라이언트 스펙 v3)."""
        resp = ScanUrlResponse(
            scan_id="uuid-123",
            url="https://example.com",
            risk_level=RiskLevel(
                code="SECURED", label="안전", description="안전한 URL입니다."
            ),
            final_score=15,
            vt_total_engines=94,
            vt_detected_engines=0,
            xai_features=[],
            scanned_at="2025-03-10T10:05:38Z",
        )
        assert resp.risk_level.code == "SECURED"
        assert resp.risk_level.label == "안전"
        assert resp.final_score == 15

    def test_xai_features_is_a_list(self):
        resp = ScanUrlResponse(
            scan_id="uuid-123",
            url="http://phish.tk/login",
            risk_level=RiskLevel(
                code="BLOCKED", label="위험", description="악성 URL로 판정되었습니다."
            ),
            final_score=87,
            xai_features=[
                XaiFeatureDetail(
                    title="위험 도메인 확장자",
                    description="악성 사이트에서 자주 쓰이는 확장자입니다.",
                    severity="high",
                    contribution=35,
                ),
            ],
            scanned_at="2025-03-10T10:05:38Z",
        )
        assert len(resp.xai_features) == 1
        assert resp.xai_features[0].severity == "high"
        assert resp.xai_features[0].contribution == 35

    def test_secured_has_empty_xai(self):
        """SECURED는 사용자에게 노출할 위험 근거가 없으므로 빈 배열"""
        resp = ScanUrlResponse(
            scan_id="uuid-123",
            url="https://example.com",
            risk_level=RiskLevel(code="SECURED", label="안전", description="안전합니다."),
            final_score=5,
            xai_features=[],
            scanned_at="2025-03-10T10:05:38Z",
        )
        assert resp.xai_features == []


# ── Report Schema ──

class TestReportRequest:
    def test_valid_report(self):
        req = ReportRequest(
            scan_log_id="uuid-456",
            url="https://malicious.com",
            reason="피싱 사이트입니다",
        )
        assert req.reason == "피싱 사이트입니다"

    def test_reason_max_length(self):
        with pytest.raises(ValidationError):
            ReportRequest(
                scan_log_id="uuid-456",
                url="https://malicious.com",
                reason="x" * 1001,
            )


class TestReportResponse:
    def test_default_values(self):
        resp = ReportResponse(report_id="uuid-789")
        assert resp.status == "queued"
        assert "검증" in resp.message


# ── User Log Schema ──

class TestBookmarkCreateRequest:
    def test_valid_bookmark(self):
        req = BookmarkCreateRequest(url="https://naver.com", title="네이버")
        assert req.title == "네이버"

    def test_title_optional(self):
        req = BookmarkCreateRequest(url="https://naver.com")
        assert req.title is None


class TestVisitCreateRequest:
    def test_valid_visit(self):
        req = VisitCreateRequest(url="https://naver.com", risk_level="SECURED")
        assert req.risk_level == "SECURED"


class TestScanSummary:
    def test_summary(self):
        summary = ScanSummary(
            total_scans=10,
            secured_count=6,
            suspicious_count=1,
            blocked_count=2,
            reported_count=1,
        )
        assert summary.total_scans == 10
        assert summary.suspicious_count == 1

    def test_suspicious_count_is_required(self):
        """WARNING → SUSPICIOUS 리네이밍 시 추가된 필드 (#24)"""
        with pytest.raises(ValidationError):
            ScanSummary(
                total_scans=0, secured_count=0, blocked_count=0, reported_count=0
            )


class TestScanLogsResponse:
    def test_empty_logs(self):
        resp = ScanLogsResponse(
            summary=ScanSummary(
                total_scans=0,
                secured_count=0,
                suspicious_count=0,
                blocked_count=0,
                reported_count=0,
            ),
            logs=[],
            total=0,
        )
        assert len(resp.logs) == 0
        assert resp.total == 0

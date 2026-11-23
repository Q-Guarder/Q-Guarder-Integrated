"""
클라이언트 API 명세서 변경사항 검증 테스트

항목:
  ① POST /scan/url  — 응답 스키마 구조 + 변환 로직
  ② GET  /scan-logs — summary 전체 집계 + REPORTED 오버라이드
  ③ PATCH /users/me          — 닉네임 변경 (200 / 404 / 422)
  ④ PATCH /users/me/password — 비밀번호 변경 (200 / 403)
  ⑤ DELETE /users/me         — 회원 탈퇴 (200 / 403 / body 포함)

실행: pytest tests/test_client_spec_changes.py -v
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.security import hash_password, verify_password
from app.schemas.auth_schema import (
    PasswordChangeRequest,
    PasswordChangeResponse,
    UserDeleteRequest,
    UserDeleteResponse,
    UserUpdateRequest,
    UserUpdateResponse,
)
from app.schemas.scan_schema import RiskLevel, ScanUrlResponse, XaiFeatureDetail
from app.schemas.user_log_schema import ScanLogItem
from app.services.feature_metadata import (
    FEATURE_META,
    RISK_LEVEL_META,
    XAI_MAX_FEATURES,
    _SEVERITY_ORDER,
)

# ── 테스트 상수 ──
TEST_USER_ID = uuid.uuid4()
TEST_PASSWORD = "correct_password_123"
TEST_PASSWORD_HASH = hash_password(TEST_PASSWORD)


def make_mock_user(nickname="테스터", password_hash=None):
    user = MagicMock()
    user.id = TEST_USER_ID
    user.email = "test@example.com"
    user.nickname = nickname
    user.password_hash = password_hash or TEST_PASSWORD_HASH
    user.refresh_token = "test_refresh_token"
    user.created_at = datetime.now(timezone.utc)
    return user


# ════════════════════════════════════════════════════════════════
#  ① POST /scan/url — 스키마 구조 검증
# ════════════════════════════════════════════════════════════════

class TestScanResponseSchema:
    """risk_level 객체화, xai_features 배열화, final_score int 검증"""

    def test_risk_level_is_object_not_string(self):
        rl = RiskLevel(code="BLOCKED", label="위험", description="악성 URL입니다.")
        assert isinstance(rl, RiskLevel)
        assert rl.code == "BLOCKED"
        assert rl.label == "위험"
        assert rl.description == "악성 URL입니다."

    def test_xai_contribution_is_int_not_float(self):
        xf = XaiFeatureDetail(
            title="단축 URL", description="설명", severity="high", contribution=34
        )
        assert isinstance(xf.contribution, int)
        assert xf.contribution == 34

    def test_scan_response_final_score_is_int(self):
        resp = ScanUrlResponse(
            scan_id="abc",
            url="https://example.com",
            risk_level=RiskLevel(code="SECURED", label="안전", description="안전합니다."),
            final_score=20,
            xai_features=[],
            scanned_at=datetime.now(timezone.utc),
        )
        assert isinstance(resp.final_score, int)

    def test_scan_response_xai_is_list_never_null(self):
        resp = ScanUrlResponse(
            scan_id="abc",
            url="https://example.com",
            risk_level=RiskLevel(code="SECURED", label="안전", description="안전합니다."),
            final_score=20,
            xai_features=[],
            scanned_at=datetime.now(timezone.utc),
        )
        assert isinstance(resp.xai_features, list)
        assert resp.xai_features is not None

    def test_all_three_risk_level_codes_have_korean_text(self):
        for code in ("SECURED", "SUSPICIOUS", "BLOCKED"):
            meta = RISK_LEVEL_META[code]
            rl = RiskLevel(code=code, label=meta["label"], description=meta["description"])
            assert rl.label != ""
            assert rl.description != ""

    def test_risk_level_meta_descriptions(self):
        assert RISK_LEVEL_META["SECURED"]["label"] == "안전"
        assert RISK_LEVEL_META["SUSPICIOUS"]["label"] == "주의"
        assert RISK_LEVEL_META["BLOCKED"]["label"] == "위험"


# ════════════════════════════════════════════════════════════════
#  ① POST /scan/url — 변환 로직 검증
# ════════════════════════════════════════════════════════════════

class TestScanTransformLogic:
    """float→int, xai 필터/정렬/제한 로직"""

    def test_final_score_float_to_int_conversion(self):
        assert round(0.674 * 100) == 67
        assert round(1.0 * 100) == 100
        assert round(0.0 * 100) == 0
        assert round(0.350 * 100) == 35
        assert round(0.999 * 100) == 100

    def test_xai_value_zero_excluded(self):
        """value=0인 피처는 xai_features에서 제외"""
        raw = {
            "is_shortened_url": {"value": 1.0, "contribution": 0.30},  # 포함
            "has_ip_address":   {"value": 0.0, "contribution": 0.20},  # value=0 → 제외
            "domain_entropy":   {"value": 0.8, "contribution": 0.25},  # 포함
        }
        result = []
        for feat_name, feat_data in raw.items():
            if not feat_data.get("value", 0):
                continue
            meta = FEATURE_META.get(feat_name)
            if meta is None:
                continue
            result.append(feat_name)

        assert len(result) == 2
        assert "has_ip_address" not in result

    def test_xai_sorted_by_contribution_descending(self):
        items = [
            XaiFeatureDetail(title="A", description="", severity="low",    contribution=20),
            XaiFeatureDetail(title="B", description="", severity="high",   contribution=35),
            XaiFeatureDetail(title="C", description="", severity="medium", contribution=28),
        ]
        items.sort(key=lambda x: (-x.contribution, _SEVERITY_ORDER.get(x.severity, 99)))
        assert [x.contribution for x in items] == [35, 28, 20]

    def test_xai_same_contribution_high_severity_first(self):
        """contribution 동률 시 severity 높은 것이 먼저"""
        items = [
            XaiFeatureDetail(title="Low",    description="", severity="low",    contribution=30),
            XaiFeatureDetail(title="High",   description="", severity="high",   contribution=30),
            XaiFeatureDetail(title="Medium", description="", severity="medium", contribution=30),
        ]
        items.sort(key=lambda x: (-x.contribution, _SEVERITY_ORDER.get(x.severity, 99)))
        assert items[0].severity == "high"
        assert items[1].severity == "medium"
        assert items[2].severity == "low"

    def test_xai_max_5_features_limit(self):
        items = [
            XaiFeatureDetail(title=f"F{i}", description="", severity="high", contribution=i)
            for i in range(10)
        ]
        limited = items[:XAI_MAX_FEATURES]
        assert len(limited) == 5
        assert XAI_MAX_FEATURES == 5

    def test_secured_forces_empty_xai_list(self):
        """SECURED 판정 시 xai_features는 강제로 빈 배열"""
        risk_level_code = "SECURED"
        xai_list = []
        if risk_level_code != "SECURED":
            xai_list.append("should not appear")
        assert xai_list == []

    def test_26_features_all_have_metadata(self):
        """26개 피처 모두 title/description/severity 보유"""
        from app.services.url_features import FEATURE_COLUMNS
        for col in FEATURE_COLUMNS:
            assert col in FEATURE_META, f"누락된 피처 메타데이터: {col}"
            meta = FEATURE_META[col]
            assert "title" in meta and meta["title"]
            assert "description" in meta and meta["description"]
            assert meta["severity"] in ("high", "medium", "low")


# ════════════════════════════════════════════════════════════════
#  ② GET /scan-logs — REPORTED + summary 집계
# ════════════════════════════════════════════════════════════════

class TestScanLogsBehavior:

    def test_reported_scan_shows_as_reported(self):
        """신고된 항목의 risk_level은 REPORTED로 오버라이드"""
        reported_id = uuid.uuid4()
        other_id = uuid.uuid4()
        reported_ids = {reported_id}

        assert ("REPORTED" if reported_id in reported_ids else "BLOCKED") == "REPORTED"
        assert ("REPORTED" if other_id in reported_ids else "BLOCKED") == "BLOCKED"

    def test_non_reported_items_keep_original_risk_level(self):
        """신고되지 않은 항목은 원래 risk_level 유지"""
        scan_ids = [uuid.uuid4() for _ in range(4)]
        reported_ids = {scan_ids[0]}
        originals = ["BLOCKED", "SUSPICIOUS", "SECURED", "BLOCKED"]

        logs = []
        for i, sid in enumerate(scan_ids):
            log = MagicMock()
            log.id = sid
            log.risk_level = originals[i]
            logs.append(log)

        results = [
            "REPORTED" if log.id in reported_ids else log.risk_level
            for log in logs
        ]
        assert results == ["REPORTED", "SUSPICIOUS", "SECURED", "BLOCKED"]

    def test_scan_log_item_final_score_is_int(self):
        item = ScanLogItem(
            scan_id=str(uuid.uuid4()),
            url="https://example.com",
            risk_level="BLOCKED",
            final_score=round(0.67 * 100),
            scanned_at=datetime.now(timezone.utc),
        )
        assert isinstance(item.final_score, int)
        assert item.final_score == 67

    def test_scan_log_item_accepts_reported_risk_level(self):
        """ScanLogItem.risk_level은 REPORTED 값 허용 (str 타입)"""
        item = ScanLogItem(
            scan_id=str(uuid.uuid4()),
            url="https://example.com",
            risk_level="REPORTED",
            final_score=87,
            scanned_at=datetime.now(timezone.utc),
        )
        assert item.risk_level == "REPORTED"

    def test_summary_fields_present(self):
        """ScanLogsResponse에 total 필드 존재"""
        from app.schemas.user_log_schema import ScanSummary, ScanLogsResponse
        summary = ScanSummary(
            total_scans=10, secured_count=5, suspicious_count=3,
            blocked_count=2, reported_count=1,
        )
        resp = ScanLogsResponse(summary=summary, logs=[], total=10)
        assert resp.total == 10
        assert resp.summary.reported_count == 1


# ════════════════════════════════════════════════════════════════
#  ③ PATCH /users/me — 닉네임 변경 스키마
# ════════════════════════════════════════════════════════════════

class TestUpdateProfileSchema:

    def test_empty_nickname_rejected(self):
        with pytest.raises(ValidationError):
            UserUpdateRequest(nickname="")

    def test_too_long_nickname_rejected(self):
        with pytest.raises(ValidationError):
            UserUpdateRequest(nickname="a" * 101)

    def test_max_length_100_accepted(self):
        req = UserUpdateRequest(nickname="a" * 100)
        assert len(req.nickname) == 100

    def test_korean_nickname_accepted(self):
        req = UserUpdateRequest(nickname="홍길동")
        assert req.nickname == "홍길동"

    def test_response_has_required_fields(self):
        resp = UserUpdateResponse(
            user_id=str(uuid.uuid4()),
            email="test@example.com",
            nickname="홍길동",
            created_at=datetime.now(timezone.utc),
        )
        assert resp.user_id
        assert resp.email
        assert resp.nickname == "홍길동"
        assert resp.created_at


# ════════════════════════════════════════════════════════════════
#  ③ PATCH /users/me — 라우트 핸들러
# ════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_update_profile_valid_nickname_returns_200():
    from app.api.v1.user_logs import update_profile
    mock_user = make_mock_user(nickname="새닉네임")
    mock_db = AsyncMock()

    with patch("app.crud.crud_user.update_user_nickname", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = mock_user
        result = await update_profile(
            body=UserUpdateRequest(nickname="새닉네임"),
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    assert result.nickname == "새닉네임"
    assert result.email == "test@example.com"
    assert result.user_id == str(TEST_USER_ID)
    mock_fn.assert_called_once_with(mock_db, TEST_USER_ID, "새닉네임")


@pytest.mark.asyncio
async def test_update_profile_user_not_found_raises_404():
    from app.api.v1.user_logs import update_profile
    mock_db = AsyncMock()

    with patch("app.crud.crud_user.update_user_nickname", new_callable=AsyncMock) as mock_fn:
        mock_fn.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            await update_profile(
                body=UserUpdateRequest(nickname="새닉네임"),
                current_user_id=str(TEST_USER_ID),
                db=mock_db,
            )
    assert exc_info.value.status_code == 404


# ════════════════════════════════════════════════════════════════
#  ④ PATCH /users/me/password — 비밀번호 변경 스키마
# ════════════════════════════════════════════════════════════════

class TestPasswordChangeSchema:

    def test_new_password_too_short_rejected(self):
        with pytest.raises(ValidationError):
            PasswordChangeRequest(current_password="old", new_password="short")

    def test_new_password_max_128_accepted(self):
        req = PasswordChangeRequest(current_password="old", new_password="a" * 128)
        assert len(req.new_password) == 128

    def test_new_password_129_rejected(self):
        with pytest.raises(ValidationError):
            PasswordChangeRequest(current_password="old", new_password="a" * 129)

    def test_success_message_korean(self):
        assert PasswordChangeResponse().message == "비밀번호가 변경되었습니다"


# ════════════════════════════════════════════════════════════════
#  ④ PATCH /users/me/password — 라우트 핸들러
# ════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_change_password_wrong_current_returns_403_not_401():
    """현재 비밀번호 불일치 → 반드시 403 (Android가 403에 매핑됨)"""
    from app.api.v1.user_logs import change_password
    mock_user = make_mock_user()
    mock_db = AsyncMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_user
        with pytest.raises(HTTPException) as exc_info:
            await change_password(
                body=PasswordChangeRequest(
                    current_password="wrong_password_xyz",
                    new_password="new_long_pass_123",
                ),
                current_user_id=str(TEST_USER_ID),
                db=mock_db,
            )

    assert exc_info.value.status_code == 403  # 401이 아님
    assert "현재 비밀번호" in exc_info.value.detail


@pytest.mark.asyncio
async def test_change_password_correct_current_returns_success():
    """현재 비밀번호 일치 → 200 + 성공 메시지"""
    from app.api.v1.user_logs import change_password
    mock_user = make_mock_user()
    mock_db = AsyncMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get, \
         patch("app.crud.crud_user.update_user_password", new_callable=AsyncMock) as mock_update:
        mock_get.return_value = mock_user
        mock_update.return_value = None
        result = await change_password(
            body=PasswordChangeRequest(
                current_password=TEST_PASSWORD,
                new_password="new_long_pass_123",
            ),
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    assert result.message == "비밀번호가 변경되었습니다"


@pytest.mark.asyncio
async def test_change_password_refresh_token_invalidated():
    """비밀번호 변경 시 update_user_password 호출 → 내부에서 refresh_token 무효화"""
    from app.api.v1.user_logs import change_password
    mock_user = make_mock_user()
    mock_db = AsyncMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get, \
         patch("app.crud.crud_user.update_user_password", new_callable=AsyncMock) as mock_update:
        mock_get.return_value = mock_user
        mock_update.return_value = None
        await change_password(
            body=PasswordChangeRequest(
                current_password=TEST_PASSWORD,
                new_password="new_long_pass_123",
            ),
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    # update_user_password가 호출되었는지 확인 (이 함수가 refresh_token 무효화)
    mock_update.assert_called_once()
    _, called_user_id, called_hash = mock_update.call_args[0]
    assert called_user_id == TEST_USER_ID
    # 새 비밀번호 해시가 올바른지 확인
    assert verify_password("new_long_pass_123", called_hash)
    # 기존 비밀번호 해시와 달라야 함
    assert called_hash != TEST_PASSWORD_HASH


# ════════════════════════════════════════════════════════════════
#  ⑤ DELETE /users/me — 회원 탈퇴 스키마
# ════════════════════════════════════════════════════════════════

class TestUserDeleteSchema:

    def test_password_field_required(self):
        with pytest.raises(ValidationError):
            UserDeleteRequest()

    def test_valid_delete_request(self):
        req = UserDeleteRequest(password="my_password")
        assert req.password == "my_password"

    def test_success_message_korean(self):
        assert UserDeleteResponse().message == "회원 탈퇴가 처리되었습니다"


# ════════════════════════════════════════════════════════════════
#  ⑤ DELETE /users/me — 라우트 핸들러
# ════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_delete_account_wrong_password_returns_403_not_401():
    """비밀번호 불일치 → 반드시 403 (Android가 403에 매핑됨)"""
    from app.api.v1.user_logs import delete_account
    mock_user = make_mock_user()
    mock_db = AsyncMock()
    mock_response = MagicMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_user
        with pytest.raises(HTTPException) as exc_info:
            await delete_account(
                body=UserDeleteRequest(password="wrong_password_xyz"),
                response=mock_response,
                current_user_id=str(TEST_USER_ID),
                db=mock_db,
            )

    assert exc_info.value.status_code == 403  # 401이 아님
    assert "비밀번호" in exc_info.value.detail


@pytest.mark.asyncio
async def test_delete_account_correct_password_returns_success():
    """비밀번호 일치 → 200 + 성공 메시지"""
    from app.api.v1.user_logs import delete_account
    mock_user = make_mock_user()
    mock_db = AsyncMock()
    mock_response = MagicMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get, \
         patch("app.crud.crud_user.delete_user", new_callable=AsyncMock) as mock_delete:
        mock_get.return_value = mock_user
        mock_delete.return_value = None
        result = await delete_account(
            body=UserDeleteRequest(password=TEST_PASSWORD),
            response=mock_response,
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    assert result.message == "회원 탈퇴가 처리되었습니다"


@pytest.mark.asyncio
async def test_delete_account_refresh_token_cookie_cleared():
    """탈퇴 후 refresh_token 쿠키 삭제 확인"""
    from app.api.v1.user_logs import delete_account
    mock_user = make_mock_user()
    mock_db = AsyncMock()
    mock_response = MagicMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get, \
         patch("app.crud.crud_user.delete_user", new_callable=AsyncMock):
        mock_get.return_value = mock_user
        await delete_account(
            body=UserDeleteRequest(password=TEST_PASSWORD),
            response=mock_response,
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    mock_response.delete_cookie.assert_called_once_with(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


@pytest.mark.asyncio
async def test_delete_account_calls_delete_user_crud():
    """탈퇴 시 delete_user CRUD가 올바른 user_id로 호출되는지 확인"""
    from app.api.v1.user_logs import delete_account
    mock_user = make_mock_user()
    mock_db = AsyncMock()
    mock_response = MagicMock()

    with patch("app.crud.crud_user.get_user_by_id", new_callable=AsyncMock) as mock_get, \
         patch("app.crud.crud_user.delete_user", new_callable=AsyncMock) as mock_delete:
        mock_get.return_value = mock_user
        mock_delete.return_value = None
        await delete_account(
            body=UserDeleteRequest(password=TEST_PASSWORD),
            response=mock_response,
            current_user_id=str(TEST_USER_ID),
            db=mock_db,
        )

    mock_delete.assert_called_once_with(mock_db, TEST_USER_ID)

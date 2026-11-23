"""사용자 기록 API 라우터 — 스캔 이력, 즐겨찾기(안심 URL), 방문 기록, 회원 정보 관리"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    get_current_user_id,
    hash_password,
    verify_password,
)
from app.crud import crud_log, crud_report, crud_scan, crud_user
from app.db.session import get_db
from app.schemas.auth_schema import (
    PasswordChangeRequest,
    PasswordChangeResponse,
    UserDeleteRequest,
    UserDeleteResponse,
    UserUpdateRequest,
    UserUpdateResponse,
)
from app.schemas.user_log_schema import (
    BookmarkCreateRequest,
    BookmarkCreateResponse,
    BookmarkDeleteResponse,
    BookmarkItem,
    BookmarkListResponse,
    ScanLogItem,
    ScanLogsResponse,
    ScanSummary,
    VisitCreateRequest,
    VisitCreateResponse,
    VisitItem,
    VisitListResponse,
)

router = APIRouter(prefix="/users/me", tags=["User Logs"])


# ═══════════════════════════════════════════════════════════════
#  회원 정보 관리
# ═══════════════════════════════════════════════════════════════

@router.get(
    "",
    response_model=UserUpdateResponse,
    summary="내 프로필 조회",
    description=(
        "로그인한 사용자의 프로필(user_id, email, nickname, created_at)을 반환합니다. "
        "Android 앱이 로그인 직후 호출해 닉네임·user_id를 저장합니다."
    ),
)
async def get_profile(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    user = await crud_user.get_user_by_id(db, uuid.UUID(current_user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="사용자를 찾을 수 없습니다.",
        )
    return UserUpdateResponse(
        user_id=str(user.id),
        email=user.email,
        nickname=user.nickname,
        created_at=user.created_at,
    )


@router.patch(
    "",
    response_model=UserUpdateResponse,
    summary="닉네임 변경",
    description="로그인한 사용자의 닉네임을 변경합니다.",
)
async def update_profile(
    body: UserUpdateRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    user = await crud_user.update_user_nickname(
        db, uuid.UUID(current_user_id), body.nickname
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="사용자를 찾을 수 없습니다.",
        )
    return UserUpdateResponse(
        user_id=str(user.id),
        email=user.email,
        nickname=user.nickname,
        created_at=user.created_at,
    )


@router.patch(
    "/password",
    response_model=PasswordChangeResponse,
    summary="비밀번호 변경",
    description=(
        "현재 비밀번호를 확인한 후 새 비밀번호로 변경합니다. "
        "성공 시 서버의 Refresh Token이 무효화되므로 클라이언트는 재로그인이 필요합니다."
    ),
)
async def change_password(
    body: PasswordChangeRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    user = await crud_user.get_user_by_id(db, uuid.UUID(current_user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="사용자를 찾을 수 없습니다.",
        )
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="현재 비밀번호가 올바르지 않습니다.",
        )
    await crud_user.update_user_password(
        db, uuid.UUID(current_user_id), hash_password(body.new_password)
    )
    return PasswordChangeResponse()


@router.delete(
    "",
    response_model=UserDeleteResponse,
    summary="회원 탈퇴",
    description=(
        "비밀번호를 확인한 후 계정을 탈퇴 처리합니다. "
        "탈퇴 후 서버의 Refresh Token이 즉시 무효화됩니다."
    ),
)
async def delete_account(
    body: UserDeleteRequest = Body(...),
    response: Response = None,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    user = await crud_user.get_user_by_id(db, uuid.UUID(current_user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="사용자를 찾을 수 없습니다.",
        )
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="비밀번호가 올바르지 않습니다.",
        )
    await crud_user.delete_user(db, uuid.UUID(current_user_id))
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return UserDeleteResponse()


# ═══════════════════════════════════════════════════════════════
#  스캔 이력 & 대시보드
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/scan-logs",
    response_model=ScanLogsResponse,
    summary="내 스캔 이력 및 보안 통계 조회",
    description=(
        "스캔 이력과 대시보드용 통계를 반환합니다. "
        "summary는 page/size/날짜 필터와 무관하게 사용자 전체 이력 기준으로 집계됩니다. "
        "신고된 항목은 risk_level이 REPORTED로 반환됩니다."
    ),
)
async def get_scan_logs(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
    date_from: datetime | None = Query(None, alias="from", description="조회 시작일 (ISO 8601)"),
    date_to: datetime | None = Query(None, alias="to", description="조회 종료일 (ISO 8601)"),
    page: int = Query(1, ge=1, description="페이지 번호"),
    size: int = Query(20, ge=1, le=100, description="페이지 크기"),
):
    uid = uuid.UUID(current_user_id)

    # summary: 항상 전체 이력 기준 (page/size/날짜 필터 무관)
    summary_data = await crud_scan.get_scan_summary(db, uid)
    reported_count = await crud_report.get_reported_count_by_user(db, uid)
    summary = ScanSummary(
        total_scans=summary_data["total_scans"],
        secured_count=summary_data["secured_count"],
        suspicious_count=summary_data["suspicious_count"],
        blocked_count=summary_data["blocked_count"],
        reported_count=reported_count,
    )

    # 이력 조회 (페이지네이션 + 날짜 필터 적용)
    logs, total = await crud_scan.get_scan_logs_by_user(
        db, uid, date_from, date_to, page, size
    )

    # 신고된 scan_log_id 집합 — risk_level 오버라이드용
    reported_scan_ids = await crud_report.get_reported_scan_ids_by_user(db, uid)

    log_items = [
        ScanLogItem(
            scan_id=str(log.id),
            url=log.url,
            risk_level="REPORTED" if log.id in reported_scan_ids else log.risk_level,
            final_score=round(log.final_score * 100),
            scanned_at=log.scanned_at,
        )
        for log in logs
    ]

    return ScanLogsResponse(summary=summary, logs=log_items, total=total)


# ═══════════════════════════════════════════════════════════════
#  즐겨찾기 (안심 URL)
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/bookmarks",
    response_model=BookmarkListResponse,
    summary="즐겨찾기 목록 조회",
    description="사용자가 등록한 안심 URL(즐겨찾기) 목록을 반환합니다.",
)
async def get_bookmarks(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
    page: int = Query(1, ge=1, description="페이지 번호"),
    size: int = Query(20, ge=1, le=100, description="페이지 크기"),
):
    bookmarks, total = await crud_log.get_bookmarks_by_user(
        db, uuid.UUID(current_user_id), page, size
    )
    items = [
        BookmarkItem(
            bookmark_id=str(b.id),
            url=b.url,
            title=b.title,
            risk_level=b.risk_level,
            created_at=b.created_at,
        )
        for b in bookmarks
    ]
    return BookmarkListResponse(items=items, total=total)


@router.post(
    "/bookmarks",
    response_model=BookmarkCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="즐겨찾기 추가",
    description="안심 URL을 즐겨찾기에 등록합니다.",
)
async def create_bookmark(
    body: BookmarkCreateRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    bookmark = await crud_log.create_bookmark(
        db=db,
        user_id=uuid.UUID(current_user_id),
        url=body.url,
        title=body.title,
    )
    return BookmarkCreateResponse(
        bookmark_id=str(bookmark.id),
        created_at=bookmark.created_at,
    )


@router.delete(
    "/bookmarks/{bookmark_id}",
    response_model=BookmarkDeleteResponse,
    summary="즐겨찾기 삭제",
    description="지정한 즐겨찾기를 삭제합니다. 본인 소유의 항목만 삭제할 수 있습니다.",
)
async def delete_bookmark(
    bookmark_id: str,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    deleted = await crud_log.delete_bookmark(
        db, uuid.UUID(bookmark_id), uuid.UUID(current_user_id)
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="즐겨찾기를 찾을 수 없거나 삭제 권한이 없습니다.",
        )
    return BookmarkDeleteResponse()


# ═══════════════════════════════════════════════════════════════
#  방문 기록
# ═══════════════════════════════════════════════════════════════

@router.post(
    "/visits",
    response_model=VisitCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="방문 기록 추가",
    description="스캔 후 실제 웹사이트 방문 시 기록을 저장합니다.",
)
async def create_visit(
    body: VisitCreateRequest,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    visit = await crud_log.create_visit(
        db=db,
        user_id=uuid.UUID(current_user_id),
        url=body.url,
        risk_level=body.risk_level,
    )
    return VisitCreateResponse(
        visit_id=str(visit.id),
        visited_at=visit.visited_at,
    )


@router.get(
    "/visits",
    response_model=VisitListResponse,
    summary="방문 기록 조회",
    description="과거 방문 기록을 페이지네이션으로 조회합니다.",
)
async def get_visits(
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
    page: int = Query(1, ge=1, description="페이지 번호"),
    size: int = Query(20, ge=1, le=100, description="페이지 크기"),
):
    visits, total = await crud_log.get_visits_by_user(
        db, uuid.UUID(current_user_id), page, size
    )
    items = [
        VisitItem(
            url=v.url,
            risk_level=v.risk_level,
            visited_at=v.visited_at,
        )
        for v in visits
    ]
    return VisitListResponse(items=items, total=total)

import uuid
from datetime import datetime

from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import ScanLog, ScoreDetail


async def create_scan_log(
    db: AsyncSession,
    user_id: uuid.UUID,
    url: str,
    url_hash: str,
    risk_level: str,
    final_score: float,
    scan_source: str | None = None,
) -> ScanLog:
    """스캔 로그 생성"""
    scan_log = ScanLog(
        id=uuid.uuid4(),
        user_id=user_id,
        url=url,
        url_hash=url_hash,
        risk_level=risk_level,
        final_score=final_score,
        scan_source=scan_source,
    )
    db.add(scan_log)
    await db.flush()
    return scan_log


async def create_score_detail(
    db: AsyncSession,
    scan_log_id: uuid.UUID,
    vt_detected_engines: int | None = None,
    vt_total_engines: int | None = None,
    vt_weighted_score: float | None = None,
    ml_probability: float | None = None,
    ml_weighted_score: float | None = None,
    weighting_case: str | None = None,
    xai_features: dict | None = None,
) -> ScoreDetail:
    """스캔 점수 상세 저장"""
    detail = ScoreDetail(
        id=uuid.uuid4(),
        scan_log_id=scan_log_id,
        vt_detected_engines=vt_detected_engines,
        vt_total_engines=vt_total_engines,
        vt_weighted_score=vt_weighted_score,
        ml_probability=ml_probability,
        ml_weighted_score=ml_weighted_score,
        weighting_case=weighting_case,
        xai_features=xai_features,
    )
    db.add(detail)
    await db.flush()
    return detail


async def get_scan_log_by_id(db: AsyncSession, scan_id: uuid.UUID) -> ScanLog | None:
    """스캔 로그 단건 조회"""
    result = await db.execute(select(ScanLog).where(ScanLog.id == scan_id))
    return result.scalar_one_or_none()


async def get_scan_logs_by_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = 1,
    size: int = 20,
) -> tuple[list[ScanLog], int]:
    """사용자의 스캔 이력 페이지네이션 조회 (기간 필터 지원)"""
    base = select(ScanLog).where(ScanLog.user_id == user_id)
    if date_from:
        base = base.where(ScanLog.scanned_at >= date_from)
    if date_to:
        base = base.where(ScanLog.scanned_at <= date_to)

    # total count
    count_stmt = select(sa_func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # paginated items
    offset = (page - 1) * size
    stmt = base.order_by(ScanLog.scanned_at.desc()).offset(offset).limit(size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return items, total


async def get_scan_summary(
    db: AsyncSession,
    user_id: uuid.UUID,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
) -> dict:
    """사용자 스캔 통계 (대시보드용)"""
    base = select(ScanLog).where(ScanLog.user_id == user_id)
    if date_from:
        base = base.where(ScanLog.scanned_at >= date_from)
    if date_to:
        base = base.where(ScanLog.scanned_at <= date_to)

    total_q = select(sa_func.count()).select_from(base.subquery())
    secured_q = select(sa_func.count()).select_from(
        base.where(ScanLog.risk_level == "SECURED").subquery()
    )
    suspicious_q = select(sa_func.count()).select_from(
        base.where(ScanLog.risk_level == "SUSPICIOUS").subquery()
    )
    blocked_q = select(sa_func.count()).select_from(
        base.where(ScanLog.risk_level == "BLOCKED").subquery()
    )

    total = (await db.execute(total_q)).scalar() or 0
    secured = (await db.execute(secured_q)).scalar() or 0
    suspicious = (await db.execute(suspicious_q)).scalar() or 0
    blocked = (await db.execute(blocked_q)).scalar() or 0

    return {
        "total_scans": total,
        "secured_count": secured,
        "suspicious_count": suspicious,
        "blocked_count": blocked,
    }

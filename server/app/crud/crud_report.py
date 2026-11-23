import hashlib
import uuid

from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.report import FeedbackQueue, ReportedUrl


async def create_reported_url(
    db: AsyncSession,
    user_id: uuid.UUID,
    scan_log_id: uuid.UUID,
    url: str,
    reason: str,
) -> ReportedUrl:
    """악성 URL 신고 접수"""
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    reported = ReportedUrl(
        id=uuid.uuid4(),
        user_id=user_id,
        scan_log_id=scan_log_id,
        url=url,
        url_hash=url_hash,
        reason=reason,
    )
    db.add(reported)
    await db.flush()
    return reported


async def create_feedback_queue(
    db: AsyncSession, reported_url_id: uuid.UUID, url: str
) -> FeedbackQueue:
    """신고 건을 Feedback Queue에 적재"""
    queue_item = FeedbackQueue(
        id=uuid.uuid4(),
        reported_url_id=reported_url_id,
        url=url,
    )
    db.add(queue_item)
    await db.flush()
    return queue_item


async def mark_kisa_reported(db: AsyncSession, feedback_id: uuid.UUID) -> bool:
    """KISA 신고 메일 발송이 **성공한 뒤에** 호출하여 중복 신고를 방지한다.

    발송 전에 플래그를 세우면 발송 실패 시에도 '신고됨'으로 남아 재시도가 불가능해진다.
    """
    item = await db.get(FeedbackQueue, feedback_id)
    if item is None:
        return False
    item.is_reported_to_kisa = True
    await db.flush()
    return True


async def get_pending_feedback_items(db: AsyncSession) -> list[FeedbackQueue]:
    """처리되지 않은 Feedback Queue 항목 조회"""
    stmt = (
        select(FeedbackQueue)
        .where(FeedbackQueue.processed_at.is_(None))
        .order_by(FeedbackQueue.queued_at.asc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_reported_count_by_user(
    db: AsyncSession, user_id: uuid.UUID
) -> int:
    """사용자의 총 신고 건수"""
    stmt = select(sa_func.count()).select_from(
        select(ReportedUrl).where(ReportedUrl.user_id == user_id).subquery()
    )
    return (await db.execute(stmt)).scalar() or 0


async def get_reported_scan_ids_by_user(
    db: AsyncSession, user_id: uuid.UUID
) -> set[uuid.UUID]:
    """사용자가 신고한 scan_log_id 집합 반환 (risk_level 오버라이드용)"""
    stmt = select(ReportedUrl.scan_log_id).where(ReportedUrl.user_id == user_id)
    result = await db.execute(stmt)
    return set(result.scalars().all())

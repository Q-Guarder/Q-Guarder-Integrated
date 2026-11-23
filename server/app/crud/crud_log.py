import uuid

from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.log import Bookmark, VisitHistory


# ── Bookmarks ──

async def create_bookmark(
    db: AsyncSession,
    user_id: uuid.UUID,
    url: str,
    title: str | None = None,
    risk_level: str | None = None,
) -> Bookmark:
    """즐겨찾기 추가"""
    bookmark = Bookmark(
        id=uuid.uuid4(),
        user_id=user_id,
        url=url,
        title=title,
        risk_level=risk_level,
    )
    db.add(bookmark)
    await db.flush()
    return bookmark


async def get_bookmarks_by_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    page: int = 1,
    size: int = 20,
) -> tuple[list[Bookmark], int]:
    """사용자 즐겨찾기 목록 페이지네이션 조회"""
    base = select(Bookmark).where(Bookmark.user_id == user_id)

    # total count
    count_stmt = select(sa_func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # paginated items
    offset = (page - 1) * size
    stmt = base.order_by(Bookmark.created_at.desc()).offset(offset).limit(size)
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return items, total


async def delete_bookmark(
    db: AsyncSession, bookmark_id: uuid.UUID, user_id: uuid.UUID
) -> bool:
    """즐겨찾기 삭제 (소유자 확인)"""
    stmt = select(Bookmark).where(
        Bookmark.id == bookmark_id, Bookmark.user_id == user_id
    )
    result = await db.execute(stmt)
    bookmark = result.scalar_one_or_none()
    if bookmark is None:
        return False
    await db.delete(bookmark)
    await db.flush()
    return True


# ── Visit History ──

async def create_visit(
    db: AsyncSession,
    user_id: uuid.UUID,
    url: str,
    risk_level: str,
) -> VisitHistory:
    """방문 기록 추가"""
    visit = VisitHistory(
        id=uuid.uuid4(),
        user_id=user_id,
        url=url,
        risk_level=risk_level,
    )
    db.add(visit)
    await db.flush()
    return visit


async def get_visits_by_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    page: int = 1,
    size: int = 20,
) -> tuple[list[VisitHistory], int]:
    """사용자 방문 기록 페이지네이션 조회"""
    # total count
    count_stmt = select(sa_func.count()).select_from(
        select(VisitHistory).where(VisitHistory.user_id == user_id).subquery()
    )
    total = (await db.execute(count_stmt)).scalar() or 0

    # paginated items
    offset = (page - 1) * size
    stmt = (
        select(VisitHistory)
        .where(VisitHistory.user_id == user_id)
        .order_by(VisitHistory.visited_at.desc())
        .offset(offset)
        .limit(size)
    )
    result = await db.execute(stmt)
    items = list(result.scalars().all())

    return items, total

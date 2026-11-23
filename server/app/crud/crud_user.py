import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


async def create_user(
    db: AsyncSession,
    email: str,
    password_hash: str,
    nickname: str,
) -> User:
    """신규 회원 생성"""
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=password_hash,
        nickname=nickname,
    )
    db.add(user)
    await db.flush()
    return user


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """이메일로 사용자 조회"""
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    """UUID로 사용자 조회"""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def update_refresh_token(
    db: AsyncSession, user_id: uuid.UUID, refresh_token: str | None
) -> None:
    """Refresh Token 저장 또는 무효화(None)"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.refresh_token = refresh_token
        await db.flush()


async def update_user_nickname(
    db: AsyncSession, user_id: uuid.UUID, nickname: str
) -> User | None:
    """닉네임 변경"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.nickname = nickname
        await db.flush()
    return user


async def update_user_password(
    db: AsyncSession, user_id: uuid.UUID, new_password_hash: str
) -> None:
    """비밀번호 변경 + Refresh Token 무효화 (기존 세션 강제 만료)"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.password_hash = new_password_hash
        user.refresh_token = None
        await db.flush()


async def delete_user(db: AsyncSession, user_id: uuid.UUID) -> None:
    """회원 탈퇴 (소프트 삭제: 비활성화 + 토큰 무효화)"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.is_active = False
        user.refresh_token = None
        await db.flush()


async def deactivate_user(db: AsyncSession, user_id: uuid.UUID) -> None:
    """사용자 비활성화"""
    user = await get_user_by_id(db, user_id)
    if user:
        user.is_active = False
        await db.flush()

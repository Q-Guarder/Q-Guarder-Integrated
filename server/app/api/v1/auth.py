"""인증 API 라우터 — 회원가입, 로그인, 토큰 갱신, 로그아웃"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, Cookie, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user_id,
)
from app.crud import crud_user
from app.db.session import get_db
from app.schemas.auth_schema import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
)

router = APIRouter(prefix="/auth", tags=["Auth"])


# ── 회원가입 ──

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="회원가입",
    description="이메일, 비밀번호, 닉네임으로 신규 회원을 생성합니다.",
)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db, scope="function")):
    existing = await crud_user.get_user_by_email(db, body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="이미 가입된 이메일입니다.",
        )

    hashed = hash_password(body.password)
    user = await crud_user.create_user(db, body.email, hashed, body.nickname)

    return RegisterResponse(
        user_id=str(user.id),
        email=user.email,
        nickname=user.nickname,
        created_at=user.created_at,
    )


# ── 로그인 ──

@router.post(
    "/login",
    response_model=LoginResponse,
    summary="로그인",
    description="이메일/비밀번호 인증 후 Access Token을 반환하고, Refresh Token을 HttpOnly 쿠키로 설정합니다.",
)
async def login(
    body: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db, scope="function"),
):
    user = await crud_user.get_user_by_email(db, body.email)
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="이메일 또는 비밀번호가 올바르지 않습니다.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="비활성화된 계정입니다.",
        )

    access_token = create_access_token(subject=str(user.id))
    refresh_token = create_refresh_token(subject=str(user.id))

    await crud_user.update_refresh_token(db, user.id, refresh_token)

    settings = get_settings()
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict" if settings.COOKIE_SECURE else "lax",
        path="/",
    )

    return LoginResponse(access_token=access_token)


# ── 토큰 갱신 ──

@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Access Token 갱신",
    description="HttpOnly 쿠키의 Refresh Token으로 새 Access Token을 발급합니다.",
)
async def refresh(
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token이 없습니다.",
        )

    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token이 아닙니다.",
        )

    user_id = uuid.UUID(payload["sub"])
    user = await crud_user.get_user_by_id(db, user_id)
    if not user or user.refresh_token != refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 Refresh token입니다.",
        )

    new_access = create_access_token(subject=str(user.id))
    return RefreshResponse(access_token=new_access)


# ── 로그아웃 ──

@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="로그아웃",
    description="서버의 Refresh Token을 무효화하고 쿠키를 삭제합니다.",
)
async def logout(
    response: Response,
    current_user_id: str = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db, scope="function"),
):
    await crud_user.update_refresh_token(db, uuid.UUID(current_user_id), None)

    settings = get_settings()
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict" if settings.COOKIE_SECURE else "lax",
        path="/",
    )

    return LogoutResponse()

"""Q-Guarder FastAPI 앱 — 라우터 통합 (uvicorn으로 실행)"""

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.api.v1 import auth, scan, report, user_logs
from app.db.session import engine
from app.models.user import Base
# 모든 모델을 import하여 Base.metadata에 등록
import app.models.scan  # noqa: F401
import app.models.log  # noqa: F401
import app.models.report  # noqa: F401
import app.models.ml_model  # noqa: F401

settings = get_settings()

# ── 로깅 설정 ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# ── Lifespan: 서버 시작 시 DB 테이블 자동 생성 ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logging.warning(f"DB 연결 실패 (테이블 생성 건너뜀): {e}")
    yield


# ── FastAPI 앱 생성 ──
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="QR 코드 악성 URL 탐지 API — LightGBM + VirusTotal 하이브리드 엔진",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS 미들웨어 ──
_origins = [
    origin.strip()
    for origin in settings.CORS_ORIGINS.split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── v1 라우터 등록 ──
app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(scan.router, prefix=settings.API_V1_PREFIX)
app.include_router(report.router, prefix=settings.API_V1_PREFIX)
app.include_router(user_logs.router, prefix=settings.API_V1_PREFIX)


# ── Health Check ──
@app.get(
    "/health",
    tags=["Health"],
    summary="서버 상태 확인",
    description="API 서버가 정상 동작 중인지 확인합니다.",
)
async def health_check():
    return {"status": "ok", "service": settings.PROJECT_NAME}


@app.get(
    f"{settings.API_V1_PREFIX}/health",
    tags=["Health"],
    summary="서버 상태 확인 (앱용)",
    description="Android 앱의 HealthData(status, version, model, checks) 형식으로 응답합니다.",
)
async def health_check_v1():
    return {
        "status": "ok",
        "version": app.version,
        "model": "xgb+lgbm-top17-softvoting",
        "checks": {"api": "ok"},
    }

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Depends용 비동기 DB 세션 제너레이터

    ⚠️ 반드시 `Depends(get_db, scope="function")` 으로 주입할 것.
       FastAPI 0.118+ 의 기본 scope("request")는 yield 뒤 코드(= commit)를 **응답을 보낸 뒤에**
       실행한다. 그러면 클라이언트가 응답을 받자마자 보낸 다음 요청이 아직 커밋되지 않은
       데이터를 못 본다 (예: 로그인 직후 GET /users/me → 401 "Token has been revoked",
       가입 직후 로그인 실패). scope="function" 은 응답 전에 커밋한다.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

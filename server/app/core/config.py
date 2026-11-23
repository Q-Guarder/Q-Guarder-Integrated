from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # ── 프로젝트 기본 정보 ──
    PROJECT_NAME: str = "Q-Guarder"
    API_V1_PREFIX: str = "/api/v1"

    # ── 데이터베이스 ──
    DATABASE_URL: str  # e.g. postgresql+asyncpg://user:pass@host:5432/dbname

    # ── JWT 인증 ──
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── AWS ──
    AWS_REGION: str = "ap-northeast-2"
    S3_MODEL_BUCKET: str = ""
    S3_MODEL_KEY: str = "models/model.pkl"
    SES_SENDER_EMAIL: str = ""
    # KISA(cert@kisa.or.kr) 자동 신고 메일 발송 스위치.
    # 기본 False — 로컬 개발·시연·테스트에서 실제 메일이 나가지 않게 한다.
    # 운영 배포에서만 True 로 켠다 (infrastructure/main.tf 의 Lambda 환경 변수).
    KISA_REPORT_ENABLED: bool = False

    # ── Cookie ──
    COOKIE_SECURE: bool = True  # HTTPS 전용 쿠키 (로컬 개발 시 False)

    # ── CORS ──
    CORS_ORIGINS: str = ""  # 쉼표 구분 허용 출처 (e.g. "https://app.example.com,https://admin.example.com")

    # ── VirusTotal ──
    VIRUSTOTAL_API_KEY: str = ""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


@lru_cache()
def get_settings() -> Settings:
    return Settings()

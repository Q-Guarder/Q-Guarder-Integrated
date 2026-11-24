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

    # ── KISA 신고 메일 (SMTP) ──
    # 발송 스위치. 기본 False — 켜지 않으면 신고를 받아도 메일을 보내지 않는다.
    KISA_REPORT_ENABLED: bool = False
    # 받는 주소. 비어 있으면 보내지 않는다.
    # 테스트할 때는 본인 메일 주소, 실제 신고할 때만 cert@kisa.or.kr
    KISA_REPORT_RECIPIENT: str = ""
    # 보내는 메일 서버 (Gmail: smtp.gmail.com / 587 / STARTTLS, 비밀번호는 '앱 비밀번호')
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True  # STARTTLS
    # 보내는 사람 주소. 비어 있으면 SMTP_USERNAME을 쓴다.
    MAIL_FROM: str = ""

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

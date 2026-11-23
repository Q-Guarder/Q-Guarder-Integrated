# ── Stage: runtime ──
FROM python:3.11-slim AS runtime

# 시스템 패키지 업데이트 + psycopg2-binary + ML 런타임(OpenMP)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# [보안] non-root 유저 생성
RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# 의존성 레이어 캐시 분리: requirements.txt만 먼저 복사 → pip install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 소스코드 복사
COPY . .

# [보안] non-root 유저로 전환
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

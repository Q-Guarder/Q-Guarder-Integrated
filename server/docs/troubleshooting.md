# Q-Guarder Troubleshooting & Security Hotfix Log

> **작성일**: 2026-03-25  
> **작성자**: DevSecOps 보안 감사팀  
> **대상**: Q-Guarder-Server v1.0.0  
> **감사 기준**: OWASP Top 10 2021 · Zero-Trust Architecture

---

## 목차

1. [SEC-01: CORS allow_origins 와일드카드(*) + Credentials 동시 허용](#sec-01-cors-allow_origins-와일드카드--credentials-동시-허용)
2. [SEC-02: Report API IDOR(Broken Object Level Authorization) 취약점](#sec-02-report-api-idorbroken-object-level-authorization-취약점)
3. [SEC-03: Scan API 에러 바운더리 미비로 인한 스택트레이스 노출](#sec-03-scan-api-에러-바운더리-미비로-인한-스택트레이스-노출)
4. [ASYNC-01: asyncio.get_event_loop() Deprecation으로 인한 런타임 충돌](#async-01-asyncioget_event_loop-deprecation으로-인한-런타임-충돌)
5. [SEC-04: URL 스키마 검증 부재 — XSS 벡터 유입 가능](#sec-04-url-스키마-검증-부재--xss-벡터-유입-가능)
6. [SEC-05: verify_password 예외 미처리로 인한 인증 우회 가능성](#sec-05-verify_password-예외-미처리로-인한-인증-우회-가능성)
7. [AUTH-01: Refresh Token 쿠키 Secure 플래그로 인한 로컬 개발 환경 토큰 갱신 실패](#auth-01-refresh-token-쿠키-secure-플래그로-인한-로컬-개발-환경-토큰-갱신-실패)
8. [AUTH-02: 로그아웃 후 Access Token 무효화 미구현](#auth-02-로그아웃-후-access-token-무효화-미구현)
9. [개선 전후 안정성 점수 비교](#개선-전후-안정성-점수-비교)
10. [GitHub Issue 템플릿 요약](#github-issue-템플릿-요약)

---

## SEC-01: CORS allow_origins 와일드카드(*) + Credentials 동시 허용

### [Phenomenon] 현상

브라우저 DevTools에서 확인 시, 임의 Origin에서 `credentials: include` 요청이 성공. `Access-Control-Allow-Origin: *`과 `Access-Control-Allow-Credentials: true`가 동시에 반환됨.

악성 사이트(`https://evil.com`)에서 다음 코드로 인증된 사용자의 데이터 탈취 가능:
```javascript
fetch('https://api.q-guarder.com/api/v1/users/me/scan-logs', {
  credentials: 'include'
}).then(r => r.json()).then(data => sendToAttacker(data));
```

### [Root Cause] 원인 분석

FastAPI `CORSMiddleware`에서 `allow_origins=["*"]`와 `allow_credentials=True`를 동시 설정. **RFC 6454(Same-Origin Policy)** 위반이며, 브라우저는 이 조합을 기술적으로 허용하지 않지만, 일부 구현에서는 와일드카드를 요청 Origin으로 미러링하여 **실질적으로 모든 도메인을 허용**하는 동작이 발생.

### [Resolution] 해결책

`app/core/config.py`에 `CORS_ORIGINS` 환경변수 추가, `app/main.py`에서 쉼표 구분 파싱:

```python
# config.py
CORS_ORIGINS: str = ""  # "https://app.example.com,https://admin.example.com"

# main.py
_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_credentials=True, ...)
```

### [Security/Operational Impact] 보안 및 운영 영향

- **Cookie 탈취 방어**: HttpOnly Refresh Token이 **허가된 도메인에서만** 자동 전송. CSRF(Cross-Site Request Forgery) 공격 벡터 차단.
- **OWASP A01:2021 (Broken Access Control)** 직접 대응.

---

## SEC-02: Report API IDOR(Broken Object Level Authorization) 취약점

### [Phenomenon] 현상

인증된 사용자 A가 사용자 B의 `scan_log_id`를 추측하여 `POST /api/v1/report` 요청 시, **B의 스캔 기록을 기반으로 KISA 허위 신고**가 가능. 시스템은 `scan_log_id`의 존재만 확인하고, 해당 스캔이 요청자의 것인지 검증하지 않음.

```bash
# 공격 시나리오: 사용자 A가 B의 scan_log_id로 신고
curl -X POST /api/v1/report \
  -H "Authorization: Bearer <user_A_token>" \
  -d '{"scan_log_id": "<user_B_scan_id>", "url": "https://naver.com", "reason": "허위 신고"}'
# → 200 OK (신고 접수됨 + KISA에 거짓 신고 발송 가능)
```

### [Root Cause] 원인 분석

`app/api/v1/report.py`의 `report_url()` 함수에서 `scan_log_id`로 스캔 기록을 조회한 후, **`scan_log.user_id`와 `current_user_id`의 일치 여부를 검증하지 않음**. 이는 **OWASP API Security Top 10의 API1:2023 Broken Object Level Authorization (BOLA)** 에 해당하는 취약점.

UUID v4의 추측 가능성은 낮지만, API 응답이나 로그에서 다른 사용자의 `scan_id`가 유출될 수 있으며, 방어적 프로그래밍 관점에서 반드시 소유자 검증이 필요.

### [Resolution] 해결책

스캔 로그 조회 직후 소유자 검증 로직 추가:

```python
# app/api/v1/report.py
scan_log = await crud_scan.get_scan_log_by_id(db, uuid.UUID(body.scan_log_id))
if not scan_log:
    raise HTTPException(status_code=404, detail="해당 스캔 기록을 찾을 수 없습니다.")

# 소유자 검증 — 본인의 스캔 기록만 신고 가능
if str(scan_log.user_id) != current_user_id:
    raise HTTPException(status_code=403, detail="본인의 스캔 기록만 신고할 수 있습니다.")
```

### [Security/Operational Impact] 보안 및 운영 영향

- **허위 신고 방지**: 타 사용자 명의의 스캔 기록으로 KISA 자동 신고 메일이 발송되는 것을 원천 차단.
- **BOLA/IDOR 방어**: Zero-Trust 원칙에 따라 "리소스 소유권은 항상 서버에서 검증"하는 패턴 적용. 토큰의 `sub` 파라미터와 리소스의 `user_id`를 명시적으로 비교.
- **OWASP API1:2023** 직접 대응.

---

## SEC-03: Scan API 에러 바운더리 미비로 인한 스택트레이스 노출

### [Phenomenon] 현상

`analyze_url()` 내부에서 예외 발생 시(ML 모델 로딩 실패, VT 파싱 오류 등) FastAPI 기본 500 응답이 반환. Production에서 `debug=False`여도 응답 body에 `"Internal Server Error"` 외에 로그에 **전체 스택트레이스가 기록**되어 민감한 파일 경로, 모듈 구조 등이 노출 가능.

### [Root Cause] 원인 분석

`app/api/v1/scan.py`의 `scan_url()` 핸들러에서 `analyze_url(body.url)` 호출 주변에 **try/except 블록이 없음**. 하이브리드 엔진 내부의 예외가 핸들러를 관통하여 FastAPI의 기본 Exception Handler까지 전파됨.

### [Resolution] 해결책

```python
try:
    result = await analyze_url(body.url)
except Exception:
    logger.exception("하이브리드 엔진 분석 실패: %s", body.url)
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="URL 분석 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
    )
```

### [Security/Operational Impact] 보안 및 운영 영향

- **정보 유출 방지**: 내부 스택트레이스, 모듈 경로, 서버 설정값 등이 응답에 노출되지 않음.
- **Graceful Degradation**: 사용자에게 의미 있는 에러 메시지(502) 반환. 클라이언트가 재시도 로직을 구현할 수 있는 명확한 상태 코드 제공.

---

## ASYNC-01: asyncio.get_event_loop() Deprecation으로 인한 런타임 충돌

### [Phenomenon] 현상

Python 3.10+에서 `DeprecationWarning: There is no current event loop` 발생. Python 3.12+에서는 **`RuntimeError`로 승격**되어 큐 프로세서가 즉시 실패하며 FeedbackQueue 전체 미처리 상태 유지.

### [Root Cause] 원인 분석

`background/queue_processor.py`의 실행 코드에서 `asyncio.get_event_loop().run_until_complete()`를 사용. Python 3.10 이후 메인 스레드에 기본 이벤트 루프가 자동 생성되지 않으며, `asyncio.get_event_loop()`는 실행 중인 루프가 없으면 Deprecation 경고 → 3.12에서 `RuntimeError`를 발생.

### [Resolution] 해결책

```python
# AS-IS (Deprecated)
result = asyncio.get_event_loop().run_until_complete(process_feedback_queue())

# TO-BE (최신 표준)
result = asyncio.run(process_feedback_queue())
```

`asyncio.run()`은 새 이벤트 루프를 안전하게 생성하고 코루틴 완료 후 정리하므로 Python 전 버전에서 호환.

### [Security/Operational Impact] 보안 및 운영 영향

- **Python 3.12+ 호환성**: Python 3.12 이상에서도 안전하게 동작.
- **FeedbackQueue 처리 보장**: 런타임 에러로 인한 큐 프로세서 전체 실패 방지 → KISA 자동 신고 파이프라인 안정성 확보.

---

## SEC-04: URL 스키마 검증 부재 — XSS 벡터 유입 가능

### [Phenomenon] 현상

`POST /api/v1/scan/url` 요청 시 `url` 필드에 `javascript:alert(1)`, `data:text/html,...`, `file:///etc/passwd` 등의 위험 스키마가 입력될 수 있음. 해당 URL이 DB에 저장된 후 클라이언트(모바일 앱/웹 대시보드)에서 렌더링 시 **Stored XSS** 또는 **로컬 파일 유출** 벡터로 활용 가능.

### [Root Cause] 원인 분석

`app/schemas/scan_schema.py`의 `ScanUrlRequest`에 `max_length=2048` 제한만 존재하고, **URL 스키마(프로토콜) 검증이 없음**. Pydantic v2의 `AnyHttpUrl` 타입도 미사용.

### [Resolution] 해결책

```python
class ScanUrlRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    source: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL은 http:// 또는 https://로 시작해야 합니다.")
        return v
```

### [Security/Operational Impact] 보안 및 운영 영향

- **XSS 벡터 차단**: `javascript:`, `data:`, `vbscript:` 등의 위험 스키마가 DB에 저장되는 것을 입력 단계에서 원천 차단.
- **입력 검증 심층 방어(Defense in Depth)**: Pydantic Schema → API → DB 순서로 다계층 검증 확보.

---

## SEC-05: verify_password 예외 미처리로 인한 인증 우회 가능성

### [Phenomenon] 현상

DB에 저장된 `password_hash` 값이 손상되거나 비표준 형식일 경우, `passlib.context.CryptContext.verify()`가 `ValueError` 또는 `UnknownHashError`를 발생. 이 예외가 로그인 핸들러(`app/api/v1/auth.py`)까지 전파되어 **500 Internal Server Error** 반환.

### [Root Cause] 원인 분석

`app/core/security.py`의 `verify_password()` 함수가 `pwd_context.verify()`를 try/except 없이 직접 호출. passlib은 인식 불가능한 해시 형식에 대해 예외를 발생시키며, 이는 DB 마이그레이션 오류나 해시 알고리즘 변경 시 발생 가능.

### [Resolution] 해결책

```python
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False
```

### [Security/Operational Impact] 보안 및 운영 영향

- **Fail-Closed 원칙**: 예외 발생 시 `False`를 반환하여 인증을 거부. 예외가 인증 우회로 이어지지 않음.
- **운영 안정성**: DB 해시 손상이라는 엣지 케이스에서도 500 대신 정상적인 401 Unauthorized가 반환됨.

---

## 개선 전후 안정성 점수 비교

### 앱 코드 보안 핫픽스 (7건)

| 평가 항목 | 핫픽스 전 | 핫픽스 후 |
|-----------|-----------|-----------|
| 인증/인가 | 7.0 | 9.0 |
| 입력 검증 | 7.5 | 9.0 |
| 에러 핸들링 | 5.0 | 8.0 |
| CORS 보안 | 2.0 | 9.0 |
| SQL Injection | 10.0 | 10.0 |
| 데이터 무결성 | 9.0 | 9.0 |
| API 스펙 정합성 | 10.0 | 10.0 |
| 비동기 안정성 | 6.0 | 8.5 |
| **앱 코드 종합** | **7.1 / 10** | **9.1 / 10** |

---

## GitHub Issue 템플릿 요약

아래 내용을 GitHub Issue로 복사하여 사용할 수 있습니다.

---

### Issue Template: SEC-01 ~ SEC-05, ASYNC-01

```markdown
## 🔒 [Security] Zero-Trust 보안 감사 핫픽스 — IDOR, CORS, Input Validation

### Summary
Zero-Trust 원칙 기반 보안 감사에서 발견된 앱 코드 취약점 7건을 해결합니다.
안정성 점수 7.1 → 9.1 개선.

### Issues Resolved

#### SEC-01: CORS 와일드카드 + Credentials (위험도: 🔴 상)
- OWASP A01:2021 Broken Access Control 대응
- allow_origins=["*"] → CORS_ORIGINS 환경변수 기반 화이트리스트

#### SEC-02: Report API IDOR 취약점 (위험도: 🔴 상)
- OWASP API1:2023 Broken Object Level Authorization 대응
- scan_log.user_id != current_user_id 소유자 검증 추가

#### SEC-03: Scan API 에러 바운더리 (위험도: 🟠 중)
- analyze_url() try/except 래핑, 502 Bad Gateway 응답

#### SEC-04: URL 스키마 검증 (위험도: 🟡 하)
- Pydantic field_validator로 http/https 스키마 강제

#### SEC-05: verify_password 예외 방어 (위험도: 🟡 하)
- Fail-Closed 원칙: 예외 시 False 반환

#### ASYNC-01: asyncio.get_event_loop() Deprecation (위험도: 🟠 중)
- asyncio.run() 표준 패턴으로 교체

### Changed Files
- `app/main.py` — CORS 화이트리스트
- `app/core/config.py` — CORS_ORIGINS 환경변수
- `app/core/security.py` — verify_password try/except
- `app/api/v1/report.py` — 소유자 검증 (403)
- `app/api/v1/scan.py` — 에러 바운더리 (502)
- `app/schemas/scan_schema.py` — URL 스키마 validator
- `background/queue_processor.py` — asyncio.run()

### Labels
`security` `hotfix` `OWASP` `zero-trust`
```

---

## AUTH-01: Refresh Token 쿠키 Secure 플래그로 인한 로컬 개발 환경 토큰 갱신 실패

### [Phenomenon] 현상

로컬 개발 환경(HTTP, `localhost:8000`)에서 로그인 후 `POST /api/v1/auth/refresh` 호출 시 **401 Unauthorized** 응답 발생:

```json
{"detail": "Refresh token이 없습니다."}
```

로그인 응답의 `Set-Cookie` 헤더에는 Refresh Token이 정상적으로 포함되어 있으나, 브라우저/httpx가 후속 요청에 쿠키를 전송하지 않음.

### [Root Cause] 원인 분석

`app/api/v1/auth.py`의 로그인 엔드포인트에서 쿠키 설정 시 `secure=True`가 하드코딩되어 있었음:

```python
response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,
    secure=True,        # ← HTTPS에서만 쿠키 전송
    samesite="strict",
    path="/",
)
```

HTTP 프로토콜에서는 `Secure` 플래그가 설정된 쿠키를 브라우저가 전송하지 않는 것이 RFC 6265 표준 동작임. 프로덕션(HTTPS)에서는 정상 동작하지만, 로컬 개발(HTTP)에서는 토큰 갱신이 불가능.

### [Resolution] 해결책

**1. `COOKIE_SECURE` 환경변수 도입 (`app/core/config.py`)**

```python
COOKIE_SECURE: bool = True  # 프로덕션: True, 로컬: False
```

**2. 쿠키 설정에서 환경변수 참조 (`app/api/v1/auth.py`)**

```python
settings = get_settings()
response.set_cookie(
    key="refresh_token",
    value=refresh_token,
    httponly=True,
    secure=settings.COOKIE_SECURE,
    samesite="strict" if settings.COOKIE_SECURE else "lax",
    path="/",
)
```

**3. `.env` 설정**

```env
# 로컬 개발
COOKIE_SECURE=False

# 프로덕션 (HTTPS)
COOKIE_SECURE=True
```

### Changed Files
- `app/core/config.py` — `COOKIE_SECURE` 설정 추가
- `app/api/v1/auth.py` — 로그인/로그아웃 쿠키 Secure 플래그 환경변수화
- `.env.example` — `COOKIE_SECURE` 설명 추가

---

## AUTH-02: 로그아웃 후 Access Token 무효화 미구현

### [Phenomenon] 현상

`POST /api/v1/auth/logout` 호출 후에도 기존 Access Token으로 인증 필요 API를 정상적으로 호출 가능:

```
POST /api/v1/auth/logout → 200 {"message": "logged out"}
GET /api/v1/users/me/scan-logs → 200 (토큰 여전히 유효!)
```

로그아웃 후에도 JWT Access Token이 만료 시간(30분)까지 계속 사용 가능하여 보안 취약점 존재.

### [Root Cause] 원인 분석

`get_current_user_id()` 함수가 JWT 토큰의 서명과 만료시간만 검증하고, DB에서 사용자의 로그인 상태를 확인하지 않았음:

```python
# AS-IS: JWT 서명만 검증
def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(401, "Access token required")
    return payload["sub"]  # DB 검증 없음
```

로그아웃 시 `refresh_token`을 `None`으로 설정하지만, Access Token은 stateless JWT이므로 서버가 즈시 무효화할 수 없었음.

### [Resolution] 해결책

`get_current_user_id()`에 DB 세션 의존성을 추가하여 로그아웃/비활성화 사용자의 토큰을 차단:

```python
# TO-BE: JWT 서명 + DB 로그아웃 검증
async def get_current_user_id(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> str:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(401, "Access token required")
    user_id = payload["sub"]

    # DB 검증: refresh_token=None(로그아웃) 또는 비활성 사용자 차단
    from app.crud import crud_user
    user = await crud_user.get_user_by_id(db, uuid.UUID(user_id))
    if not user or not user.is_active or user.refresh_token is None:
        raise HTTPException(401, "Token has been revoked")

    return user_id
```

**트레이드오프**: 매 요청마다 DB 조회 1회 추가 (SELECT users WHERE id = ?). 대규모 서비스에서는 Redis 토큰 블랙리스트로 대체 가능.

### Changed Files
- `app/core/security.py` — `get_current_user_id()` async 전환 + DB 검증 로직 추가

---

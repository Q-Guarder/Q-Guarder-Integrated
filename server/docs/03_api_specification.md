# Q-Guard API Specification v3.0


## 1. Auth (인증)
사용자 계정 생성 및 JWT(Access/Refresh) 토큰 기반 인증 관리

### `POST /api/v1/auth/register`
* **설명:** 신규 회원 가입
* **Request (Body):**
```json
{
  "email": "user@example.com",
  "password": "securepassword123!",
  "nickname": "QGuardUser"
}
```
* **Response (201 Created):**
```json
{
  "user_id": "uuid-string",
  "email": "user@example.com",
  "nickname": "QGuardUser",
  "created_at": "2025-03-10T10:00:00Z"
}
```

### `POST /api/v1/auth/login`
* **설명:** 로그인 및 토큰 발급 (Refresh Token은 HttpOnly 쿠키로 설정)
* **Request (Body):**
```json
{
  "email": "user@example.com",
  "password": "securepassword123!"
}
```
* **Response (200 OK):**
```json
{
  "access_token": "jwt-access-token-string",
  "token_type": "bearer"
}
```
* **Headers:** `Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict`

### `POST /api/v1/auth/refresh`
* **설명:** Access Token 만료 시 재발급
* **Request (Headers):** `Cookie: refresh_token=...`
* **Response (200 OK):**
```json
{
  "access_token": "new-jwt-access-token-string",
  "token_type": "bearer"
}
```

### `POST /api/v1/auth/logout`
* **설명:** 로그아웃 (서버 내 Refresh Token 무효화 및 쿠키 삭제)
* **Request (Headers):** `Authorization: Bearer <access_token>`
* **Response (200 OK):**
```json
{
  "message": "logged out"
}
```
* **Headers:** `Set-Cookie: refresh_token=; Max-Age=0`

---

## 2. Scan (검사)
QR 스캔 시 URL의 위험도를 실시간으로 분석 (LightGBM + VirusTotal)

### `POST /api/v1/scan/url` (JWT Required)
* **설명:** URL 위험도 분석 (하이브리드 엔진 적용)
* **Request (Body):**
```json
{
  "url": "[http://secure-update-192.168.0.1.xyz/auth](http://secure-update-192.168.0.1.xyz/auth)",
  "source": "camera"
}
```
* **Response (200 OK):**
```json
{
  "scan_id": "uuid-string",
  "url": "[http://secure-update-192.168.0.1.xyz/auth](http://secure-update-192.168.0.1.xyz/auth)",
  "risk_level": "BLOCKED",
  "final_score": 0.87,
  "vt_total_engines": 94,
  "vt_detected_engines": 3,
  "xai_features": {
    "is_shortened_url": {"value": 1, "contribution": 0.35},
    "ratio_url_encoded": {"value": 0.25, "contribution": 0.21},
    "contains_update": {"value": 1, "contribution": 0.18}
  },
  "scanned_at": "2025-03-10T10:05:38Z"
}
```

---

## 3. Report (신고 및 피드백)
오탐지 신고

### `POST /api/v1/report`
* **설명:** 사용자가 URL을 악성으로 신고 (Feedback Queue 적재 후, 신규 악성 URL일 경우 AWS SES를 이용해서 KISA로 자동 신고)
* **Request (Body):**
```json
{
  "scan_log_id": "uuid-string",
  "url": "[https://m.naver.com](https://m.naver.com)",
  "reason": "네이버로 위장한 교묘한 피싱 같습니다."
}
```
* **Response (200 OK):**
```json
{
  "report_id": "uuid-string",
  "status": "queued",
  "message": "신고가 접수되어 추가 검증을 진행합니다."
}
```

---

## 4. User Log (사용자 기록 및 대시보드)
스캔 통계, 즐겨찾기(안심 URL), 실제 접속 이력 관리

### `GET /api/v1/users/me/scan-logs`
* **설명:** 내 스캔 이력 및 보안 통계 조회 (대시보드 UI용)
* **Request:** `?from=2025-03-01&to=2025-03-31`
* **Response (200 OK):**
```json
{
  "summary": {
    "total_scans": 6,
    "secured_count": 4,
    "blocked_count": 2,
    "reported_count": 1
  },
  "logs": [
    {
      "scan_id": "uuid-string",
      "url": "[http://secure-update-192.168.0.1.xyz](http://secure-update-192.168.0.1.xyz)...",
      "risk_level": "BLOCKED",
      "scanned_at": "2025-03-10T17:38:00Z"
    }
  ]
}
```

### `GET /api/v1/users/me/bookmarks`
* **설명:** 즐겨찾기(안심 URL 화이트리스트) 목록 조회
* **Response (200 OK):**
```json
{
  "items": [
    {
      "bookmark_id": "uuid-string",
      "url": "[https://m.naver.com](https://m.naver.com)",
      "title": "네이버 모바일",
      "risk_level": "SECURED",
      "created_at": "2025-03-09T10:00:00Z"
    }
  ]
}
```

### `POST /api/v1/users/me/bookmarks`
* **설명:** 즐겨찾기 추가
* **Request (Body):**
```json
{
  "url": "[https://m.naver.com](https://m.naver.com)",
  "title": "네이버 모바일"
}
```
* **Response (201 Created):**
```json
{
  "bookmark_id": "uuid-string",
  "created_at": "..."
}
```

### `DELETE /api/v1/users/me/bookmarks/{bookmark_id}`
* **설명:** 즐겨찾기 삭제
* **Response (200 OK):**
```json
{
  "message": "deleted"
}
```

### `POST /api/v1/users/me/visits` [신규]
* **설명:** 스캔 후 실제 웹사이트로 이동(방문) 시 기록 추가
* **Request (Body):**
```json
{
  "url": "[https://m.naver.com](https://m.naver.com)",
  "risk_level": "SECURED"
}
```
* **Response (201 Created):**
```json
{
  "visit_id": "uuid-string",
  "visited_at": "..."
}
```

### `GET /api/v1/users/me/visits`
* **설명:** 과거 방문 기록 조회
* **Request:** `?page=1&size=20`
* **Response (200 OK):**
```json
{
  "items": [
    {
      "url": "[https://m.naver.com](https://m.naver.com)",
      "risk_level": "SECURED",
      "visited_at": "2025-03-10T17:39:00Z"
    }
  ],
  "total": 45
}
```
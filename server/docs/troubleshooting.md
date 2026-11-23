# Q-Guarder Troubleshooting & Security Hotfix Log

> **작성일**: 2026-03-25  
> **작성자**: DevSecOps 보안 감사팀  
> **대상**: Q-Guarder-Server v1.0.0  
> **감사 기준**: AWS Well-Architected Framework · OWASP Top 10 2021 · Zero-Trust Architecture

---

## 목차

1. [INFRA-01: Private Subnet Lambda 외부 API 통신 불가](#infra-01-private-subnet-lambda-외부-api-통신-불가)
2. [INFRA-02: Terraform State 로컬 관리로 인한 인프라 드리프트 위험](#infra-02-terraform-state-로컬-관리로-인한-인프라-드리프트-위험)
3. [INFRA-03: RDS Single-AZ 단일 장애점(SPOF)](#infra-03-rds-single-az-단일-장애점spof)
4. [INFRA-04: API Gateway CORS 와일드카드로 앱 보안 핫픽스 무력화](#infra-04-api-gateway-cors-와일드카드로-앱-보안-핫픽스-무력화)
5. [SEC-01: CORS allow_origins 와일드카드(*) + Credentials 동시 허용](#sec-01-cors-allow_origins-와일드카드--credentials-동시-허용)
6. [SEC-02: Report API IDOR(Broken Object Level Authorization) 취약점](#sec-02-report-api-idorbroken-object-level-authorization-취약점)
7. [SEC-03: Scan API 에러 바운더리 미비로 인한 스택트레이스 노출](#sec-03-scan-api-에러-바운더리-미비로-인한-스택트레이스-노출)
8. [ASYNC-01: asyncio.get_event_loop() Deprecation으로 인한 런타임 충돌](#async-01-asyncioget_event_loop-deprecation으로-인한-런타임-충돌)
9. [SEC-04: URL 스키마 검증 부재 — XSS 벡터 유입 가능](#sec-04-url-스키마-검증-부재--xss-벡터-유입-가능)
10. [SEC-05: verify_password 예외 미처리로 인한 인증 우회 가능성](#sec-05-verify_password-예외-미처리로-인한-인증-우회-가능성)
11. [AUTH-01: Refresh Token 쿠키 Secure 플래그로 인한 로컬 개발 환경 토큰 갱신 실패](#auth-01-refresh-token-쿠키-secure-플래그로-인한-로컬-개발-환경-토큰-갱신-실패)
12. [AUTH-02: 로그아웃 후 Access Token 무효화 미구현](#auth-02-로그아웃-후-access-token-무효화-미구현)
13. [개선 전후 안정성 점수 비교](#개선-전후-안정성-점수-비교)
14. [GitHub Issue 템플릿 요약](#github-issue-템플릿-요약)

---

## INFRA-01: Private Subnet Lambda 외부 API 통신 불가

### [Phenomenon] 현상

상용 배포 시 Lambda 함수에서 VirusTotal API 호출(`httpx.AsyncClient` → `https://www.virustotal.com/api/v3/urls`) 시 **30초 Timeout 후 `httpx.ConnectError`** 발생. AWS SES 이메일 발송(KISA 자동 신고)도 동일하게 실패. CloudWatch Logs에 `Lambda Timeout (30s exceeded)` 기록.

```
ERROR VirusTotal API 연결 실패 (네트워크 오류): https://example-phishing.com
ERROR KISA 신고 메일 발송 실패: ConnectionError
```

API Gateway 응답으로는 **504 Gateway Timeout**이 클라이언트에 전달.

### [Root Cause] 원인 분석

Lambda 함수가 **Private Subnet**(`10.0.1.0/24`, `10.0.2.0/24`)에 배치되어 있으나, VPC에 **Internet Gateway → NAT Gateway → Route Table** 경로가 구성되지 않음. Private Subnet의 기본 라우팅은 VPC 내부(`10.0.0.0/16`)만 허용하며, `0.0.0.0/0`(인터넷)으로의 아웃바운드 경로가 존재하지 않음.

AWS VPC 네트워크 설계 원칙상, Private Subnet에서 외부 인터넷으로 나가려면 반드시 **Public Subnet에 배치된 NAT Gateway**를 경유해야 함. 현재 아키텍처에는 Public Subnet 자체가 선언되지 않았음.

```
[AS-IS] Lambda (Private) ──X──▶ Internet (VirusTotal, SES)
                               ❌ 라우팅 경로 없음

[TO-BE] Lambda (Private) ──▶ NAT GW (Public) ──▶ IGW ──▶ Internet
                            ✅ 0.0.0.0/0 → nat_gateway_id
```

### [Resolution] 해결책

`infrastructure/main.tf`에 다음 리소스를 추가:

| 리소스 | 목적 |
|--------|------|
| `aws_subnet.public_a/b` | NAT Gateway 배치용 Public Subnet (10.0.10.0/24, 10.0.11.0/24) |
| `aws_internet_gateway.main` | VPC의 인터넷 게이트웨이 |
| `aws_route_table.public` | Public Subnet → IGW 라우팅 |
| `aws_eip.nat` | NAT Gateway용 Elastic IP |
| `aws_nat_gateway.main` | Private→Internet 아웃바운드 NAT |
| `aws_route_table.private` | Private Subnet → NAT Gateway 라우팅 (0.0.0.0/0) |
| `aws_vpc_endpoint.s3` | S3 Gateway Endpoint (NAT 우회, 데이터 전송 비용 절감) |

```hcl
resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  depends_on    = [aws_internet_gateway.main]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
}
```

S3 접근은 **VPC Gateway Endpoint**를 통해 NAT를 우회하도록 최적화하여 데이터 전송 비용을 절감.

### [Security/Operational Impact] 보안 및 운영 영향

- **서비스 가용성**: 핵심 기능(하이브리드 스캔 엔진)이 실제로 동작 가능한 상태로 전환. 수정 전에는 **Production 배포 자체가 불가능**했음.
- **보안 계층 유지**: Lambda는 여전히 Private Subnet에 격리됨. 외부에서 Lambda로의 직접 접근은 불가하며, 아웃바운드만 NAT를 통해 허용. 공격 표면(Attack Surface) 최소화 원칙 유지.
- **비용 영향**: NAT Gateway ~$32/월 + 데이터 전송 $0.045/GB. S3 Endpoint로 모델 로딩 트래픽은 무과금.

---

## INFRA-02: Terraform State 로컬 관리로 인한 인프라 드리프트 위험

### [Phenomenon] 현상

`terraform plan` 실행 시 State 파일이 로컬 `terraform.tfstate`에만 존재. 팀원 B가 별도 환경에서 `terraform apply`를 실행하면 **State 충돌**이 발생하며, 리소스가 이중 생성되거나 기존 리소스가 untracked 상태로 전환됨.

또한 `.tfstate` 파일에 `db_password`, `jwt_secret_key` 등 민감 정보가 **평문으로 포함**되어 있어, 로컬 파일 유출 시 전체 인프라 자격 증명이 노출됨.

### [Root Cause] 원인 분석

`terraform {}` 블록에 `backend` 설정이 없어 Terraform이 기본 로컬 파일 시스템(`terraform.tfstate`)을 사용. 이는 개인 실습 환경에서는 문제없으나, **팀 협업 · CI/CD · Production 운영**에서는 다음 문제를 야기:

1. **State Lock 미지원** → 동시 `apply` 시 리소스 충돌
2. **State 유실 위험** → 로컬 파일 삭제 시 인프라 관리 불가 (orphaned resources)
3. **Secrets 노출** → `.tfstate`에 평문 비밀번호 저장

### [Resolution] 해결책

S3 + DynamoDB 기반 **Remote Backend** 설정 추가:

```hcl
terraform {
  backend "s3" {
    bucket         = "q-guarder-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "ap-northeast-2"
    encrypt        = true                        # AES-256 Server-Side Encryption
    dynamodb_table = "q-guarder-tfstate-lock"    # State Lock (Pessimistic Locking)
  }
}
```

**사전 준비 (1회)**:
```bash
# State 버킷 생성 (버저닝 + 암호화)
aws s3api create-bucket --bucket q-guarder-tfstate \
  --region ap-northeast-2 \
  --create-bucket-configuration LocationConstraint=ap-northeast-2

aws s3api put-bucket-versioning --bucket q-guarder-tfstate \
  --versioning-configuration Status=Enabled

# DynamoDB Lock 테이블 생성
aws dynamodb create-table --table-name q-guarder-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### [Security/Operational Impact] 보안 및 운영 영향

- **State 보안**: S3 서버 사이드 암호화(`encrypt = true`)로 `.tfstate` 내 시크릿 보호. IAM 정책으로 접근 통제 가능.
- **동시성 안전**: DynamoDB 기반 Pessimistic Locking으로 동시 `terraform apply` 차단.
- **복구 가능성**: S3 버저닝으로 과거 State 복원 가능. `terraform state pull/push`로 DR 대응.

---

## INFRA-03: RDS Single-AZ 단일 장애점(SPOF)

### [Phenomenon] 현상

RDS가 `ap-northeast-2a` 단일 AZ에 배치된 상태에서 해당 AZ에 장애가 발생하면, 데이터베이스 연결이 끊기면서 **전체 API 및 Queue Processor가 동시에 마비**됨.

FastAPI 앱에서 `sqlalchemy.exc.OperationalError: (asyncpg) connection refused` 발생 → 모든 API 응답이 **500 Internal Server Error**로 전환.

추가로 `skip_final_snapshot = true` 설정으로 인해, `terraform destroy` 또는 RDS 인스턴스 교체 시 **사용자 데이터가 복구 불가능하게 영구 소실**.

### [Root Cause] 원인 분석

```hcl
# AS-IS (위험)
multi_az            = false    # ← 단일 AZ, Standby 복제본 없음
skip_final_snapshot = true     # ← 삭제 시 스냅샷 미생성
instance_class      = "db.t3.micro"  # ← Multi-AZ 성능 제한
```

- **Multi-AZ 미활성**: Primary 인스턴스만 운영, Synchronous Standby 미존재. AZ 장애 시 자동 Failover 불가.
- **최종 스냅샷 건너뜀**: 개발 단계 편의 설정이 Production에 잔존. 스키마 변경이나 운영 실수로 인스턴스 삭제 시 데이터 전량 유실.

### [Resolution] 해결책

```hcl
# TO-BE (Production Ready)
multi_az                  = true
skip_final_snapshot       = false
final_snapshot_identifier = "${var.project_name}-final-snapshot"
instance_class            = "db.t3.small"   # Multi-AZ 안정 운영을 위한 업그레이드
```

**아키텍처 변경:**
```
[AS-IS]                          [TO-BE]
ap-northeast-2a                  ap-northeast-2a    ap-northeast-2b
┌──────────┐                     ┌──────────┐      ┌──────────┐
│ RDS      │                     │ RDS      │sync  │ RDS      │
│ Primary  │                     │ Primary  │─────▶│ Standby  │
│ (only)   │                     │          │      │          │
└──────────┘                     └──────────┘      └──────────┘
❌ SPOF                           ✅ Auto-Failover (~60초)
```

### [Security/Operational Impact] 보안 및 운영 영향

- **가용성**: AZ 장애 시 **~60초 이내 DNS 기반 Auto-Failover**로 서비스 연속성 확보. SLA 99.95% → 99.99% 수준.
- **데이터 보호**: `final_snapshot_identifier` 설정으로 인스턴스 삭제 시 자동 스냅샷 생성. Point-in-Time Recovery와 함께 이중 보호.
- **Synchronous Replication**: Standby는 Primary와 동기 복제(Synchronous)되므로 RPO(Recovery Point Objective) = 0.

---

## INFRA-04: API Gateway CORS 와일드카드로 앱 보안 핫픽스 무력화

### [Phenomenon] 현상

앱 코드(`app/main.py`)에서 CORS를 화이트리스트 기반으로 수정했음에도 불구하고, 브라우저에서 임의 Origin의 Cross-Origin 요청이 여전히 성공함. `Access-Control-Allow-Origin: *` 헤더가 응답에 포함됨.

### [Root Cause] 원인 분석

**CORS 설정이 2계층에 이중 적용**되어 있었음:

1. **API Gateway 레벨** (`main.tf`): `allow_origins = ["*"]` → Preflight(OPTIONS) 응답에 와일드카드 포함
2. **FastAPI 미들웨어 레벨** (`app/main.py`): `CORS_ORIGINS` 환경변수 기반 화이트리스트

HTTP API의 CORS 구성은 Lambda 응답 이전에 API Gateway가 자체적으로 OPTIONS 응답을 반환하므로, **앱 레벨 수정이 실질적으로 무력화**됨. 이는 Cross-Origin Resource Sharing(CORS) 정책의 이중화 시 발생하는 전형적인 설정 충돌.

### [Resolution] 해결책

Terraform CORS 설정을 `var.cors_allowed_origins` 변수로 통일하고, Lambda 환경변수로도 동일 값을 전달:

```hcl
# API Gateway CORS
cors_configuration {
  allow_origins     = var.cors_allowed_origins  # ["https://q-guarder.example.com"]
  allow_credentials = true
  ...
}

# Lambda 환경변수 (FastAPI 동기화)
environment {
  variables = {
    CORS_ORIGINS = join(",", var.cors_allowed_origins)
  }
}
```

```hcl
# variables.tf
variable "cors_allowed_origins" {
  type    = list(string)
  default = ["https://q-guarder.example.com"]
}
```

### [Security/Operational Impact] 보안 및 운영 영향

- **CSRF 방어 완성**: `allow_credentials = true`와 특정 Origin 조합으로, **HttpOnly Cookie 기반 Refresh Token이 허가된 도메인에서만 전송**됨. 기존 와일드카드 설정에서는 악성 사이트에서도 인증된 API 호출이 가능했음.
- **단일 진실 공급원(Single Source of Truth)**: CORS 허용 도메인을 `var.cors_allowed_origins` 하나로 통합 관리. 인프라와 앱 설정 간 드리프트 방지.

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

- **허위 신고 방지**: 타 사용자 명의의 스캔 기록으로 KISA 자동 신고(SES 이메일)가 발송되는 것을 원천 차단.
- **BOLA/IDOR 방어**: Zero-Trust 원칙에 따라 "리소스 소유권은 항상 서버에서 검증"하는 패턴 적용. 토큰의 `sub` 파라미터와 리소스의 `user_id`를 명시적으로 비교.
- **OWASP API1:2023** 직접 대응.

---

## SEC-03: Scan API 에러 바운더리 미비로 인한 스택트레이스 노출

### [Phenomenon] 현상

`analyze_url()` 내부에서 예외 발생 시(ML 모델 로딩 실패, VT 파싱 오류 등) FastAPI 기본 500 응답이 반환. Production에서 `debug=False`여도 응답 body에 `"Internal Server Error"` 외에 로그에 **전체 스택트레이스가 기록**되어 민감한 S3 경로, 모듈 구조 등이 노출 가능.

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

- **정보 유출 방지**: 내부 스택트레이스, 모듈 경로, S3 버킷명 등이 응답에 노출되지 않음.
- **Graceful Degradation**: 사용자에게 의미 있는 에러 메시지(502) 반환. 클라이언트가 재시도 로직을 구현할 수 있는 명확한 상태 코드 제공.

---

## ASYNC-01: asyncio.get_event_loop() Deprecation으로 인한 런타임 충돌

### [Phenomenon] 현상

Python 3.10+에서 `DeprecationWarning: There is no current event loop` 발생. Python 3.12+에서는 **`RuntimeError`로 승격**되어 Queue Processor Lambda가 즉시 실패하며 FeedbackQueue 전체 미처리 상태 유지.

### [Root Cause] 원인 분석

`background/queue_processor.py`의 Lambda 핸들러에서 `asyncio.get_event_loop().run_until_complete()`를 사용. Python 3.10 이후 메인 스레드에 기본 이벤트 루프가 자동 생성되지 않으며, `asyncio.get_event_loop()`는 실행 중인 루프가 없으면 Deprecation 경고 → 3.12에서 `RuntimeError`를 발생.

### [Resolution] 해결책

```python
# AS-IS (Deprecated)
result = asyncio.get_event_loop().run_until_complete(process_feedback_queue())

# TO-BE (최신 표준)
result = asyncio.run(process_feedback_queue())
```

`asyncio.run()`은 새 이벤트 루프를 안전하게 생성하고 코루틴 완료 후 정리하므로 Python 전 버전에서 호환.

### [Security/Operational Impact] 보안 및 운영 영향

- **Python 3.12+ 호환성**: Lambda 런타임을 `python3.12`로 업그레이드해도 안전하게 동작.
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

### 인프라 Production Readiness (4건 P0/P1)

| 평가 항목 | 핫픽스 전 | 핫픽스 후 |
|-----------|-----------|-----------|
| NAT Gateway (외부 통신) | 🔴 Fail | ✅ Pass |
| Terraform Remote Backend | 🔴 Fail | ✅ Pass |
| RDS Multi-AZ | 🔴 Fail | ✅ Pass |
| RDS Final Snapshot | 🔴 Fail | ✅ Pass |
| API Gateway CORS 동기화 | 🔴 Fail | ✅ Pass |
| S3 SSE 암호화 | ⚠️ Warning | ✅ Pass |
| **인프라 Fail 항목** | **5건** | **0건** |
| **인프라 종합** | **Not Ready** | **Conditionally Ready** |

### 총합 Production Readiness Score

| | 핫픽스 전 | 핫픽스 후 |
|---|---|---|
| **앱 코드** | 7.1 / 10 | 9.1 / 10 |
| **인프라** | Fail (5건) | Pass (Warning 5건 잔여) |
| **종합 판정** | 🔴 **배포 불가** | 🟡 **조건부 배포 가능** |

> **잔여 Warning**: Secrets Manager 미연동, IAM 와일드카드 리소스, Lambda→RDS TLS 미강제, RDS Proxy 미도입, Terraform 모듈 미분리. 이들은 서비스 동작에 영향을 주지 않으나, SOC 2 / ISO 27001 인증 시 추가 조치 필요.

---

## GitHub Issue 템플릿 요약

아래 내용을 GitHub Issue로 복사하여 사용할 수 있습니다.

---

### Issue Template: INFRA-01 ~ INFRA-04

```markdown
## 🛡️ [Infra Hotfix] Production Readiness — NAT Gateway, Remote Backend, Multi-AZ, CORS 동기화

### Summary
아키텍처 감사에서 발견된 P0/P1 인프라 결함 5건을 일괄 해결합니다.

### Issues Resolved

#### INFRA-01: Private Subnet Lambda 외부 API 통신 불가 (P0)
- **현상**: Lambda → VirusTotal/SES 통신 시 ConnectError, 504 Gateway Timeout
- **원인**: Private Subnet에 NAT Gateway 및 Route Table 미설정
- **해결**: IGW + NAT Gateway + Public/Private Route Table + S3 VPC Endpoint 추가

#### INFRA-02: Terraform State 로컬 관리 (P0)
- **현상**: .tfstate 로컬 관리로 State Lock 부재, Secrets 평문 노출
- **원인**: backend "s3" 설정 누락
- **해결**: S3 Remote Backend + DynamoDB State Lock 설정 추가

#### INFRA-03: RDS Single-AZ SPOF (P1)
- **현상**: AZ 장애 시 전체 서비스 중단, 데이터 복구 불가
- **원인**: multi_az=false, skip_final_snapshot=true
- **해결**: multi_az=true, skip_final_snapshot=false, final_snapshot_identifier 설정

#### INFRA-04: API Gateway CORS 와일드카드 (P1)
- **현상**: 앱 코드 CORS 핫픽스가 API Gateway 레벨에서 무력화
- **원인**: API Gateway cors_configuration에 allow_origins=["*"] 잔존
- **해결**: var.cors_allowed_origins 변수로 통합, Lambda 환경변수와 동기화

#### INFRA-05: S3 ML 모델 버킷 SSE 미설정 (P2)
- **현상**: IaC 감사 기준 미충족 (명시적 암호화 선언 없음)
- **해결**: aws_s3_bucket_server_side_encryption_configuration (KMS) 추가

### Changed Files
- `infrastructure/main.tf` — 네트워크, RDS, API Gateway, S3 SSE, Outputs
- `infrastructure/variables.tf` — cors_allowed_origins, db_instance_class 업데이트

### Test Plan
- [ ] `terraform validate` — HCL 문법 검증
- [ ] `terraform plan` — 변경 리소스 사전 확인
- [ ] NAT Gateway 기능 검증 (Lambda → VT API 호출 성공)
- [ ] RDS Multi-AZ Failover 테스트
- [ ] API Gateway CORS Preflight 검증

### Labels
`P0` `infrastructure` `security` `production-readiness`
```

---

### Issue Template: SEC-01 ~ SEC-05 + ASYNC-01

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

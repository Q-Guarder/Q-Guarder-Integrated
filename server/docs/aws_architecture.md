# Q-Guarder AWS 인프라 아키텍처 전체 구조도

> **리전:** `ap-northeast-2` (서울)  
> **IaC:** Terraform ≥ 1.5 / AWS Provider ~> 5.0  
> **환경:** prod (변수로 dev/staging 전환 가능)

---

## 1. 전체 흐름 다이어그램 (ASCII)

```
                        ┌─────────────────────┐
                        │      Client App      │
                        │ (모바일 / 웹 브라우저) │
                        └──────────┬──────────┘
                                   │ HTTPS
                                   ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                         AWS Cloud (ap-northeast-2)                  │
  │                                                                     │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │                    API Gateway (HTTP API)                    │   │
  │  │        q-guarder-api-gateway / $default 스테이지             │   │
  │  │        CORS 설정 / Auto Deploy / AWS_PROXY 통합             │   │
  │  └────────────────────────┬─────────────────────────────────────┘   │
  │                           │ AWS_PROXY                               │
  │                           ▼                                         │
  │  ┌─────────────────────────────────────────────────────────────┐    │
  │  │              VPC: q-guarder-vpc (10.0.0.0/16)               │    │
  │  │                                                             │    │
  │  │  ┌─── Public Subnets ───────────────────────────────────┐   │    │
  │  │  │  public-a (10.0.10.0/24, AZ-a)                      │   │    │
  │  │  │    └─ NAT Gateway ← Elastic IP                      │   │    │
  │  │  │  public-b (10.0.11.0/24, AZ-b)                      │   │    │
  │  │  │                                                      │   │    │
  │  │  │  Route Table: 0.0.0.0/0 → Internet Gateway          │   │    │
  │  │  └──────────────────────────────────────────────────────┘   │    │
  │  │          │ IGW                                              │    │
  │  │          ▼                                                  │    │
  │  │  ┌─── Internet Gateway (q-guarder-igw) ────────────────┐   │    │
  │  │  └─────────────────────────────────────────────────────┘   │    │
  │  │                                                             │    │
  │  │  ┌─── Private Subnets ──────────────────────────────────┐   │    │
  │  │  │  private-a (10.0.1.0/24, AZ-a)                      │   │    │
  │  │  │  private-b (10.0.2.0/24, AZ-b)                      │   │    │
  │  │  │                                                      │   │    │
  │  │  │  Route Table: 0.0.0.0/0 → NAT Gateway               │   │    │
  │  │  │                                                      │   │    │
  │  │  │  ┌─────────────────────────────────────────────┐     │   │    │
  │  │  │  │     Lambda: q-guarder-api-prod              │     │   │    │
  │  │  │  │     (FastAPI + Mangum 래퍼)                  │     │   │    │
  │  │  │  │     Runtime: Python 3.10                    │     │   │    │
  │  │  │  │     Memory: 512 MB / Timeout: 60s           │     │   │    │
  │  │  │  │     Handler: app.main.handler               │     │   │    │
  │  │  │  │     SG: q-guarder-lambda-sg                 │     │   │    │
  │  │  │  │                                             │     │   │    │
  │  │  │  │     ┌─ 환경 변수 ────────────────────┐      │     │   │    │
  │  │  │  │     │ DATABASE_URL (asyncpg)         │      │     │   │    │
  │  │  │  │     │ JWT_SECRET_KEY / JWT_ALGORITHM │      │     │   │    │
  │  │  │  │     │ S3_MODEL_BUCKET / S3_MODEL_KEY│      │     │   │    │
  │  │  │  │     │ SES_SENDER_EMAIL              │      │     │   │    │
  │  │  │  │     │ VIRUSTOTAL_API_KEY            │      │     │   │    │
  │  │  │  │     │ CORS_ORIGINS / AWS_REGION     │      │     │   │    │
  │  │  │  │     └───────────────────────────────┘      │     │   │    │
  │  │  │  └─────────────────────────────────────────────┘     │   │    │
  │  │  │                                                      │   │    │
  │  │  │  ┌─────────────────────────────────────────────┐     │   │    │
  │  │  │  │  Lambda: q-guarder-queue-processor-prod     │     │   │    │
  │  │  │  │  (FeedbackQueue 백그라운드 처리기)            │     │   │    │
  │  │  │  │  Runtime: Python 3.10                       │     │   │    │
  │  │  │  │  Memory: 256 MB / Timeout: 300s             │     │   │    │
  │  │  │  │  Handler: background.queue_processor.handler│     │   │    │
  │  │  │  │  SG: q-guarder-lambda-sg                    │     │   │    │
  │  │  │  └─────────────────────────────────────────────┘     │   │    │
  │  │  │                                                      │   │    │
  │  │  │  ┌─────────────────────────────────────────────┐     │   │    │
  │  │  │  │       RDS PostgreSQL 15.4                   │     │   │    │
  │  │  │  │       인스턴스: db.t3.small                  │     │   │    │
  │  │  │  │       Multi-AZ: ✅ (고가용성)                │     │   │    │
  │  │  │  │       Storage: 20GB (Auto 50GB)             │     │   │    │
  │  │  │  │       암호화: ✅ (storage_encrypted)         │     │   │    │
  │  │  │  │       백업 보존: 7일                         │     │   │    │
  │  │  │  │       Public Access: ❌                      │     │   │    │
  │  │  │  │       SG: q-guarder-rds-sg (5432/tcp)       │     │   │    │
  │  │  │  │       DB Subnet Group: private-a, private-b │     │   │    │
  │  │  │  └─────────────────────────────────────────────┘     │   │    │
  │  │  └──────────────────────────────────────────────────────┘   │    │
  │  │                                                             │    │
  │  │  ┌─── VPC Endpoint ─────────────────────────────────────┐   │    │
  │  │  │  S3 Gateway Endpoint (Private RT 연결)               │   │    │
  │  │  │  → NAT 우회, S3 직접 접근 (비용 절감)                 │   │    │
  │  │  └──────────────────────────────────────────────────────┘   │    │
  │  └─────────────────────────────────────────────────────────────┘    │
  │                                                                     │
  │  ┌─── VPC 외부 AWS 서비스 ─────────────────────────────────────┐    │
  │  │                                                             │    │
  │  │  ┌─────────────────────────────────────────────────┐        │    │
  │  │  │          S3: q-guarder-ml-models                │        │    │
  │  │  │          ML 모델 저장 (model.pkl)                │        │    │
  │  │  │          Versioning: ✅                          │        │    │
  │  │  │          Public Access Block: ✅ All             │        │    │
  │  │  │          암호화: AWS KMS (SSE-KMS + Bucket Key) │        │    │
  │  │  └─────────────────────────────────────────────────┘        │    │
  │  │                                                             │    │
  │  │  ┌─────────────────────────────────────────────────┐        │    │
  │  │  │          AWS SES (Simple Email Service)         │        │    │
  │  │  │          KISA 악성 URL 자동 신고 메일 발송        │        │    │
  │  │  │          수신: cert@kisa.or.kr                   │        │    │
  │  │  │          발신: SES 인증 이메일                    │        │    │
  │  │  └─────────────────────────────────────────────────┘        │    │
  │  │                                                             │    │
  │  │  ┌─────────────────────────────────────────────────┐        │    │
  │  │  │          EventBridge (CloudWatch Events)        │        │    │
  │  │  │          Schedule: rate(5 minutes)              │        │    │
  │  │  │          → Queue Processor Lambda 트리거         │        │    │
  │  │  └─────────────────────────────────────────────────┘        │    │
  │  │                                                             │    │
  │  │  ┌─────────────────────────────────────────────────┐        │    │
  │  │  │          CloudWatch Logs                        │        │    │
  │  │  │          Lambda 실행 로그 수집                    │        │    │
  │  │  └─────────────────────────────────────────────────┘        │    │
  │  │                                                             │    │
  │  │  ┌─────────────────────────────────────────────────┐        │    │
  │  │  │          IAM Role: q-guarder-lambda-role-prod   │        │    │
  │  │  │          정책: Logs / SES / S3 / VPC (ENI)      │        │    │
  │  │  └─────────────────────────────────────────────────┘        │    │
  │  └─────────────────────────────────────────────────────────────┘    │
  │                                                                     │
  │  ┌─── Terraform State 관리 ────────────────────────────────────┐    │
  │  │  S3 Backend: q-guarder-tfstate (암호화)                     │    │
  │  │  DynamoDB Lock: q-guarder-tfstate-lock                      │    │
  │  └─────────────────────────────────────────────────────────────┘    │
  └─────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ NAT Gateway 아웃바운드
                                   ▼
                     ┌──────────────────────────┐
                     │   외부 API (인터넷)        │
                     │  • VirusTotal API v3      │
                     │    (URL 위협 스캔/리포트)   │
                     └──────────────────────────┘
```

---

## 2. AWS 리소스 전체 목록

### 2.1 네트워크 (VPC)

| 리소스 | 이름/식별자 | 설명 |
|--------|------------|------|
| **VPC** | `q-guarder-vpc` | CIDR `10.0.0.0/16`, DNS Support/Hostnames 활성화 |
| **Public Subnet A** | `q-guarder-public-a` | `10.0.10.0/24`, AZ `ap-northeast-2a`, Public IP 자동 할당 |
| **Public Subnet B** | `q-guarder-public-b` | `10.0.11.0/24`, AZ `ap-northeast-2b`, Public IP 자동 할당 |
| **Private Subnet A** | `q-guarder-private-a` | `10.0.1.0/24`, AZ `ap-northeast-2a` |
| **Private Subnet B** | `q-guarder-private-b` | `10.0.2.0/24`, AZ `ap-northeast-2b` |
| **Internet Gateway** | `q-guarder-igw` | VPC 인터넷 연결 |
| **NAT Gateway** | `q-guarder-nat-gw` | Public Subnet A에 배치, Private Subnet 아웃바운드 경로 |
| **Elastic IP** | `q-guarder-nat-eip` | NAT Gateway에 할당된 고정 Public IP |
| **Public Route Table** | `q-guarder-public-rt` | `0.0.0.0/0` → IGW, Public Subnet A/B 연결 |
| **Private Route Table** | `q-guarder-private-rt` | `0.0.0.0/0` → NAT GW, Private Subnet A/B 연결 |
| **S3 Gateway Endpoint** | `q-guarder-s3-endpoint` | Private RT에 연결, NAT 우회하여 S3 직접 접근 (비용 절감) |

### 2.2 보안 그룹 (Security Groups)

| 보안 그룹 | 규칙 | 설명 |
|-----------|------|------|
| **q-guarder-lambda-sg** | Egress: 전체 허용 (`0.0.0.0/0`) | Lambda 함수용 (RDS/외부 API 접근) |
| **q-guarder-rds-sg** | Ingress: `5432/tcp` from `lambda-sg` | RDS PostgreSQL용 (Lambda에서만 접근 허용) |

### 2.3 컴퓨팅 (Lambda)

| Lambda 함수 | 사양 | 역할 |
|-------------|------|------|
| **q-guarder-api-prod** | Python 3.10, 512MB, 60s timeout | FastAPI + Mangum 래퍼, API 서버 메인 함수 |
| **q-guarder-queue-processor-prod** | Python 3.10, 256MB, 300s timeout | FeedbackQueue 미처리 건 VT 재검사 + KISA 자동 신고 |

### 2.4 API Gateway

| 리소스 | 설정 | 설명 |
|--------|------|------|
| **HTTP API** | `q-guarder-api-gateway` | HTTP 프로토콜, `$default` 스테이지 (Auto Deploy) |
| **Integration** | `AWS_PROXY` → API Lambda | Payload Format v2.0, Timeout 30초 |
| **Route** | `$default` | 모든 경로를 Lambda로 프록시 |
| **CORS** | Origins: 변수 지정, Methods: GET/POST/PUT/DELETE/OPTIONS | `Authorization`, `Content-Type` 헤더 허용, Credentials 허용 |

### 2.5 데이터베이스 (RDS)

| 항목 | 값 |
|------|-----|
| **엔진** | PostgreSQL 15.4 |
| **인스턴스 클래스** | `db.t3.small` |
| **Multi-AZ** | ✅ (고가용성) |
| **스토리지** | 20GB (Auto Scaling 최대 50GB) |
| **스토리지 암호화** | ✅ |
| **Public Access** | ❌ |
| **백업 보존 기간** | 7일 |
| **Final Snapshot** | ✅ (`q-guarder-final-snapshot`) |
| **Subnet Group** | Private Subnet A + B |
| **보안 그룹** | `q-guarder-rds-sg` |
| **접속 드라이버** | `asyncpg` (SQLAlchemy Async) |

### 2.6 스토리지 (S3)

| 버킷 | 설정 | 용도 |
|-------|------|------|
| **q-guarder-ml-models** | Versioning ✅, Public Access Block ✅ (전체 차단), SSE-KMS 암호화 + Bucket Key | LightGBM ML 모델 파일 (`models/model.pkl`) 저장 |
| **q-guarder-tfstate** | 암호화 ✅ | Terraform Remote State 저장 (Backend) |

### 2.7 이벤트/스케줄 (EventBridge)

| 리소스 | 설정 | 설명 |
|--------|------|------|
| **EventBridge Rule** | `q-guarder-queue-schedule` | `rate(5 minutes)` 스케줄 |
| **EventBridge Target** | → `queue-processor` Lambda | 5분마다 FeedbackQueue 처리기 트리거 |
| **Lambda Permission** | `AllowEventBridgeInvoke` | EventBridge에서 Lambda 호출 허용 |

### 2.8 이메일 (SES)

| 항목 | 설명 |
|------|------|
| **AWS SES** | KISA(`cert@kisa.or.kr`)로 악성 URL 자동 신고 메일 발송 |
| **발신자** | `SES_SENDER_EMAIL` 변수로 설정 (SES 인증 필요) |
| **트리거** | ① API Lambda: 사용자 신고 시 즉시 발송 ② Queue Processor: VT 재검사 후 탐지 시 자동 발송 |

### 2.9 로깅 (CloudWatch)

| 항목 | 설명 |
|------|------|
| **CloudWatch Logs** | 두 Lambda 함수의 실행 로그 수집 (`CreateLogGroup`, `CreateLogStream`, `PutLogEvents`) |

### 2.10 IAM

| 역할 | 정책 | 설명 |
|------|------|------|
| **q-guarder-lambda-role-prod** | Lambda Assume Role | 두 Lambda 함수 공통 실행 역할 |
| ↳ `lambda-logging` | `logs:CreateLogGroup/Stream`, `logs:PutLogEvents` | CloudWatch Logs 쓰기 |
| ↳ `lambda-ses` | `ses:SendEmail`, `ses:SendRawEmail` | SES 이메일 발송 (KISA 신고) |
| ↳ `lambda-s3` | `s3:GetObject`, `s3:ListBucket` on `q-guarder-ml-models` | ML 모델 다운로드 |
| ↳ `lambda-vpc` | `ec2:Create/Describe/DeleteNetworkInterface` | VPC 내 Lambda ENI 관리 |

### 2.11 Terraform 상태 관리

| 항목 | 값 |
|------|-----|
| **State Backend** | S3 `q-guarder-tfstate` / `prod/terraform.tfstate` |
| **State Lock** | DynamoDB `q-guarder-tfstate-lock` |
| **암호화** | ✅ |

---

## 3. 데이터 흐름 상세

### 3.1 URL 스캔 요청 흐름
```
Client → API Gateway (HTTPS)
       → Lambda API (FastAPI/Mangum)
         ├─ JWT 토큰 검증
         ├─ S3에서 ML 모델 로드 (LightGBM, 메모리 캐싱)  ← S3 Gateway Endpoint
         ├─ ML 추론: URL 위험도 스코어 산출
         ├─ VirusTotal API v3 호출 (NAT Gateway 경유)  ← 외부 인터넷
         ├─ 하이브리드 스코어 계산 (ML + VT 통합)
         ├─ RDS PostgreSQL에 스캔 결과 저장  ← Private Subnet 내부
         └─ 결과 응답 반환 → API Gateway → Client
```

### 3.2 악성 URL 신고 흐름
```
Client → API Gateway → Lambda API
         ├─ 신고 데이터 검증
         ├─ REPORTED_URLS 테이블에 저장 (RDS)
         ├─ FEEDBACK_QUEUE 테이블에 항목 추가 (RDS)
         ├─ 즉시: AWS SES → KISA 자동 신고 메일 발송
         └─ 응답 반환
```

### 3.3 백그라운드 큐 처리 흐름
```
EventBridge (5분 주기)
   → Lambda Queue Processor
      ├─ RDS에서 미처리 FEEDBACK_QUEUE 조회
      ├─ 각 항목별:
      │   ├─ VirusTotal API 재검사 (NAT Gateway 경유)
      │   ├─ 탐지 ≥ 1건 && 미신고 → AWS SES KISA 신고
      │   └─ processed_at 갱신 (RDS)
      └─ 완료 summary 반환
```

---

## 4. 외부 서비스 연동

| 외부 서비스 | 접근 경로 | 용도 |
|-------------|----------|------|
| **VirusTotal API v3** | NAT Gateway → Internet | URL 위협 분석 (스캔 + 리포트) |
| **KISA (cert@kisa.or.kr)** | AWS SES 경유 | 악성 URL 자동 신고 메일 |

---

## 5. 보안 설계 요약

| 항목 | 적용 내용 |
|------|----------|
| **네트워크 격리** | Lambda, RDS 모두 Private Subnet 배치 → 직접 인터넷 노출 없음 |
| **최소 권한 원칙** | IAM 정책별 리소스/액션 한정 (S3는 특정 버킷만, SES는 이메일만) |
| **DB 접근 제어** | RDS SG는 Lambda SG에서만 5432 포트 허용 |
| **S3 보안** | Public Access Block 전체 차단 + KMS 서버사이드 암호화 + 버전 관리 |
| **전송 암호화** | API Gateway HTTPS 강제, RDS storage_encrypted |
| **Secrets** | `db_password`, `jwt_secret_key`, `virustotal_api_key` → Terraform sensitive 변수 |
| **Docker 보안** | non-root 유저(`appuser`) 실행 |
| **S3 접근 최적화** | VPC Gateway Endpoint로 NAT 우회 (비용 절감 + 보안) |

---

## 6. 로컬 개발 환경 (Docker Compose)

프로덕션 AWS 환경과 별도로, 로컬 개발 시에는 Docker Compose를 사용:

| 서비스 | 이미지 | 포트 | 역할 |
|--------|--------|------|------|
| **db** | `postgres:16-alpine` | `5432` | 로컬 PostgreSQL (RDS 대체) |
| **web** | Dockerfile 빌드 | `8000` | Uvicorn 직접 실행 (Hot Reload) |

---

## 7. Terraform Outputs

| Output | 설명 |
|--------|------|
| `api_gateway_url` | API Gateway 엔드포인트 URL |
| `rds_endpoint` | RDS PostgreSQL 접속 엔드포인트 (sensitive) |
| `nat_gateway_ip` | NAT Gateway 퍼블릭 IP (아웃바운드 출구) |
| `s3_model_bucket` | ML 모델 S3 버킷 이름 |
| `api_lambda_name` | API Lambda 함수 이름 |
| `queue_processor_lambda_name` | Queue Processor Lambda 함수 이름 |

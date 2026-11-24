# Q-Guard — QR 코드 큐싱 탐지 시스템

QR 코드에 숨은 피싱 URL(큐싱, Quishing)을 찍는 순간 판별하는 **Android 앱 + FastAPI 서버** 통합본입니다.

앱이 QR에서 읽은 URL을 서버로 보내면, 서버가 **URL 특징 기반 머신러닝 예측**과 **VirusTotal 평판 정보**를 합쳐 결과를 돌려줍니다.

| 판정 | 점수 (0~100) | 앱 화면 |
|---|---|---|
| 🟢 안전 `SECURED` | 45점 미만 | 접속 허용 |
| 🟠 주의 `SUSPICIOUS` | 45 ~ 64점 | 경고 후 선택 |
| 🔴 위험 `BLOCKED` | 65점 이상, 또는 VirusTotal 탐지 비율 5% 이상 | 접속 차단 |

> 📄 **최종 발표자료 · 포스터 · 학술대회 논문(PDF)과 시연용 QR**은 [`docs/`](docs/)에 있습니다.
> 개발 기록(커밋 이력)은 원본 레포 [Q-Guarder-App](https://github.com/Q-Guarder/Q-Guarder-App) · [Q-Guarder-Server](https://github.com/Q-Guarder/Q-Guarder-Server)에 있습니다.

### 목차

1. [빠른 시작](#1-빠른-시작)
2. [디렉터리 구조](#2-디렉터리-구조)
3. [데이터 설명](#3-데이터-설명)
4. [앱과 서버의 API 대응](#4-앱과-서버의-api-대응)
5. [통합 작업과 검증](#5-통합-작업과-검증)
6. [문제 해결과 알아둘 점](#6-문제-해결과-알아둘-점)

---

## 1. 빠른 시작

**필요한 것:** Docker Desktop, Android Studio, VirusTotal 무료 API 키

### 1-1. 서버 실행

`server/` 폴더에서 실행합니다.

```powershell
copy .env.example .env
```

`.env`를 열어 `VIRUSTOTAL_API_KEY=` 뒤에 자기 키를 붙여넣고 저장합니다. 키는 <https://www.virustotal.com/gui/my-apikey>에서 무료로 받을 수 있습니다. 나머지 값은 기본값으로 로컬에서 동작합니다.

```powershell
docker compose up --build
```

브라우저에서 <http://localhost:8000/api/v1/health>를 열어 `"status":"ok"`가 나오면 정상입니다. API 문서는 <http://localhost:8000/docs>에 있습니다.

> ⚠️ **VirusTotal 키는 저장소에 들어 있지 않습니다.** 각자 `server/.env`에 넣어야 합니다.
> 키 없이도 서버는 켜지지만 ML 점수만으로 판정하므로 `https://www.google.com` 같은 정상 사이트도 "위험"으로 나옵니다.

### 1-2. 앱 실행

1. Android Studio에서 **`app/` 폴더**를 엽니다. 맨 위 폴더를 열면 Gradle 프로젝트를 찾지 못합니다.
2. `app/local.properties.example`을 `app/local.properties`로 복사합니다.
   기본값 `BASE_URL=http://10.0.2.2:8000/`은 에뮬레이터에서 본 "같은 PC의 서버" 주소입니다.
3. 에뮬레이터를 고르고 ▶ Run → 회원가입 → 로그인 → QR 스캔.

### 1-3. 연결 확인

| 확인 방법 | 정상일 때 |
|---|---|
| 서버 터미널 로그 | 스캔할 때 `POST /api/v1/scan/url ... 200`이 찍힘 |
| 에뮬레이터 크롬에서 `http://10.0.2.2:8000/api/v1/health` | `"status":"ok"` |
| Android Studio Logcat에서 `okhttp` 검색 | 요청(`-->`)과 응답(`<-- 200`) 본문이 보임 (debug 빌드) |

시연용 QR(안전·주의·위험)은 [`docs/demo_qr/`](docs/demo_qr/)에 있습니다.

---

## 2. 디렉터리 구조

```
Q-Guarder-Integrated/
├─ README.md        이 문서
├─ .gitignore       비밀값(.env, local.properties)과 빌드 산출물 제외
├─ docs/            최종 발표자료 · 포스터 · 학술대회 논문(PDF), 시연용 QR(demo_qr/)
├─ server/          FastAPI 서버 · 학습된 모델 · 실험 데이터
└─ app/             Android 앱 (Kotlin)
```

<details>
<summary><b>server/ 자세히 보기</b></summary>

```
server/
├─ app/                          서버 애플리케이션
│  ├─ main.py                    FastAPI 앱 생성, 라우터 등록, /health, AWS Lambda 핸들러
│  ├─ api/v1/                    HTTP 라우터
│  │  ├─ auth.py                 회원가입 · 로그인 · 토큰 갱신 · 로그아웃
│  │  ├─ scan.py                 URL 위험도 분석 (POST /scan/url)
│  │  ├─ report.py               악성 URL 신고, KISA 신고 백그라운드 작업
│  │  └─ user_logs.py            프로필 · 스캔 이력 · 즐겨찾기 · 방문 기록
│  ├─ services/                  핵심 로직
│  │  ├─ url_features.py         URL 전처리와 26개 특징 추출 (논문 표 1)
│  │  ├─ ensemble_model.py       XGBoost+LightGBM Soft Voting 앙상블 (모델 파일 복원용)
│  │  ├─ s3_loader.py            모델 로딩 (S3 또는 local_models/)
│  │  ├─ fusion.py               ML 예측과 VirusTotal 정보를 합치는 판정 로직
│  │  ├─ hybrid_engine.py        ML 추론 → VirusTotal 조회 → 판정을 묶는 분석 엔진
│  │  ├─ feature_metadata.py     판정 근거(XAI) 한글 설명, 위험도 문구
│  │  └─ kisa_reporter.py        KISA 신고 메일 (KISA_REPORT_ENABLED로 켜고 끔)
│  ├─ schemas/                   요청·응답 형식 (Pydantic) — 앱의 Dtos.kt와 대응
│  ├─ models/                    DB 테이블 정의 (SQLAlchemy)
│  ├─ crud/                      DB 조회·저장 함수
│  ├─ core/                      설정(config.py), 인증·JWT(security.py)
│  └─ db/session.py              DB 세션
├─ background/queue_processor.py 신고 큐 재검증 (운영: EventBridge → Lambda)
├─ local_models/                 학습된 모델 파일 (.pkl)
├─ experiments/                  실험 스크립트(*.py)와 데이터(data/) → 3장 참고
├─ tests/                        서버 단위 테스트 (pytest, 126개)
├─ docs/                         설계 문서 (API 명세, DB 스키마, AWS 구조, 트러블슈팅)
├─ infrastructure/               AWS 배포 Terraform (VPC, RDS, Lambda, API Gateway, S3)
├─ Dockerfile, docker-compose.yml 로컬 실행 (서버 + PostgreSQL)
├─ requirements.txt              Python 의존성
└─ .env.example                  환경 변수 템플릿 (.env로 복사해 사용)
```

</details>

<details>
<summary><b>app/ 자세히 보기</b></summary>

```
app/
├─ app/
│  ├─ build.gradle.kts           모듈 빌드 설정 (BASE_URL을 local.properties에서 읽음)
│  ├─ schemas/                   Room DB 스키마 기록
│  └─ src/
│     ├─ main/java/com/qguarder/android/
│     │  ├─ data/remote/         서버 통신 — ApiService.kt, dto/Dtos.kt, AuthInterceptor.kt, *Repository.kt
│     │  ├─ data/local/          기기 저장소 — Room DB(화이트리스트·즐겨찾기·스캔 캐시), 암호화된 토큰·쿠키
│     │  ├─ di/                  Hilt 모듈 (네트워크, DB)
│     │  ├─ domain/model/        도메인 모델 (RiskLevel, ScanResult 등)
│     │  ├─ ui/                  화면 — splash, login, register, scan, scanning, result, logs, favorites, profile
│     │  └─ util/                입력 검증
│     ├─ main/res/               레이아웃, 문자열, 내비게이션 그래프, 네트워크 보안 설정
│     ├─ debug/                  debug 빌드 전용 (로컬 서버 HTTP 허용)
│     ├─ test/                   JVM 단위 테스트 (47개)
│     └─ androidTest/            계측 테스트
├─ gradle/, gradlew, *.gradle.kts Gradle 래퍼와 빌드 설정
├─ local.properties.example      BASE_URL 설정 템플릿 (local.properties로 복사)
└─ Qushing_Defense_구현명세서_v3.pdf 앱 화면 구현 명세서
```

</details>

---

## 3. 데이터 설명

학술대회 논문 「URL Feature 확장을 통한 머신러닝 기반 QR 코드 큐싱(Quishing) 공격 탐지」(2026 한국멀티미디어학회 춘계학술발표대회, [`docs/학술대회논문.pdf`](docs/학술대회논문.pdf))의 구성을 따릅니다.

- 모든 데이터에서 **label 0 = 정상, 1 = 피싱**입니다.
- 3-1 ~ 3-3은 논문 내용, 3-4 ~ 3-5는 논문 이후 서비스에 적용하면서 확장한 부분입니다.

> ⚠️ 데이터에는 **실제 피싱 URL**이 들어 있습니다. 브라우저로 접속하지 마세요.

### 3-1. 학습 데이터 수집과 전처리 (논문 2.1절)

| 구분 | 출처 | 수집 | 전처리 후 |
|---|---|---:|---:|
| 정상 | Kaggle *Malicious URLs dataset* (크롤러로 수집한 실제 full URL) | 60,000 | **59,960** |
| 피싱 | PhishTank | 56,195 | 55,861 |
| 피싱 | OpenPhish (최신 피싱 URL 구조 반영) | 300 | 298 |
| **합계** | | 116,495 | **116,119** |

**전처리 순서:**
1. 정리: NULL·공백 제거, URL 파싱 실패와 형식이 잘못된 URL 제거
2. 정규화: 도메인 소문자 변환, http/https 처리, 끝의 `/` 정리
3. 정합성: 중복 URL 제거, 같은 URL에 label이 엇갈리는지 검증

| 파일 | 내용 |
|---|---|
| `server/experiments/data/raw/offline_urls.csv` | 전처리를 마친 전체 **116,119건**. 열: `url, label, source(kaggle/phishtank/openphish)` |
| `server/experiments/data/test_feature_dataset.csv` | 테스트 분할 **23,224건**(정상 11,992 / 피싱 11,232). 열: 26개 특징 + `label` (URL 원문 없음) |

### 3-2. 특징 26개 (논문 2.2절, 표 1)

URL의 구조와 문자열 패턴을 나타내는 26개 특징을 5개 분류로 설계했습니다. 추출 코드는 `server/app/services/url_features.py`이며, 아래 이름은 코드와 데이터 파일의 열 이름입니다.

| 분류 | 개수 | 특징 |
|---|---:|---|
| URL 구조 | 9 | `url_length`, `num_dots`, `num_hyphens`, `num_slashes`, `num_digits`, `ratio_digits`, `ratio_special_chars`, `path_length`, `has_at_symbol` |
| 난독화 | 2 | `has_double_slash_anomaly`, `ratio_url_encoded` |
| 도메인 | 4 | `num_subdomains`, `has_ip_address`, `domain_length`, `domain_entropy` |
| 키워드 | 8 | `contains_login`, `contains_verify`, `contains_account`, `contains_secure`, `contains_update`, `contains_bank`, `contains_confirm`, `contains_password` |
| 보안·외부 정보 | 3 | `suspicious_tld`, `brand_similarity`, `is_shortened_url` |

**논문에서 확장한 특징:**
- `domain_entropy`: 특수문자 분포가 아니라 **도메인 문자열 전체**에 Shannon entropy를 적용해 무작위성을 측정합니다.
- `brand_similarity`: 도메인과 정상 브랜드 이름의 **Levenshtein 거리**로 브랜드 사칭을 잡습니다.
- HTTPS 사용 여부는 최근 피싱 URL도 HTTPS를 많이 써서 구분력이 낮다고 보고 **제외**했습니다.

### 3-3. 데이터 분할과 모델 성능 (논문 3장, 표 2)

- **분할:** 정상·피싱 비율을 유지하는 stratified sampling으로 학습 8 : 테스트 2
- **모델:** LightGBM, RandomizedSearchCV로 하이퍼파라미터 탐색, 5-fold 교차 검증
- **선정 기준:** 악성 URL을 놓치지 않는 것이 중요하므로 **재현율(Recall)**

| 데이터 | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| Validation | 0.9345 | 0.9328 | 0.9318 | 0.9323 |
| Test | 0.9325 | 0.9315 | **0.9288** | 0.9301 |

### 3-4. 서비스 적용 모델 (논문 이후 확장)

서버에 탑재한 모델은 논문의 LightGBM을 확장한 것입니다.

| 항목 | 내용 |
|---|---|
| 모델 파일 | `server/local_models/final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl` |
| 구성 | XGBoost + LightGBM Soft Voting 앙상블, 26개 중 중요도 상위 **17개 특징** 사용, 분류 임계값 0.41 |
| 성능 (3-1의 테스트 23,224건) | Accuracy 0.9351 · Precision 0.9225 · **Recall 0.9452** · F1 0.9337 |
| 재현 | `server/experiments/data/model_validation.json` (TP 10,616 / FP 892 / TN 11,100 / FN 616) |

서버는 이 ML 예측에 **VirusTotal 평판 정보를 상황별 가중치로 합쳐** 최종 점수를 만듭니다(`server/app/services/fusion.py`).

| 상황 | 조건 | ML 가중치 |
|---|---|---:|
| 규칙 우선 | VirusTotal 탐지 비율 5% 이상 | — (바로 위험) |
| VT 다수 탐지 | 5개 이상 엔진 탐지 | 0.25 |
| VT 소수 탐지 | 1~4개 엔진 탐지 | 0.50 |
| VT 미탐지 | 등재됐지만 탐지 없음 | 0.30 (경로 포함 URL은 0.50) |
| VT 정보 없음 | 미등재 또는 조회 실패 | 0.80 |

<details>
<summary><b>판정 로직 평가에 쓴 추가 데이터와 스크립트</b></summary>

학습에 쓰지 않은 URL **1,000건**(검증 500 / 독립 테스트 500)으로 판정 로직의 파라미터를 정하고 평가했습니다.

| 파일 | 내용 |
|---|---|
| `server/experiments/data/evalset.csv` | 평가 URL 1,000건. 열: `url, label, source, path_type, split` |
| `server/experiments/data/vt_cache.jsonl` | 1,000건의 VirusTotal 조회 결과 (조회만 하고 URL은 제출하지 않음, 2026-08-08 ~ 10-20 수집) |
| `server/experiments/data/raw/`, `raw_test/` | 평가셋 원자료 — OpenPhish 피드, Tranco 상위 도메인 (`raw/` 검증용, `raw_test/` 테스트용) |
| `server/experiments/data/revision/` | 파라미터 선정·최종 평가 결과 (`fixed_params.json`, `per_url_*.csv`, `tables*.md`, 그림·로그) |
| `server/experiments/data/confusion/`, `results.json`, `experiments/figures/` | 초기 실험 결과 (이력 보관용, 현재 수치와 다름) |
| `evalset_validation_only.csv`, `raw.zip`, `vt_cache.INVALID.jsonl` | 백업과 무효 처리한 초기 수집분 (실험에 쓰지 않음) |

`evalset.csv` 구성:

| split | 정상 (Tranco) | 피싱 (OpenPhish) |
|---|---|---|
| validation 500 | 250 — 루트 125 + 경로 포함 125 | 250 — 루트 141 + 경로 포함 109 |
| test 500 | 250 — 루트 125 + 경로 포함 125 | 250 — 루트 166 + 경로 포함 84 |

VirusTotal 등재: 검증 444건 / 미등재 56건, 테스트 432건 / 미등재 68건.

| 스크립트 (`server/experiments/`) | 하는 일 |
|---|---|
| `build_evalset.py`, `prepare_testset.py` | 평가셋 구성, 학습 데이터와의 중복 제거 |
| `collect_vt.py` | VirusTotal 정보 수집 (조회 전용) |
| `revision_experiment.py`, `run_test_pipeline.py` | 파라미터 선정과 최종 평가 |
| `recheck_from_csv.py`, `review_followup.py` | 결과 파일만으로 표를 다시 계산, 보완 표 |
| `validate_model.py` | 서비스 모델 재검증 → `model_validation.json` |
| `fusion_experiment.py`, `confusion_report.py`, `make_figures.py` | 초기 실험·혼동행렬·그림 |

실험 스크립트는 서버와 **같은 판정 함수**(`fusion.py`의 `fuse()`)를 호출하므로 실험 수치와 서버 동작이 같습니다. `server/` 폴더에서 실행합니다.

```powershell
python experiments/validate_model.py --csv experiments/data/test_feature_dataset.csv
```

</details>

### 3-5. 서비스 운영 데이터

**서버 DB (PostgreSQL)** — 서버를 실행하면 자동으로 만들어집니다. 정의는 `server/app/models/`, 설명은 `server/docs/04_db_schema.md`.

| 테이블 | 내용 |
|---|---|
| `users` | 계정 (이메일, 비밀번호 해시, 닉네임, refresh token) |
| `scan_logs` | 스캔 이력 (URL, 판정, 최종 점수, 스캔 경로) |
| `score_details` | 스캔별 상세 (VirusTotal 탐지 수, ML 확률, 적용된 상황, 판정 근거 기여도) |
| `reported_urls`, `feedback_queue` | 사용자 신고와 재검증 큐 |
| `bookmarks`, `visit_history` | 즐겨찾기, 방문 기록 |
| `ml_models` | 모델 버전 정보 |

**앱 기기 저장소 (Room DB)** — 화이트리스트, 즐겨찾기 캐시, 스캔 이력 캐시 (`app/app/src/main/java/com/qguarder/android/data/local/AppDatabase.kt`). 화이트리스트나 즐겨찾기에 있는 URL은 서버에 묻지 않고 바로 안전으로 처리합니다.

---

## 4. 앱과 서버의 API 대응

| 앱 호출 (`ApiService.kt`) | 서버 라우터 (`server/app/`) | 비고 |
|---|---|---|
| `GET api/v1/health` | `main.py` | 통합하며 추가 |
| `POST api/v1/auth/register` · `login` · `refresh` · `logout` | `api/v1/auth.py` | refresh token은 HttpOnly 쿠키 |
| `POST api/v1/scan/url` | `api/v1/scan.py` | ML + VirusTotal 판정, 판정 근거(XAI) |
| `POST api/v1/report` | `api/v1/report.py` | 위험 판정 URL이면 KISA 신고 (기본 꺼짐) |
| `GET api/v1/users/me` | `api/v1/user_logs.py` | 통합하며 추가 |
| `PATCH api/v1/users/me` · `/password`, `DELETE api/v1/users/me` | `api/v1/user_logs.py` | |
| `GET api/v1/users/me/scan-logs` | `api/v1/user_logs.py` | |
| `GET` · `POST` · `DELETE api/v1/users/me/bookmarks` | `api/v1/user_logs.py` | |
| `GET` · `POST api/v1/users/me/visits` | `api/v1/user_logs.py` | |

요청·응답 필드 이름과 타입은 앱의 `Dtos.kt`와 서버의 `server/app/schemas/*.py`가 일치합니다.

---

## 5. 통합 작업과 검증

### 통합하면서 바꾼 것

**서버**
- `GET /api/v1/users/me` 추가 — 앱이 로그인 직후 호출하는데 서버에 없었습니다(405).
- `GET /api/v1/health` 추가 — 앱의 `HealthData` 형식. 기존 `/health`는 그대로 둡니다.
- DB 커밋을 응답 전에 하도록 변경(`Depends(get_db, scope="function")`, `fastapi>=0.121.0`) — 로그인 직후 프로필 조회가 401로 튕겨 강제 로그아웃되던 문제 해결.
- KISA 메일 발송 스위치 `KISA_REPORT_ENABLED` 추가(기본 `False`) — 로컬·시연에서 실제 메일이 나가지 않게 합니다.
- `requirements.txt`: `sqlalchemy` → `sqlalchemy[asyncio]` — 최신 SQLAlchemy가 `greenlet`을 기본 설치하지 않아 서버가 시작하지 못하던 문제 해결.

**앱**
- debug 빌드에서 `10.0.2.2` · `localhost` · `127.0.0.1`에 한해 HTTP 허용(`app/app/src/debug/res/xml/network_security_config.xml`). release 빌드는 HTTPS 전용 그대로입니다.
- `app/local.properties.example`에 `BASE_URL` 기본값과 설명 추가.
- 단위 테스트를 현재 코드에 맞게 수정하고 `build.gradle.kts`에 `unitTests.isReturnDefaultValues = true` 추가.

**저장소**
- `server/.gitignore`에 예외 추가 — 모델 파일(.pkl)과 실험 로그가 저장소에서 빠지던 문제 해결.
- 넣지 않은 것: 서버 `.env`(비밀값), `local.properties`, 빌드 캐시, 쓰지 않는 구버전 모델 파일.

### 검증 결과

| 항목 | 결과 |
|---|---|
| 서버 단위 테스트 | ✅ 126개 통과 |
| 서버 API (앱의 호출 순서 그대로 Docker + PostgreSQL에서) | ✅ 38개 항목 통과 |
| 앱 debug 빌드 · 단위 테스트 | ✅ 빌드 성공, 47개 통과 |
| 에뮬레이터 + 로컬 서버 실행 | ✅ 회원가입 · 로그인 · QR 카메라 스캔 · 결과 화면 · 보안 로그 · 신고 · 내 정보 · 로그아웃 |
| VirusTotal 연동 | ✅ `https://www.google.com` → 안전 (93개 엔진 중 0개 탐지) |

---

## 6. 문제 해결과 알아둘 점

| 증상 | 해결 |
|---|---|
| Android Studio에서 "Gradle을 찾을 수 없음" | 맨 위 폴더가 아니라 **`app/` 폴더**를 여세요 |
| 빌드 오류 `BASE_URL이 local.properties에 정의되지 않았습니다` | `app/local.properties`에 `BASE_URL=http://10.0.2.2:8000/` 추가 |
| Gradle Sync 실패 (JDK 오류) | Settings → Build Tools → Gradle → Gradle JDK를 **Embedded JDK (jbr-21)**로 |
| Docker Desktop이 "Virtual Machine Platform" 필요 | Windows 기능에서 **가상 머신 플랫폼**과 **Linux용 Windows 하위 시스템**을 켜고 재부팅 |
| 앱에서 "서버에 연결할 수 없습니다" | 서버가 켜져 있는지, 에뮬레이터 크롬에서 `http://10.0.2.2:8000/api/v1/health`가 열리는지 확인 |
| 정상 사이트가 "위험"으로 나옴 | `server/.env`의 `VIRUSTOTAL_API_KEY` 확인 후 서버 재시작 |
| 실제 휴대폰으로 테스트 | `10.0.2.2`는 에뮬레이터 전용입니다. ngrok 등 `https://` 주소를 `BASE_URL`에 넣고 다시 빌드 (`/`로 끝나야 함) |

**알아둘 점**
- 앱에는 URL 직접 입력 화면이 없습니다. QR 카메라 스캔으로만 검사합니다. 에뮬레이터에서는 Extended controls → Camera → Virtual scene images에 [`docs/demo_qr/`](docs/demo_qr/)의 PNG를 지정하면 됩니다.
- 앱의 응답 대기 시간과 서버의 VirusTotal 대기 시간이 모두 30초라, VirusTotal이 응답하지 않는 드문 경우 앱이 먼저 타임아웃될 수 있습니다.
- 서버는 `http://` 또는 `https://`로 시작하는 URL만 분석합니다. 그 밖의 QR 문자열은 422로 거절됩니다.
- 즐겨찾기의 `risk_level`은 앱이 서버로 보내지 않아 서버에는 비어 있습니다(앱은 기기에 저장한 값을 씁니다).
- KISA 신고 메일은 기본으로 꺼져 있습니다. 운영 배포에서만 `KISA_REPORT_ENABLED=True`와 `SES_SENDER_EMAIL`을 설정하세요.
- 서버 테스트: `server/`에서 `pip install -r requirements.txt` 후 `pytest tests` (`.env`의 `DATABASE_URL`, `JWT_SECRET_KEY` 사용).
- `server/docs/kci_research_analysis.md`는 초기 설계 기록이라 현재 값과 다릅니다.

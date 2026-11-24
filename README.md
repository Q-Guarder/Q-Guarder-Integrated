# Q-Guard 통합본 (서버 + Android 앱)

QR 코드 큐싱 탐지 시스템 Q-Guard의 서버와 Android 앱을 한 폴더로 묶은 것입니다.
앱이 QR에서 읽은 URL을 서버로 보내면, 서버가 ML 앙상블 예측과 VirusTotal(VT) 정보를 상황 적응형으로 융합해 안전(SECURED) / 주의(SUSPICIOUS) / 위험(BLOCKED)을 돌려줍니다.

📄 최종 발표자료, 포스터, 학술대회 논문(PDF)은 [`docs/`](docs/)에 있습니다.
개발 기록(커밋 이력)은 원본 레포 [Q-Guarder-App](https://github.com/Q-Guarder/Q-Guarder-App)과 [Q-Guarder-Server](https://github.com/Q-Guarder/Q-Guarder-Server)에 있습니다.

목차: [1. 디렉터리 구조](#1-디렉터리-구조) · [2. 데이터 설명](#2-데이터-설명) · [3. 서버 실행](#3-서버-실행-docker) · [4. 앱 실행](#4-앱-실행-android-studio--에뮬레이터) · [5. 앱 ↔ 서버 API 대응](#5-앱--서버-api-대응) · [6. 통합하면서 바꾼 것](#6-통합하면서-바꾼-것) · [7. 알아둘 점](#7-알아둘-점)

---

## 1. 디렉터리 구조

```
Q-Guard-integrated/
├─ README.md                    이 문서
├─ .gitignore                   비밀값(.env, local.properties)·빌드 산출물 제외
├─ docs/                        최종 발표자료 · 포스터 · 학술대회 논문 (PDF), 시연용 QR (demo_qr/)
├─ server/                      FastAPI 서버 + 실험 + 문서
└─ app/                         Android 앱 (Kotlin)
```

### 1.1 server/

```
server/
├─ app/                         서버 애플리케이션
│  ├─ main.py                   FastAPI 앱 생성, 라우터 등록, /health, Lambda 핸들러
│  ├─ api/v1/                   HTTP 라우터
│  │  ├─ auth.py                회원가입 · 로그인 · 토큰 갱신 · 로그아웃
│  │  ├─ scan.py                URL 위험도 분석 (POST /scan/url)
│  │  ├─ report.py              악성 URL 신고, KISA 신고 백그라운드 작업
│  │  └─ user_logs.py           프로필 · 스캔 이력 · 즐겨찾기 · 방문 기록
│  ├─ services/                 핵심 로직
│  │  ├─ url_features.py        URL 전처리 + 26개 특징 추출 (논문 Table 1)
│  │  ├─ ensemble_model.py      XGB+LGBM Soft Voting 앙상블 클래스 (pkl 복원용)
│  │  ├─ s3_loader.py           모델 로딩 (S3 또는 local_models/)
│  │  ├─ fusion.py              상황 적응형 가중 융합 — 논문 식 (2)~(7), SERVER_PARAMS
│  │  ├─ hybrid_engine.py       ML 추론 + VT 조회 + 융합을 묶는 분석 엔진
│  │  ├─ feature_metadata.py    XAI용 특징 한글 설명, 위험도 문구
│  │  └─ kisa_reporter.py       KISA 신고 메일 (KISA_REPORT_ENABLED로 on/off)
│  ├─ schemas/                  요청·응답 스키마 (Pydantic) — 앱의 Dtos.kt와 대응
│  ├─ models/                   DB 테이블 정의 (SQLAlchemy)
│  ├─ crud/                     DB 조회·저장 함수
│  ├─ core/                     설정(config.py), 인증·JWT(security.py)
│  └─ db/session.py             DB 세션
├─ background/queue_processor.py   신고 큐 재검증 (운영: EventBridge → Lambda)
├─ local_models/                학습된 모델 파일 (.pkl)
├─ experiments/                 논문 실험 스크립트와 데이터 → 2장 참고
│  ├─ *.py                      실험 스크립트 (2.4절)
│  ├─ data/                     실험 데이터와 결과 (2.2~2.3절)
│  └─ figures/                  1차 심사본 민감도 그림 (PDF)
├─ tests/                       단위 테스트 (pytest, 126개)
├─ docs/                        설계 문서 (API 명세, DB 스키마, AWS 구조, 트러블슈팅 등)
├─ infrastructure/              AWS 배포 Terraform (VPC, RDS, Lambda, API Gateway, S3)
├─ Dockerfile, docker-compose.yml   로컬 실행 (서버 + PostgreSQL)
├─ requirements.txt             Python 의존성
└─ .env.example                 환경 변수 템플릿 (.env로 복사해 사용)
```

### 1.2 app/

```
app/
├─ app/
│  ├─ build.gradle.kts          모듈 빌드 설정 (BASE_URL을 local.properties에서 읽음)
│  ├─ schemas/                  Room DB 스키마 내보내기
│  └─ src/
│     ├─ main/
│     │  ├─ AndroidManifest.xml
│     │  ├─ java/com/qguarder/android/
│     │  │  ├─ data/remote/     서버 통신 — ApiService.kt, dto/Dtos.kt, AuthInterceptor.kt, *Repository.kt
│     │  │  ├─ data/local/      로컬 저장 — Room DB(화이트리스트·즐겨찾기·스캔 캐시), 토큰, 쿠키
│     │  │  ├─ di/              Hilt 모듈 (네트워크, DB)
│     │  │  ├─ domain/model/    도메인 모델 (RiskLevel, ScanResult 등)
│     │  │  ├─ ui/              화면 — splash, login, register, scan, scanning, result, logs, favorites, profile
│     │  │  └─ util/            입력 검증
│     │  └─ res/                레이아웃, 문자열, 내비게이션 그래프, 네트워크 보안 설정
│     ├─ debug/                 debug 빌드 전용 설정 (로컬 서버 HTTP 허용)
│     ├─ test/                  JVM 단위 테스트
│     └─ androidTest/           계측 테스트
├─ gradle/, gradlew, *.gradle.kts   Gradle 래퍼와 빌드 설정
├─ local.properties.example     BASE_URL 설정 템플릿 (local.properties로 복사)
└─ Qushing_Defense_구현명세서_v3.pdf   앱 구현 명세서
```

---

## 2. 데이터 설명

모든 데이터에서 **label 0 = 정상, 1 = 피싱**입니다.

> ⚠️ 데이터에는 실제 피싱 URL이 들어 있습니다. 브라우저로 접속하지 마세요.

### 2.1 모델과 오프라인(학습 단계) 데이터 — 논문 2.2절, 3.1~3.2절

| 경로 | 내용 |
|---|---|
| `server/local_models/final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl` | 최종 모델. XGBoost + LightGBM Soft Voting 앙상블, Top-17 특징, 분류 임계값 0.41. 서버가 `S3_MODEL_BUCKET`이 비어 있을 때 이 파일을 읽습니다. |
| `server/experiments/data/raw/offline_urls.csv` | 전처리를 마친 오프라인 URL 전체 **116,119건**. 열: `url, label, source`. 정상 59,960건(Kaggle), 피싱 56,159건(PhishTank 55,861 + OpenPhish 298). 학습 6 : 검증 2 : 테스트 2로 나눠 썼고, 온라인 평가셋과의 중복(누수) 검사에도 씁니다. |
| `server/experiments/data/test_feature_dataset.csv` | 오프라인 **테스트 분할 23,224건**(정상 11,992 / 피싱 11,232). 열: 26개 특징 + `label`. URL 원문은 없습니다. |
| `server/experiments/data/model_validation.json` | 위 테스트 분할로 모델을 다시 평가한 결과. 논문 Table 3·4의 XGB+LGBM Top-17 행(재현율 0.9452, TP 10,616 / FP 892 / TN 11,100 / FN 616)이 재현됩니다. |

26개 특징의 정의는 `server/app/services/url_features.py`에 있고, 그중 모델이 쓰는 17개는 논문 Table 1의 별표 항목입니다.

### 2.2 온라인(융합 평가) 데이터 — 논문 3.1절, 3.3~3.5절

오프라인 모델 구축에 쓰지 않은 URL 1,000건으로, **검증 500건**(파라미터 선정)과 **독립 테스트 500건**(최종 평가)으로 나뉩니다.

| 경로 | 내용 |
|---|---|
| `server/experiments/data/evalset.csv` | 평가셋 **1,000건**. 열: `url, label, source, path_type, split`. |
| `server/experiments/data/vt_cache.jsonl` | 평가셋 1,000건의 VirusTotal 조회 결과(한 줄에 한 건). 조회만 하고 URL을 제출하지 않았습니다. 수집 기간 2026-08-08 ~ 2026-10-20. |
| `server/experiments/data/raw/`, `raw_test/` | 평가셋을 만든 원자료. `openphish_feed.txt`(OpenPhish 피드, 각 300줄), `tranco_top.csv`(Tranco 순위·도메인). `raw/`는 검증용, `raw_test/`는 테스트용입니다. |
| `server/experiments/data/evalset_validation_only.csv` | 테스트 집합을 추가하기 전의 검증 500건 백업. |
| `server/experiments/data/raw.zip` | `raw/` 원자료 백업. |
| `server/experiments/data/vt_cache.INVALID.jsonl` | 무효 처리한 초기 VT 수집분 24건. 실험에 쓰지 않습니다. |

`evalset.csv` 구성:

| split | 정상 (label 0) | 피싱 (label 1) |
|---|---|---|
| validation (500) | 250 — 루트 125(`tranco`) + 경로 포함 125(`tranco-crawl`) | 250 — 루트 141 + 경로 포함 109 (`openphish`) |
| test (500) | 250 — 루트 125(`tranco`) + 경로 포함 125(`tranco-crawl`) | 250 — 루트 166 + 경로 포함 84 (`openphish`) |

열 설명:

| 열 | 의미 |
|---|---|
| `source` | `openphish` = OpenPhish 피싱 피드, `tranco` = Tranco 상위 도메인의 루트 URL, `tranco-crawl` = 그 도메인에서 수집한 내부 링크 |
| `path_type` | `root` = 경로 없는 URL, `deep` = 경로 포함 URL. 상황 B의 가중치(0.30 / 0.50)를 가르는 기준입니다. |
| `split` | `validation` 또는 `test` |

`vt_cache.jsonl` 필드:

| 필드 | 의미 |
|---|---|
| `vt_status` | `ok` = VT에 등재됨, `not_found` = 미등재(상황 C). 검증 ok 444 / not_found 56, 테스트 ok 432 / not_found 68. |
| `detected_engines` | 논문의 d. 악성(malicious) 또는 의심(suspicious)으로 판정한 엔진 수. |
| `total_engines` | 논문의 n. 분석 통계에 포함된 전체 엔진 수. |
| `http_status`, `latency_ms`, `queried_at` | VT 응답 코드, 조회 시간, 조회 시각. |

### 2.3 실험 결과 파일

`server/experiments/data/revision/` — 논문 10주차 수정본의 수치가 나온 곳입니다.

| 파일 | 내용 |
|---|---|
| `fixed_params.json` | 검증 집합에서 확정한 융합 파라미터(α 18.4, d_high 5, τ 0.45/0.65, θ 0.05, 가중치)와 선정 기준·과정. 서버의 `SERVER_PARAMS`와 같습니다. |
| `per_url_validation.csv`, `per_url_test.csv` | URL별 결과 각 500건. `label, path_type, vt_status, d, n, p_ml`과 방법별(ML 단독, 고정 융합, 제안 방법 등) 판정·점수·상황. 이 파일만으로 논문 표를 다시 계산할 수 있습니다. |
| `tables_test.md` | **테스트 집합 최종 평가** — 논문 Table 6·7, 3.4절. |
| `tables.md` | 검증 집합의 파라미터 선정과 민감도 분석 — 논문 Table 8. |
| `tables_review_followup.md` | 고정 융합 자체 임계값 선정 등 보완 표. |
| `revision_results.json`, `revision_results_test.json`, `review_followup.json` | 위 표들의 원본 수치(JSON). |
| `zero_day_validation.csv`, `zero_day_test.csv` | VT 미등재 피싱 URL만 모은 것(검증 15건, 테스트 7건) — 논문 3.4절. |
| `figures/*.png` | 파라미터 민감도 그림. |
| `*.log`, `test_pipeline_status.json` | 실행 로그와 수집 완료 상태. |

그 밖의 결과:

| 경로 | 내용 |
|---|---|
| `server/experiments/data/confusion/` | 1차 심사본 500건(현재의 검증 집합) 기준 혼동행렬 산출물. 폴더 안 `README.md` 참고. |
| `server/experiments/data/results.json`, `server/experiments/figures/*.pdf` | 1차 심사본 실험 결과와 그림. 현재 논문 수치와 다릅니다(비교·이력용). |

### 2.4 실험 스크립트 (`server/experiments/`)

| 스크립트 | 하는 일 |
|---|---|
| `build_evalset.py` | OpenPhish·Tranco에서 평가셋을 구성 |
| `prepare_testset.py` | 독립 테스트 집합 추가, 검증 집합·오프라인 데이터와의 중복 제거 |
| `collect_vt.py` | 평가셋의 VT 정보 수집(조회 전용) → `vt_cache.jsonl` |
| `revision_experiment.py` | 파라미터 선정, 민감도 분석, 최종 평가 — 논문 3.3~3.5절 |
| `run_test_pipeline.py` | 테스트 집합 수집 → VT 조회 → 평가를 한 번에 실행 |
| `recheck_from_csv.py` | `per_url_*.csv`와 `fixed_params.json`만으로 최종 표를 독립적으로 재계산 |
| `review_followup.py` | 보완 표 계산 |
| `validate_model.py` | 오프라인 모델 재검증 → `model_validation.json` |
| `fusion_experiment.py`, `confusion_report.py`, `make_figures.py` | 1차 심사본 실험·혼동행렬·그림 |

모든 실험은 서버와 같은 융합 함수(`server/app/services/fusion.py`의 `fuse()`)를 호출하므로, 논문 수치와 서버 동작이 같습니다. 스크립트는 `server/` 폴더에서 실행합니다. 예:

```powershell
python experiments/recheck_from_csv.py --split test
```

```powershell
python experiments/validate_model.py --csv experiments/data/test_feature_dataset.csv
```

### 2.5 서비스 운영 데이터 (DB)

서버를 실행하면 PostgreSQL에 아래 테이블이 자동으로 만들어집니다. 정의는 `server/app/models/`, 설명은 `server/docs/04_db_schema.md`에 있습니다.

| 테이블 | 내용 |
|---|---|
| `users` | 계정 (이메일, 비밀번호 해시, 닉네임, refresh token) |
| `scan_logs` | 스캔 이력 (URL, 위험도, 최종 점수, 스캔 경로) |
| `score_details` | 스캔별 상세 (VT 탐지/전체 엔진 수, ML 확률, 적용된 상황, XAI 기여도) |
| `reported_urls`, `feedback_queue` | 사용자 신고와 재검증 큐 |
| `bookmarks`, `visit_history` | 즐겨찾기, 방문 기록 |
| `ml_models` | 모델 버전 메타데이터 |

앱은 기기 안에 Room DB로 화이트리스트, 즐겨찾기 캐시, 스캔 이력 캐시를 따로 둡니다(`app/app/src/main/java/com/qguarder/android/data/local/AppDatabase.kt`).

---

## 3. 서버 실행 (Docker)

Docker Desktop이 켜져 있어야 합니다. `server` 폴더에서 실행합니다.

```powershell
copy .env.example .env
```

```powershell
docker compose up --build
```

- `.env.example`의 기본값 그대로 로컬에서 동작합니다 (DB는 compose의 `db` 컨테이너).
- **`VIRUSTOTAL_API_KEY`를 꼭 넣으세요**(무료 키: <https://www.virustotal.com/gui/my-apikey>). 비워 두면 VT 조회를 건너뛰고 ML 점수만으로 판정하는데(상황 C), 이 경우 `https://www.google.com` 같은 정상 루트 URL도 "위험"으로 나옵니다. 논문에서 다룬 ML 단독의 루트 URL 오탐이며, VT 정보가 있어야 억제됩니다.
- **KISA 신고 메일은 기본으로 꺼져 있습니다.** BLOCKED로 판정된 URL을 앱에서 신고하면 신고 접수는 정상 처리되지만, `KISA_REPORT_ENABLED=False`(기본값)인 동안에는 KISA(cert@kisa.or.kr)로 메일을 보내지 않습니다. 운영 배포에서만 `KISA_REPORT_ENABLED=True`와 `SES_SENDER_EMAIL`을 설정하세요(`server/infrastructure/main.tf`의 Lambda 환경 변수에는 켜져 있습니다).
- ML 모델은 `server/local_models/`의 pkl을 읽습니다(`S3_MODEL_BUCKET`이 비어 있을 때).
- 확인: 브라우저에서 <http://localhost:8000/docs>, <http://localhost:8000/api/v1/health>

## 4. 앱 실행 (Android Studio + 에뮬레이터)

1. Android Studio에서 `app/` 폴더를 엽니다.
2. `app/local.properties.example`을 `app/local.properties`로 복사합니다.
   기본값 `BASE_URL=http://10.0.2.2:8000/`은 "같은 PC에서 띄운 서버"를 가리킵니다(에뮬레이터에서 PC는 `10.0.2.2`).
3. 에뮬레이터에서 debug 빌드로 실행합니다 → 회원가입 → 로그인 → QR 스캔 또는 URL 직접 입력.

실기기나 외부 서버를 쓸 때는 `BASE_URL`을 HTTPS 주소(ngrok, API Gateway 등)로 바꾸면 됩니다. 주소는 반드시 `/`로 끝나야 합니다.

## 5. 앱 ↔ 서버 API 대응

| 앱 호출 (`ApiService.kt`) | 서버 라우터 | 비고 |
|---|---|---|
| `GET  api/v1/health` | `server/app/main.py` | 통합하며 추가 |
| `POST api/v1/auth/register` · `login` · `refresh` · `logout` | `server/app/api/v1/auth.py` | refresh token은 HttpOnly 쿠키 |
| `POST api/v1/scan/url` | `server/app/api/v1/scan.py` | 하이브리드 판정 + XAI |
| `POST api/v1/report` | `server/app/api/v1/report.py` | BLOCKED면 KISA 신고 백그라운드 |
| `GET  api/v1/users/me` | `server/app/api/v1/user_logs.py` | 통합하며 추가 |
| `PATCH api/v1/users/me` · `/password`, `DELETE api/v1/users/me` | `server/app/api/v1/user_logs.py` | |
| `GET api/v1/users/me/scan-logs` | `server/app/api/v1/user_logs.py` | |
| `GET/POST/DELETE api/v1/users/me/bookmarks` | `server/app/api/v1/user_logs.py` | |
| `GET/POST api/v1/users/me/visits` | `server/app/api/v1/user_logs.py` | |

요청·응답 필드 이름과 타입은 앱의 `Dtos.kt`와 서버의 `server/app/schemas/*.py`가 일치합니다.

## 6. 통합하면서 바꾼 것

서버
- `GET /api/v1/users/me` 추가 — 앱이 로그인 직후 호출하는데 서버에 없었습니다(405).
- `GET /api/v1/health` 추가 — 앱의 `HealthData` 형식(status, version, model, checks). 기존 `/health`는 그대로 둡니다.
- DB 커밋을 응답 전에 하도록 변경(`Depends(get_db, scope="function")`, `fastapi>=0.121.0`). 최신 FastAPI는 응답을 보낸 뒤 커밋해서, 앱이 로그인 직후 보내는 프로필 조회가 401로 튕기고 강제 로그아웃되는 문제가 있었습니다.
- KISA 메일 발송 스위치 `KISA_REPORT_ENABLED` 추가(기본 False) — 로컬 개발·시연에서 실제 메일이 나가지 않게 합니다.
- `requirements.txt`: `sqlalchemy` → `sqlalchemy[asyncio]`. 최신 SQLAlchemy(2.1)는 `greenlet`을 기본 설치하지 않아, 새로 빌드하면 서버가 import 단계에서 죽었습니다.

앱
- `app/app/src/debug/res/xml/network_security_config.xml` — debug 빌드에서 `10.0.2.2`·`localhost`·`127.0.0.1`에 한해 HTTP 허용. 원본은 HTTP를 전부 막아 로컬 서버에 붙을 수 없었습니다. release 빌드는 그대로 HTTPS 전용입니다.
- `app/local.properties.example` — `BASE_URL` 기본값과 설명 추가.
- 단위 테스트를 현재 코드에 맞게 수정(`app/app/src/test/`), `app/app/build.gradle.kts`에 `unitTests.isReturnDefaultValues = true` 추가. 기존 테스트는 코드 변경을 따라가지 못해 컴파일되지 않았습니다.

저장소
- `server/.gitignore`에 예외 추가 — 원래 `*.pkl`, `local_models/`, `*.log`, `raw.zip`을 제외하고 있어, 위에서 안내한 모델 파일과 실험 로그가 저장소에 올라가지 않았습니다.

넣지 않은 것: 서버 `.env`(비밀값), `.git`, 캐시, 사용하지 않는 구버전 모델 파일, 앱의 `.claude/`·`.DS_Store`.

검증: 서버를 Docker(PostgreSQL)로 띄워 앱의 호출 순서 그대로 요청한 38개 항목과 서버 단위 테스트 126개가 통과했습니다. 앱은 debug APK 빌드(`./gradlew assembleDebug`)와 단위 테스트 47개(`./gradlew testDebugUnitTest`)가 통과했습니다. 에뮬레이터에서 앱과 서버를 함께 실행하는 것은 아직 확인하지 못했습니다.

## 7. 알아둘 점

- 앱의 응답 대기 시간은 30초, 서버의 VirusTotal 대기 시간도 30초입니다. VT가 응답하지 않는 드문 경우 서버가 ML 단독 판정으로 넘어가기 전에 앱이 먼저 타임아웃될 수 있습니다.
- 즐겨찾기의 `risk_level`은 앱이 서버로 보내지 않아 서버에는 비어 있습니다(앱은 로컬에 저장한 값을 씁니다).
- 서버는 `http://` 또는 `https://`로 시작하는 URL만 분석합니다. 스킴이 없는 QR 문자열은 422로 거절됩니다.
- 서버 테스트 실행: `server/`에서 `pip install -r requirements.txt` 후 `pytest tests` (환경 변수 `DATABASE_URL`, `JWT_SECRET_KEY` 필요 — `.env`가 있으면 자동으로 읽습니다).
- `server/docs/kci_research_analysis.md`는 1차 설계 기록이라 현재 값과 다릅니다(문서 상단 안내 참고).

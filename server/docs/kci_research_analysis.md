> ## ⚠️ 이 문서는 1차 설계 기록입니다 (현재 서버·투고 논문과 다름)
>
> 2026-06-02 시점의 서버 아키텍처 논문 초안이며, 이후 재심 수정(2026-10-18 파라미터 확정)을 거치며
> 융합 파라미터와 코드 구조가 바뀌었습니다. **아래 본문의 수치·코드 인용을 현재 값으로 인용하지 마세요.**
>
> | 항목 | 이 문서(1차) | 현재 서버 = 투고 논문(10주차 수정본) |
> |---|---|---|
> | 시스템 표기명 | Q-Guarder | **Q-Guard** (저장소 이름만 Q-Guarder-Server) |
> | 증폭 계수 α (식 4) | 3 | **18.4** |
> | 우선 판정 임계값 θ (식 6) | 0.30 | **0.05** |
> | SUSPICIOUS 임계값 τL (식 7) | 0.35 | **0.45** (τH 0.65는 동일) |
> | 상황 B의 ML 가중치 (식 3) | 0.30 일괄 | **루트 URL 0.30 / 경로 포함 URL 0.50** |
> | 상황 C | VT 응답 없음(total=0) | VT 미등재(404) 또는 API 장애 — `VTStatus`로 구분 기록 |
> | ML 모델 | XGB Top-25 + LGBM Top-20, 임계값 0.40 | **XGB+LGBM Top-17 Soft Voting, 임계값 0.41** |
> | VT 조회 | POST 제출 후 GET | **GET 전용** (미등재 URL을 제출하지 않음) |
> | 융합 코드 위치 | `hybrid_engine.py`의 `_select_case` 등 | `app/services/fusion.py`의 `fuse()` |
>
> 현재 값의 기준: `app/services/fusion.py`의 `SERVER_PARAMS`, `experiments/data/revision/fixed_params.json`,
> 실험 결과는 `experiments/data/revision/tables.md`(검증)·`tables_test.md`(테스트).

# Q-Guarder: 하이브리드 피싱 URL 탐지를 위한 서버 아키텍처 설계

## — ML 추론 컴포넌트와 위협 인텔리전스 API의 적응형 융합 시스템 —

---

> **프로젝트명**: Q-Guarder
> **작성일**: 2026.06.02
> **팀원 및 소속**:
>
> | 이름 | 역할 | 소속 |
> |------|------|------|
> | [팀원 1] | 서버 백엔드 설계 · 하이브리드 융합 엔진 구현 | [학과/학교명] |
> | [팀원 2] | Android 클라이언트 개발 · API 연동 | [학과/학교명] |
> | [팀원 3] | 인프라/DevOps · 서버리스 배포 | [학과/학교명] |
>
> **참고**: ML 모델 학습(XGBoost/LightGBM 앙상블)은 별도 ML 팀이 담당하며, 본 논문에서는 학습된 모델을 **추론 컴포넌트**로 통합하는 서버 아키텍처 설계에 초점을 맞춘다.
>
> **키워드**: 피싱 URL 탐지, 하이브리드 융합 아키텍처, 적응형 가중치 미들웨어, RESTful API 설계, Graceful Degradation, 사용자 대면 XAI API, 서버리스 배포, 모바일 보안

---

## 목차

1. [연구 배경](#1-연구-배경)
2. [기존 연구의 한계점](#2-기존-연구의-한계점)
3. [제안 방법의 독창성](#3-제안-방법의-독창성)
4. [제안 방법 개요](#4-제안-방법-개요)
5. [실험 환경 및 계획](#5-실험-환경-및-계획)
6. [실험 데이터](#6-실험-데이터)
7. [실험 결과 및 분석](#7-실험-결과-및-분석)
8. [향후 개선 방향](#8-향후-개선-방향)
9. [최종 정리](#9-최종-정리)
10. [참고 문헌 및 출처 검증](#10-참고-문헌-및-출처-검증)

---

## 1. 연구 배경

### 1.1 국내 피싱 공격 현황

한국인터넷진흥원(KISA)의 2024년 하반기 사이버 위협 동향 보고서에 따르면, 국내 사이버 침해사고 신고 건수는 2023년 1,277건에서 2024년 1,887건으로 **전년 대비 약 48% 증가**하였다 [S1]. 특히 스미싱(SMS 피싱) 탐지 건수는 2024년 기준 **약 150만 건**으로, 전년 대비 약 3배 증가하였으며, 이 중 공공기관 사칭이 약 96만 건, 지인 사칭이 약 28만 건을 차지하였다 [S2].

```
국내 사이버 침해사고 신고 추이:

  건수
  2,000 ┤                              ■ 1,887
        │                         ┌────┤
  1,500 ┤                   ■ 1,277    │
        │              ┌────┤     │    │
  1,000 ┤         ■ 952     │     │    │
        │    ┌────┤    │    │     │    │
    500 ┤    │    │    │    │     │    │
        │    │    │    │    │     │    │
      0 ┼────┴────┴────┴────┴─────┴────┘
         2021  2022  2023  2024

  출처: KISA 사이버 위협 동향 보고서 (2024 하반기)
```

### 1.2 시스템 관점에서의 문제 정의

피싱 URL 탐지 기술은 학술적으로 높은 정확도를 달성하고 있으나, 실제 **프로덕션 서비스**로 운용하기 위해서는 다음과 같은 **시스템 엔지니어링** 과제가 존재한다:

| 과제 영역 | 설명 | 기존 연구의 대응 |
|-----------|------|-----------------|
| **다중 소스 융합** | ML 모델과 외부 TI(VirusTotal 등)의 판정을 어떻게 결합할 것인가 | 고정 비율 또는 순차 파이프라인 |
| **외부 API 장애 내성** | VT API 타임아웃/429/네트워크 오류 시 시스템 동작 보장 | 미고려 (시스템 중단) |
| **모바일 클라이언트 연동** | ML 모델의 XAI 출력을 일반 사용자에게 어떻게 전달할 것인가 | SHAP force plot (연구자용) |
| **엔드투엔드 파이프라인** | 탐지 → 신고 → 차단까지의 자동화된 워크플로우 | 탐지(Detection)에서 종료 |
| **서버리스 제약** | Lambda 60s 타임아웃, 콜드 스타트 환경에서의 모델 서빙 | 온프레미스 가정 |

본 논문에서는 ML 모델을 **블랙박스 추론 컴포넌트**로 취급하고, 이를 외부 위협 인텔리전스와 **적응형으로 융합**하며, 모바일 클라이언트에 **구조화된 XAI JSON**을 제공하고, **장애 내성을 갖춘 서버 아키텍처**를 설계·구현하는 데 초점을 맞춘다.

### 1.3 기존 접근법의 분류

피싱 URL 탐지 접근법은 크게 3가지로 분류된다:

| 접근법 | 원리 | 장점 | 단점 |
|--------|------|------|------|
| 블랙리스트 기반 | 알려진 피싱 URL DB 조회 | 빠른 판정, 낮은 FP | Zero-day 탐지 불가 |
| ML 기반 | URL 피처 추출 → ML 분류 | Zero-day 탐지 가능 | 외부 TI 미활용, FN 위험 |
| TI 기반 | VirusTotal 등 외부 엔진 조회 | 다중 엔진 합의 | API 의존, 저탐지율 희석 |

기존 연구들은 위 3가지 중 **하나만 사용하거나**, 결합하더라도 **고정 비율 단순 융합** 또는 **순차 파이프라인**으로 구성하며, **시스템 수준의 장애 내성이나 API 응답 설계를 고려하지 않는다**. 본 연구는 이 세 접근법을 프로덕션 서버 아키텍처 내에서 **상황 인식형 적응 가중치**로 동적 융합하는 하이브리드 시스템을 제안한다.

---

## 2. 기존 연구의 한계점

### 2.1 관련 논문 조사 (12편)

기존 연구를 **4개 축**으로 분류하여 조사하였다. 각 논문의 한계점은 **서버/애플리케이션 시스템 통합 관점**에서 분석한다.

---

#### 축 A. ML 앙상블 기반 피싱 URL 탐지

**[R1] Detection of Phishing Websites from URLs Using Hybrid Ensemble-Based ML Technique**
- **저자**: Agagu, M., Ogunbiyi, I.A., Lasisi, A., Omorogiuwa, O.
- **출처**: Springer, SCDM 2024, Lecture Notes in Networks and Systems, vol. 1078
- **링크**: https://link.springer.com/chapter/10.1007/978-3-031-66965-1_2
- **내용 요약**:
  - CatBoost + XGBoost + LightGBM 3개 모델을 **Voting 앙상블**로 결합
  - **Accuracy 93.0%, Recall 92.2%, Precision 93.4%, F1-score 92.8%** 달성
- **시스템 관점 한계**: 모델 추론 결과만 출력하며 **서비스 API 설계 미제시**. 외부 TI와의 통합 아키텍처 없음. 모바일 클라이언트 연동 미고려.

**[R2] Ensemble Learning-Powered URL Phishing Detection: A Performance Driven Approach**
- **저자**: Mushtaq, S., Javed, T., Mohd Su'ud, M.
- **출처**: Journal of Informatics and Web Engineering, 2024, 3(2), pp.134-145
- **링크**: https://doi.org/10.33093/jiwe.2024.3.2.10
- **내용 요약**:
  - AdaBoost + CatBoost + Gradient Boosting Classifier의 앙상블
  - Stacking 기반 2단계 메타 학습으로 DS-50에서 98% 정확도 달성
- **시스템 관점 한계**: Stacking 2단계 추론 → **실시간 서비스 레이턴시 미고려**. API 응답 시간 제약(Lambda 60s)에서의 서빙 전략 없음.

**[R3] Combining Lexical, Host, and Content-based Features for Phishing Websites Detection Using ML Models**
- **저자**: Hamadouche, S., Boudraa, O., Gasmi, M.
- **출처**: EAI Endorsed Transactions on Scalable Information Systems, 2024, 11(6)
- **링크**: https://doi.org/10.4108/eetsis.4421
- **내용 요약**:
  - URL lexical + 호스트 기반 + 콘텐츠 기반 3종 피처 결합
  - 앙상블이 단일 모델 대비 정확도/정밀도/재현율 모두 우수
- **시스템 관점 한계**: 콘텐츠(HTML) 분석 필요 → **응답 시간 증가**로 실시간 모바일 서비스 부적합. 외부 TI 결합 아키텍처 없음.

---

#### 축 B. 설명 가능한 AI (XAI) + 피싱 탐지

**[R4] Explainable ML for Phishing Site Detection: A High-Efficiency Approach Using Boosting Models and SHAP**
- **저자**: Uddin, K. M. M. 외
- **출처**: The Journal of Engineering (IET/Wiley), 2025
- **링크**: https://doi.org/10.1049/tje2.70110
- **내용 요약**:
  - XGBoost + LightGBM + GBM에 **SHAP** 기반 XAI 결합
  - XGBoost + SHAP 조합으로 **97.78% 정확도** 달성
  - SHAP force plot, summary plot으로 피처 기여도 시각화
- **시스템 관점 한계**: SHAP 시각화 출력이 **matplotlib 이미지 형태** → REST API로 모바일 앱에 전달 불가. 일반 사용자가 해석할 수 없는 연구자 전용 출력물.

**[R5] XAI-PhD: Fortifying Trust of Phishing URL Detection Empowered by SHAP**
- **저자**: Al-Fayoumi, M., Alhijawi, B., Abu Al-Haija, Q., Armoush, R.
- **출처**: International Journal of Online and Biomedical Engineering (iJOE), 2024, 20(11), pp.80-101
- **링크**: https://doi.org/10.3991/ijoe.v20i11.49533
- **내용 요약**:
  - "XAI-PhD" 프레임워크: ML + SHAP으로 피싱 URL 판정 **신뢰성 강화**
  - 각 피처가 분류기 의사결정에 미치는 영향을 SHAP으로 분석
- **시스템 관점 한계**: SHAP force plot 이미지 기반 → **JSON API 응답으로 변환하는 파이프라인 설계 없음**. 모바일 UI 렌더링에 적합한 구조화 데이터 미제공.

**[R6] Can Features for Phishing URL Detection Be Trusted Across Diverse Datasets?**
- **저자**: Mia, M., Derakhshan, D., Pritom, M. M. A.
- **출처**: arXiv:2411.09813, 2024
- **링크**: https://arxiv.org/abs/2411.09813
- **내용 요약**:
  - 2개 공개 피싱 URL 데이터셋 간 **피처 일반화 가능성** 검증
  - SHAP 분석 결과, **피처 중요도가 데이터셋에 따라 크게 변동**
- **시사점**: ML 단독 피처 기반 탐지의 근본적 취약점을 지적. **시스템 수준에서 외부 TI 보완이 필수적**임을 시사.

**[R7] Hybridizing Explainable AI (XAI) for Intelligent Feature Extraction in Phishing Website Detection**
- **출처**: MDPI Electronics, 2025, 15(2), 350
- **링크**: https://doi.org/10.3390/electronics15020350
- **내용 요약**:
  - 4가지 XAI 기법(SHAP, LIME, PDP, Permutation Importance) 하이브리드 적용
  - XAI를 **피처 선택** 도구로 활용하여 모델 학습 최적화
- **시스템 관점 한계**: XAI 목적이 피처 선택(연구자 도구) — **최종 사용자에게 전달할 API 응답 설계 관점 없음**.

---

#### 축 C. 하이브리드 ML + 위협 인텔리전스 융합

**[R8] A Large Scale Study and Classification of VirusTotal Reports on Phishing and Malware URLs**
- **저자**: Choo, E., Nabeel, M., De Silva, R., Yu, T., Khalil, I.
- **출처**: arXiv:2205.13155, 2022
- **링크**: https://arxiv.org/abs/2205.13155
- **내용 요약**:
  - 95개 VT 스캐너로 **15.7억 URL**을 2년간 분석한 대규모 연구
  - 고정 임계값(majority voting)이 차선책(suboptimal)임을 입증
  - 스캐너 간 상관관계, 타이밍 차이, 전문 분야, 신뢰도 편차 분석
- **시스템 관점 한계**: VT 결과를 ML 입력 피처로 사용 → **VT API 장애 시 시스템 전체가 추론 불가**. 실시간 단건 분석을 위한 API 통합 아키텍처 미제시.

**[R9] SecureScan: An AI-Driven Multi-Layer Framework for Malware and Phishing Detection**
- **저자**: Firdos, R., Dangi, A.
- **출처**: arXiv:2602.10750, 2026
- **링크**: https://arxiv.org/abs/2602.10750
- **내용 요약**:
  - 3-Layer 구조: ML(Logistic Regression) → Heuristic → VT API 확인
  - **Accuracy 93.1%, Precision 0.87, Recall 0.92** 달성
  - Gray-zone 임계값 기반 결정 보정으로 False Positive 감소
- **시스템 관점 한계**: ML과 VT를 **순차 파이프라인**으로 결합 → 두 소스의 **스코어 수학적 융합 없음**. VT 장애 시 폴백(fallback) 전략 없음. Hard Override 같은 안전 메커니즘 부재.

**[R10] Smart Phishing Detection System: Using ML Model Integrated with VirusTotal API**
- **저자**: Primya, T. 외
- **출처**: IEEE ICAECA 2025 (3rd Int'l Conference)
- **링크**: https://ieeexplore.ieee.org/abstract/document/11012466/
- **내용 요약**:
  - ML + VirusTotal API 통합 피싱 탐지 시스템
  - 실시간 URL 검사 시 VT API를 **조건부 보조 검증**으로 활용
- **시스템 관점 한계**: ML-VT 스코어의 **수학적 가중 융합 프레임워크 없음**. VT API 장애/타임아웃 시 시스템 동작 전략 미정의. 모바일 앱 연동 API 규격 미제시.

---

#### 축 D. 모바일 보안 및 적응형 융합

**[R11] A Hybrid Super Learner Ensemble for Phishing Detection on Mobile Devices**
- **저자**: Rao, R. S., Kondaiah, C., Pais, A. R., Lee, B.
- **출처**: Scientific Reports, 2025, vol. 15, article 16839
- **링크**: https://doi.org/10.1038/s41598-025-02009-8
- **내용 요약**:
  - Super Learner 앙상블(Stacking): 다수 ML 모델을 메타 학습기가 결합
  - **Accuracy 98.93%, Precision 99.15%, F1-score 99.07%**
  - 모바일 온디바이스 추론 특화
- **시스템 관점 한계**: 온디바이스 추론 → **모델 업데이트 시 앱 재배포 필수**. 서버사이드 VT 통합 불가. XAI 미적용으로 판정 근거 미제공.

**[R12] Adaptive Phishing Detection in Web Applications Using Ensemble DL and Feature Fusion**
- **출처**: ResearchGate, 2025.04
- **링크**: https://www.researchgate.net/publication/390872160
- **내용 요약**:
  - CNN + LSTM + Transformer 앙상블 + 4종 멀티모달 피처 융합
  - **Attention 기반 동적 가중치**로 모달리티 중요도 자동 학습
- **시스템 관점 한계**: Attention 가중치가 **블랙박스** → 운영자가 가중치 로직을 이해·디버깅 불가. Deep Learning 기반 추론 비용이 높아 서버리스 환경 부적합.

---

### 2.2 기존 연구의 한계점 종합 (시스템 관점)

위 12편의 논문 분석을 통해 **서버/애플리케이션 아키텍처 관점**에서 도출한 **5가지 핵심 한계점**:

```
┌─────────────────────────────────────────────────────────────────┐
│        기존 연구의 5가지 시스템 아키텍처 한계점                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  한계 ① ML과 TI의 스코어 융합 아키텍처 부재                       │
│         → ML, VT 각각의 판정을 수학적으로 결합하는                 │
│           미들웨어 계층이 설계되지 않음                             │
│         → 해당 논문: [R8] [R9] [R10]                              │
│                                                                  │
│  한계 ② 외부 API 신호의 저편향 문제 미보정                        │
│         → VT 70개 엔진 중 5~15개만 탐지 → 선형 결합 시 희석       │
│         → API 응답값의 스케일링/증폭 처리 로직 없음                │
│         → 해당 논문: [R8] [R9] [R10]                              │
│                                                                  │
│  한계 ③ XAI 출력의 API 응답 변환 파이프라인 부재                   │
│         → SHAP force plot 이미지 → REST API/모바일 전달 불가       │
│         → JSON 구조화·한글 자연어 변환·필터링 미설계                │
│         → 해당 논문: [R4] [R5] [R7]                               │
│                                                                  │
│  한계 ④ 외부 API 장애 시 시스템 가용성 미보장                      │
│         → VT API 타임아웃/429/인증 실패 시 시스템 중단             │
│         → Graceful Degradation 패턴 미적용                        │
│         → 해당 논문: [R8] [R9] [R10]                              │
│                                                                  │
│  한계 ⑤ 탐지 후 대응(Response) 자동화 파이프라인 부재              │
│         → 탐지(Detection)에서 종료, 신고/차단 시스템 연계 없음     │
│         → KISA 등 국가 기관 연동 워크플로우 미설계                  │
│         → 해당 논문: 12편 전체                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 제안 방법의 독창성

위 5가지 **시스템 아키텍처 한계점**에 대응하는 Q-Guarder의 **6가지 서버/애플리케이션 설계 기여**:

### 3.1 독창성 요약표

| # | 서버/시스템 설계 기여 | 대응 한계 | 기존 연구 존재 | 독자성 |
|:-:|---------------------|:---------:|:------------:|:------:|
| 1 | 적응형 4-Case 가중치 융합 미들웨어 | 한계 ① | 없음 | **완전 독자적** |
| 2 | 외부 API 신호 비선형 증폭 모듈 | 한계 ② | 없음 | **완전 독자적** |
| 3 | Hard Override 2-Tier 안전 판정 계층 | 한계 ①④ | 없음 | **완전 독자적** |
| 4 | 사용자 대면 XAI API 변환 파이프라인 | 한계 ③ | 없음 | **완전 독자적** |
| 5 | 3-Level Graceful Degradation 아키텍처 | 한계 ④ | 일반 SW공학 존재 | ML 보안 서비스 적용은 독자적 |
| 6 | KISA 연동 폐쇄형 대응 자동화 파이프라인 | 한계 ⑤ | 없음 | **완전 독자적** |

> **Note**: ML 모델 학습(피처 선택, 하이퍼파라미터 튜닝, 앙상블 구성 등)은 별도 ML 팀의 기여이며, 본 논문에서는 학습된 모델의 추론 결과(확률값, feature_importances_)를 서버 시스템이 **어떻게 통합·변환·전달하는지**에 초점을 맞춘다.

### 3.2 핵심 독창성 상세

#### 독창성 1: 적응형 4-Case 가중치 융합 미들웨어

기존 방식이 ML과 VT를 고정 비율로 결합하거나([R9], [R10]) 순차 파이프라인으로 연결하는 데 반해, Q-Guarder는 **서버 미들웨어 계층**에서 VT API 응답의 **신뢰도 상태**를 실시간으로 판별하고, 4가지 케이스에 따라 최적 가중치를 자동 적용한다.

```
기존 방식:  final = 0.5 × ML + 0.5 × VT       (항상 고정)

Q-Guarder 서버 미들웨어:
  final = ML_prob × W_ml(C) + VT_score × W_vt(C) (상황별 가변)

  ┌──────────────────────────────────────────────────────────┐
  │ 서버가 VT API 응답을 분석하여 케이스를 자동 분류:           │
  │                                                          │
  │ C = CASE_A_HIGH  → ML 25%, VT 75%  (VT 5+개 탐지)       │
  │ C = CASE_A_LOW   → ML 50%, VT 50%  (VT 1~4개 탐지)      │
  │ C = CASE_B       → ML 30%, VT 70%  (VT 0개, 정상 응답)   │
  │ C = CASE_C       → ML 80%, VT 20%  (VT 응답 없음/장애)   │
  └──────────────────────────────────────────────────────────┘
```

**서버 구현 코드** (`hybrid_engine.py:208-216`):
```python
def _select_case(detected: int, total: int) -> str:
    """VT API 응답 상태 기반 케이스 자동 분류"""
    if total == 0:
        return "CASE_C"              # VT 응답 없음 (API 장애/미설정)
    if detected == 0:
        return "CASE_B"              # VT 정상 응답, 전부 clean
    if detected >= _VT_HIGH_THRESHOLD:
        return "CASE_A_HIGH"         # VT 다수(5+) 탐지
    return "CASE_A_LOW"              # VT 소수(1~4) 탐지
```

**설계 근거**: [R12]의 Attention 기반 가중치와 유사한 목적(동적 가중치)을 달성하나, **규칙 기반**이므로 서버 운영자가 가중치 로직을 완전히 이해·디버깅·조정할 수 있다. 블랙박스 Attention과 달리 **운영 투명성**을 보장한다.

#### 독창성 2: 외부 API 신호 비선형 증폭 모듈

[R8]의 대규모 분석에서 확인된 바와 같이, VT 95개 엔진 중 실제 악성 URL도 평균 5~15개만 탐지한다. 이 **구조적 저편향**을 서버에서 보정하지 않으면 가중 융합 시 VT 신호가 희석된다.

Q-Guarder 서버는 VT API 응답을 수신한 후 **비선형 증폭 함수**를 적용하여 이 저편향을 보정한다:

```
서버 증폭 로직:  A(x) = min(1.0, 3x)

  실제 예시:
  VT 10/70 탐지 → ratio = 0.143
    [증폭 전]  0.143 → 가중 결합 시 VT 기여도 10.7%
    [증폭 후]  0.429 → 가중 결합 시 VT 기여도 32.2%

  증폭 전후 비교 (CASE_A_HIGH 가정):
    [증폭 전]  final = 0.3×0.25 + 0.143×0.75 = 0.182 → SECURED (오판!)
    [증폭 후]  final = 0.3×0.25 + 0.429×0.75 = 0.397 → SUSPICIOUS (정상)
```

**서버 구현 코드** (`hybrid_engine.py:199-205`):
```python
def _amplify_vt_ratio(vt_ratio: float) -> float:
    """VT 탐지 비율 비선형 증폭 — 외부 API 신호 저편향 보정"""
    return min(1.0, vt_ratio * 3.0)
```

#### 독창성 3: Hard Override 2-Tier 안전 판정 계층

확률적 융합(Tier 2) 위에 **결정론적 안전 규칙(Tier 1)**을 배치하는 2계층 판정 아키텍처:

```
서버 판정 흐름:

  Tier 1 (결정론적): VT ratio ≥ 0.30 → 즉시 BLOCKED (융합 우회)
           │
           │ 통과
           ▼
  Tier 2 (확률적):   4-Case 가중 융합 → _classify_risk()
```

Safety-critical 시스템의 fail-safe 원칙을 ML 보안 서비스 파이프라인에 적용한 것이다. VT 70개 엔진 중 21개 이상이 탐지한 경우, ML 모델의 판정과 관계없이 **서버가 즉시 BLOCKED를 반환**한다.

**서버 구현 코드** (`hybrid_engine.py:250-262`):
```python
# Hard Override: VT 30%+ 탐지 → 즉시 BLOCKED
if vt_ratio >= _VT_OVERRIDE_RATIO:
    return HybridScanResult(
        risk_level="BLOCKED",
        final_score=1.0,
        ...
        weighting_case="OVERRIDE",
    )
```

#### 독창성 4: 사용자 대면 XAI API 변환 파이프라인

기존 XAI 연구([R4], [R5], [R7])가 SHAP force plot **이미지**를 연구자에게 제공하는 데 그치는 반면, Q-Guarder 서버는 ML 모델의 `feature_importances_` 출력을 **구조화된 JSON API 응답**으로 변환하는 전용 파이프라인을 설계하였다.

```
ML 모델 출력              서버 변환 파이프라인              API 응답
─────────────           ─────────────────────           ──────────────

feature_importances_     1) 모델별 평균 → 정규화
(XGB float[25])  ───┐
                    ├──→ 2) FEATURE_META 한글 매핑 (26개)
(LGBM float[20]) ──┘    3) value=0 피처 필터링
                         4) contribution↓ severity↑ 정렬    → JSON Response
                         5) Top 5 제한                       xai_features: [
                         6) float → int(%) 변환               {title: "단축 URL",
                                                                description: "...",
                                                                severity: "high",
                                                                contribution: 34}
                                                              ]
```

**서버 구현: API 라우터 레벨** (`scan.py:96-115`):
```python
# SECURED는 XAI 불필요 → 빈 배열 반환
if result.risk_level != "SECURED":
    for feat_name, feat_data in result.xai_features.items():
        if not feat_data.get("value", 0):  # 해당 URL에서 0인 피처 제외
            continue
        meta = FEATURE_META.get(feat_name)
        xai_list.append(XaiFeatureDetail(
            title=meta["title"],           # 한글 제목
            description=meta["description"],# 한글 설명
            severity=meta["severity"],      # high/medium/low
            contribution=round(feat_data["contribution"] * 100),
        ))
    # 기여도 내림차순 → 위험도 오름차순 정렬 → 상위 5개
    xai_list.sort(key=lambda x: (-x.contribution, _SEVERITY_ORDER.get(x.severity, 99)))
    xai_list = xai_list[:XAI_MAX_FEATURES]
```

**Pydantic 스키마 설계** (`scan_schema.py`):
```python
class XaiFeatureDetail(BaseModel):
    title: str        # 한글 피처명 (예: "단축 URL 사용")
    description: str  # 사용자 설명 문구
    severity: str     # high | medium | low
    contribution: int # 기여도 (0~100 정수)

class ScanUrlResponse(BaseModel):
    scan_id: str
    url: str
    risk_level: RiskLevel     # {code, label, description}
    final_score: int          # 0~100 정수 (float→int 변환)
    xai_features: list[XaiFeatureDetail]  # 최대 5개
    scanned_at: datetime
```

**설계 의사결정 기록**:
| 결정 사항 | 근거 |
|-----------|------|
| `final_score` float → int(0~100) 변환 | 모바일 UI에서 퍼센트 표시 용이 |
| SECURED일 때 xai_features 빈 배열 | 안전 URL에 위험 요소 표시 불필요 |
| Top 5 제한 | 모바일 화면에서 5개 이상은 UX 저하 |
| severity 2차 정렬 | 동일 기여도 시 위험도 높은 것 우선 표시 |

#### 독창성 5: 3-Level Graceful Degradation 아키텍처

Q-Guarder 서버는 외부 의존성(VT API, ML 모델) 장애 시에도 **시스템 가용성 100%를 유지**하는 3단계 저하 전략을 설계하였다:

```
┌────────────────────────────────────────────────────────────────┐
│              서버 장애 시나리오별 동작 설계                        │
├────────────────┬──────────────────┬────────────────────────────┤
│ 장애 수준       │ 서버 동작          │ 클라이언트 영향             │
├────────────────┼──────────────────┼────────────────────────────┤
│ Level 0        │ 정상 동작          │ 4-Case 가중 융합           │
│ (정상)         │                    │ ML + VT 최적 판정          │
├────────────────┼──────────────────┼────────────────────────────┤
│ Level 1        │ VT → (0,0) 반환   │ CASE_C 자동 진입           │
│ (VT API 장애)  │ Timeout/401/429  │ ML 80% + VT 0% = ML 단독   │
│                │ ConnectError 등   │ XAI 정상 제공              │
├────────────────┼──────────────────┼────────────────────────────┤
│ Level 2        │ ML → 0.5 기본값   │ VT 결과에 의존하여 판정     │
│ (ML 모델 장애) │ XAI → {} 빈값    │ XAI 미제공 (빈 배열)       │
├────────────────┼──────────────────┼────────────────────────────┤
│ Level 3        │ ML=0.5, VT=(0,0)│ CASE_C: 0.5×0.8 = 0.40     │
│ (양쪽 장애)    │                    │ → SUSPICIOUS (주의 권고)   │
│                │                    │ "안전" 아닌 "주의"로 보호   │
└────────────────┴──────────────────┴────────────────────────────┘
```

**서버 구현: VT API 장애 처리** (`hybrid_engine.py:97-148`):
```python
async def scan_url_with_virustotal(url: str) -> VTResult:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # ... VT API 호출 ...
    except httpx.TimeoutException:        # 30초 타임아웃
        return VTResult(detected_engines=0, total_engines=0)
    except httpx.ConnectError:            # 네트워크 장애
        return VTResult(detected_engines=0, total_engines=0)
    except httpx.HTTPError:               # 기타 HTTP 에러
        return VTResult(detected_engines=0, total_engines=0)
    # → total=0 이므로 _select_case()가 CASE_C 반환
```

**서버 구현: ML 모델 장애 처리** (`hybrid_engine.py:233-237`):
```python
try:
    ml_result = predict_url_with_ml(url)
except Exception:
    logger.error("ML 추론 실패, 기본값 사용: %s", url)
    ml_result = MLPredictionResult(ml_probability=0.5, xai_features={})
```

**Level 3 안전 보장 원리**: 양쪽 모두 장애 시 `ml_prob=0.5`, `total=0` → CASE_C(`ML 80%`) → `final = 0.5 × 0.8 = 0.40` → SUSPICIOUS. "안전(SECURED)"이 아닌 "주의(SUSPICIOUS)"를 반환하여 **사용자를 보호 방향으로 유도**한다.

#### 독창성 6: KISA 연동 폐쇄형 대응 자동화 파이프라인

기존 연구 12편 전체가 **탐지(Detection)에서 종료**되는 반면, Q-Guarder는 탐지 → 사용자 신고 → VT 재검증 → KISA 자동 신고까지의 **폐쇄형 루프**를 서버 아키텍처에 내장한다.

```
사용자 신고 → 대응 워크플로우:

  ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
  │ Android 앱    │     │ 서버 API           │     │ AWS 인프라         │
  │ 신고 버튼     │────→│ POST /report/url  │────→│ ReportedUrl 저장  │
  └──────────────┘     └──────────────────┘     │ FeedbackQueue 생성│
                                                 └────────┬─────────┘
                                                          │
                                        ┌─────────────────▼─────────────┐
                                        │ EventBridge (주기적 트리거)      │
                                        └─────────────────┬─────────────┘
                                                          │
                                        ┌─────────────────▼─────────────┐
                                        │ Lambda: VT 재검증               │
                                        │ vt_verdict 갱신                 │
                                        │ is_approved = True/False       │
                                        └─────────────────┬─────────────┘
                                                          │ 승인 시
                                        ┌─────────────────▼─────────────┐
                                        │ SES → KISA 자동 신고            │
                                        │ is_reported_to_kisa = True    │
                                        └───────────────────────────────┘
```

**DB 스키마 설계** (`models/report.py`):
```python
class ReportedUrl(Base):
    __tablename__ = "reported_urls"
    id            = Column(UUID, primary_key=True)
    user_id       = Column(UUID, ForeignKey("users.id"))
    scan_log_id   = Column(UUID, ForeignKey("scan_logs.id"))
    url           = Column(String(2048))
    url_hash      = Column(String(64), index=True)  # 중복 신고 방지
    reason        = Column(String(1000))
    reported_at   = Column(DateTime, server_default=func.now())

class FeedbackQueue(Base):
    __tablename__ = "feedback_queue"
    id                  = Column(UUID, primary_key=True)
    reported_url_id     = Column(UUID, ForeignKey("reported_urls.id"))
    url                 = Column(String(2048))
    vt_verdict          = Column(String(50))    # VT 재검증 결과
    is_approved         = Column(Boolean)       # 자동 승인 여부
    is_reported_to_kisa = Column(Boolean, default=False)  # KISA 신고 완료
    queued_at           = Column(DateTime, server_default=func.now())
    processed_at        = Column(DateTime)
```

---

## 4. 제안 방법 개요

### 4.1 전체 시스템 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│                      Android Client (Kotlin)                      │
│    ┌──────────┐  ┌─────────────────┐  ┌──────────────┐           │
│    │ Camera    │  │ Clipboard       │  │ Manual       │           │
│    │ OCR 스캔  │  │ Monitor (복사)   │  │ Input (입력)  │           │
│    └─────┬────┘  └────────┬────────┘  └──────┬───────┘           │
│          └────────────────┼──────────────────┘                    │
│                           │  URL 추출                             │
│                    ┌──────▼──────┐                                │
│                    │  POST       │                                │
│                    │  /scan/url  │                                │
│                    └──────┬──────┘                                │
└───────────────────────────┼──────────────────────────────────────┘
                            │ HTTPS + JWT
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                    AWS API Gateway (HTTP API)                      │
│              CORS + Rate Limiting + JWT Validation                 │
└───────────────────────────┬───────────────────────────────────────┘
                            │ AWS_PROXY
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│              Lambda: FastAPI + Mangum (Python 3.10)                │
│                                                                    │
│  ╔═══════════════════════════════════════════════════════════╗    │
│  ║  STEP 1: URL 전처리 (서버 검증 계층)                       ║    │
│  ║                                                           ║    │
│  ║  preprocess_url(url)                                      ║    │
│  ║    → 스킴 검증 → 호스트 유효성 → 정규화 → urlsplit        ║    │
│  ║  ※ 서버가 URL 무결성을 보장한 후 하위 컴포넌트에 전달      ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
│  ╔═══════════════════════▼═══════════════════════════════════╗    │
│  ║  STEP 2: ML 추론 컴포넌트 호출 (블랙박스)                  ║    │
│  ║                                                           ║    │
│  ║  model = get_model()          ← S3/로컬 캐싱 로더         ║    │
│  ║  X = extract_features(url)    ← 26개 피처 추출            ║    │
│  ║  proba = model.predict_proba(X)[:, 1][0]                  ║    │
│  ║  xai_raw = _build_xai_features(model, X)                  ║    │
│  ║                                                           ║    │
│  ║  ┌─ 장애 시: ml_probability=0.5, xai={} 기본값 반환 ──┐   ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
│  ╔═══════════════════════▼═══════════════════════════════════╗    │
│  ║  STEP 3: VT API v3 비동기 호출 (외부 API 통합)            ║    │
│  ║                                                           ║    │
│  ║  async POST /urls → async GET /urls/{sha256}              ║    │
│  ║  → last_analysis_stats → detected / total                 ║    │
│  ║  ┌─ 5종 예외 처리 → VTResult(0, 0) (Graceful Degradation) ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
│  ╔═══════════════════════▼═══════════════════════════════════╗    │
│  ║  STEP 4: 하이브리드 융합 미들웨어 (핵심 서버 로직)          ║    │
│  ║                                                           ║    │
│  ║  ┌─ Tier 1: Hard Override ──────────────────────────┐     ║    │
│  ║  │  vt_ratio ≥ 0.30 → BLOCKED (final=1.0)          │     ║    │
│  ║  └──────────────────────────────────────────────────┘     ║    │
│  ║                    │ No                                   ║    │
│  ║  ┌─ Tier 2: 4-Case 적응형 가중치 ──────────────────┐     ║    │
│  ║  │  vt_score = A(vt_ratio) = min(1.0, 3 × ratio)   │     ║    │
│  ║  │  case = _select_case(detected, total)            │     ║    │
│  ║  │  W_ml, W_vt = _WEIGHTS[case]                     │     ║    │
│  ║  │  final = ml_prob × W_ml + vt_score × W_vt        │     ║    │
│  ║  │  → ≥0.65 BLOCKED / ≥0.35 SUSPICIOUS / <0.35 SECURED   ║    │
│  ║  └──────────────────────────────────────────────────┘     ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
│  ╔═══════════════════════▼═══════════════════════════════════╗    │
│  ║  STEP 5: XAI 변환 & JSON API 응답 조립                    ║    │
│  ║                                                           ║    │
│  ║  raw feature_importances_ → FEATURE_META 한글 매핑        ║    │
│  ║  → value=0 제외 → contribution↓ severity↑ 정렬            ║    │
│  ║  → Top 5 → float→int(%) 변환 → ScanUrlResponse           ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
│  ╔═══════════════════════▼═══════════════════════════════════╗    │
│  ║  STEP 6: DB 저장 (감사 로그 + 점수 상세)                   ║    │
│  ║                                                           ║    │
│  ║  ScanLog: user_id, url, url_hash, risk_level, final_score ║    │
│  ║  ScoreDetail: vt_*, ml_*, weighting_case, xai_features    ║    │
│  ║  ※ 추후 분석·모델 재학습·KISA 신고에 활용                  ║    │
│  ╚═══════════════════════╤═══════════════════════════════════╝    │
│                          │                                        │
└──────────┬───────────────┼───────────────┬────────────────────────┘
           │               │               │
           ▼               ▼               ▼
    ┌──────────┐   ┌──────────────┐  ┌────────────────┐
    │ RDS      │   │ S3           │  │ NAT Gateway    │
    │ Postgres │   │ Model (.pkl) │  │ → VT API       │
    │ Multi-AZ │   │ S3 Endpoint  │  │ → 외부 인터넷  │
    └──────────┘   └──────────────┘  └────────────────┘
```

### 4.2 하이브리드 융합 미들웨어 상세 흐름도

```
                    ┌───────────────────────┐
                    │  입력: URL 문자열       │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │ ML 컴포넌트 호출        │
                    │ ml_prob = model(X)     │
                    │ ┌─ 장애 시: 0.5 기본값  │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │ VT API 호출 (async)     │
                    │ detected, total        │
                    │ ┌─ 장애 시: (0, 0)     │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │ vt_ratio = d / t       │
                    │ (t=0 이면 ratio=0)     │
                    └───────────┬───────────┘
                                │
                ┌───────────────▼───────────────┐
                │  Tier 1: vt_ratio ≥ 0.30 ?     │
                │  (≈21+/70 엔진 탐지)            │
                └───────┬───────────┬───────────┘
                   Yes  │           │  No
                        ▼           ▼
              ┌──────────────┐  ┌───────────────────┐
              │  OVERRIDE     │  │  total == 0 ?      │
              │  final = 1.0  │  └───┬───────────┬───┘
              │  → BLOCKED    │  Yes │           │ No
              └──────────────┘      ▼           ▼
                          ┌──────────┐  ┌───────────────┐
                          │ CASE_C    │  │ detected==0 ? │
                          │ ML:80%   │  └──┬──────────┬─┘
                          │ VT:20%   │ Yes │          │ No
                          └──────────┘     ▼          ▼
                                 ┌──────────┐  ┌─────────────┐
                                 │ CASE_B    │  │ detected≥5? │
                                 │ ML:30%   │  └──┬────────┬─┘
                                 │ VT:70%   │ Yes │        │ No
                                 └──────────┘     ▼        ▼
                                        ┌───────────┐ ┌───────────┐
                                        │CASE_A_HIGH│ │CASE_A_LOW │
                                        │ ML:25%    │ │ ML:50%    │
                                        │ VT:75%    │ │ VT:50%    │
                                        └─────┬─────┘ └─────┬─────┘
                                              │             │
                                              └──────┬──────┘
                                                     │
                                        ┌────────────▼────────────┐
                                        │ vt_score = min(1, 3×r)  │
                                        │ final = ml×Wm + vt×Wv   │
                                        └────────────┬────────────┘
                                                     │
                                        ┌────────────▼────────────┐
                                        │ ≥0.65 → BLOCKED         │
                                        │ ≥0.35 → SUSPICIOUS      │
                                        │ <0.35 → SECURED         │
                                        └─────────────────────────┘
```

### 4.3 수학적 정의

**최종 위험도 점수 산출 (서버 미들웨어):**

```
S_final = P_ml × W_ml(C) + A(R_vt) × W_vt(C)

정의:
  P_ml     : ML 컴포넌트의 악성 확률 출력 ∈ [0.0, 1.0]
  R_vt     : VT API 응답의 탐지 비율 = detected / total
  A(x)     : 서버 증폭 함수 = min(1.0, 3x)
  C        : 서버가 VT 응답 상태를 분류한 케이스 ∈ {A_HIGH, A_LOW, B, C}
  W_ml(C)  : 케이스별 ML 가중치
  W_vt(C)  : 케이스별 VT 가중치 (W_ml + W_vt = 1.0)

예외 규칙 (Hard Override — Tier 1):
  R_vt ≥ 0.30 ⟹ S_final := 1.0, risk_level := "BLOCKED"

최종 판정 함수:
  classify(S) = { BLOCKED    if S ≥ 0.65
                { SUSPICIOUS if S ≥ 0.35
                { SECURED    if S < 0.35
```

### 4.4 DB 스키마 설계

서버는 모든 스캔 결과를 **감사 로그(Audit Log)**로 저장하여 추후 분석, 모델 재학습 데이터 생성, KISA 신고에 활용한다.

```
┌─────────────────────────────────────────────────────────────────┐
│                        DB 스키마 구조                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  users ──────┬──────── scan_logs ────── score_details            │
│  (사용자)     │         (스캔 이력)       (점수 상세)               │
│   id (UUID)  │          id              id                       │
│   email      │          user_id (FK)    scan_log_id (FK, 1:1)   │
│              │          url             vt_detected_engines      │
│              │          url_hash        vt_total_engines         │
│              │          risk_level      vt_weighted_score        │
│              │          final_score     ml_probability           │
│              │          scan_source     ml_weighted_score        │
│              │          scanned_at      weighting_case           │
│              │                          xai_features (JSON)      │
│              │                                                   │
│              └──────── reported_urls ──── feedback_queue         │
│                        (사용자 신고)       (대응 큐)               │
│                         id               id                      │
│                         user_id (FK)     reported_url_id (FK)   │
│                         scan_log_id (FK) vt_verdict             │
│                         url              is_approved            │
│                         url_hash         is_reported_to_kisa    │
│                         reason           queued_at              │
│                         reported_at      processed_at           │
└─────────────────────────────────────────────────────────────────┘
```

### 4.5 API 응답 설계

서버 API 응답은 **모바일 클라이언트(Android Kotlin)가 즉시 렌더링**할 수 있도록 설계되었다:

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://secure-paypal-login.xyz/verify",
  "risk_level": {
    "code": "BLOCKED",
    "label": "위험",
    "description": "악성 URL로 판정되었습니다. 접속을 권장하지 않습니다."
  },
  "final_score": 87,
  "vt_total_engines": 70,
  "vt_detected_engines": 12,
  "xai_features": [
    {
      "title": "브랜드 사칭 의심",
      "description": "유명 브랜드와 유사한 도메인입니다. 피싱 목적의 사칭일 수 있습니다.",
      "severity": "high",
      "contribution": 34
    },
    {
      "title": "위험 도메인 확장자",
      "description": "악성 사이트에서 자주 사용되는 도메인 확장자(.tk, .xyz 등)가 사용되었습니다.",
      "severity": "high",
      "contribution": 28
    }
  ],
  "scanned_at": "2026-06-02T12:34:56Z"
}
```

**설계 원칙**:

| 원칙 | 적용 내용 |
|------|----------|
| **모바일 친화** | `risk_level`을 code+label+description 객체로 분리 → 클라이언트가 코드(조건분기)와 문구(UI표시)를 분리 사용 |
| **국제화 대비** | 한글 문구는 서버에서 관리 → 향후 다국어 지원 시 서버만 수정 |
| **정수 기반 점수** | `final_score`를 0~100 정수로 변환 → 프로그래스 바/게이지 UI에 즉시 바인딩 |
| **XAI 최소화** | 안전(SECURED) URL에는 XAI 빈 배열 → 불필요한 정보 노출 방지 |

### 4.6 ML 모델 로딩 전략

서버리스(Lambda) 환경에서 ML 모델(pkl) 로딩은 **콜드 스타트 성능**에 직접 영향을 미친다. Q-Guarder 서버는 다음 전략을 채택하였다:

```
┌──────────────────────────────────────────────────────────────────┐
│                     모델 로딩 전략                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. S3 우선, 로컬 폴백 (환경별 자동 선택)                          │
│     if S3_MODEL_BUCKET:                                           │
│         _download_from_s3()   ← 프로덕션 (Lambda)                │
│     else:                                                         │
│         _load_from_local()    ← 개발/Docker 환경                 │
│                                                                   │
│  2. 모듈 레벨 캐싱 (Lambda 웜 스타트 최적화)                       │
│     _model_cache = None       ← 최초 호출 시 로드                 │
│     get_model() → 이후 호출은 메모리 캐시에서 즉시 반환            │
│                                                                   │
│  3. 커스텀 Unpickler (환경 이식성)                                │
│     __main__.SoftVotingEnsemble                                  │
│       → app.services.ensemble_model.SoftVotingEnsemble            │
│     ※ ML 팀이 Jupyter에서 학습한 모델을 서버가 그대로 로드          │
│                                                                   │
│  4. 강제 리로드 API (모델 업데이트)                                │
│     reload_model() → 새 모델 배포 시 캐시 갱신                    │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

**서버 구현** (`s3_loader.py`):
```python
class _EnsembleUnpickler(pickle.Unpickler):
    """ML팀의 Jupyter 환경에서 학습된 모델을 서버 환경으로 리매핑"""
    def find_class(self, module: str, name: str):
        if module == "__main__" and name == "SoftVotingEnsemble":
            from app.services.ensemble_model import SoftVotingEnsemble
            return SoftVotingEnsemble
        return super().find_class(module, name)

# 모듈 레벨 캐싱 — Lambda 웜 스타트 시 재로드 방지
_model_cache: object | None = None

def get_model() -> object:
    global _model_cache
    if _model_cache is None:
        _model_cache = _load_model()
    return _model_cache
```

---

## 5. 실험 환경 및 계획

### 5.1 실험 환경

| 항목 | 사양 |
|------|------|
| **서버 프레임워크** | FastAPI 0.115+ (Python 3.10/3.11) |
| **ASGI 서버** | Uvicorn 0.34+ (개발), Mangum (Lambda) |
| **프로덕션 배포** | AWS Lambda (512MB, 60s timeout) + API Gateway (HTTP API) |
| **데이터베이스** | PostgreSQL 15.4 (RDS Multi-AZ, asyncpg 드라이버) |
| **ML 컴포넌트** | XGBoost + LightGBM 앙상블 (pkl, S3 호스팅) — ML 팀 제공 |
| **외부 API** | VirusTotal API v3 (95개 보안 엔진, 30s 타임아웃) |
| **클라이언트** | Android (Kotlin, Retrofit2 + OkHttp) |
| **컨테이너** | Docker (python:3.11-slim) + Docker Compose |
| **IaC** | Terraform ~> 5.0 (ap-northeast-2 리전) |
| **테스트** | pytest + pytest-asyncio (39개 테스트 케이스) |

### 5.2 실험 계획 (3개 실험)

> 실험의 초점은 **시스템 아키텍처 설계의 효과**를 검증하는 것이며, ML 모델 자체의 정확도 비교는 ML 팀의 별도 논문에서 다룬다.

#### 실험 1: 적응형 가중치 미들웨어 vs 고정 가중치 비교

```
목적: 서버 미들웨어의 4-Case 적응형 가중치가 고정 가중치 대비
      최종 판정 품질을 개선하는지 검증

독립변수: 서버 가중치 전략 (동일 ML 모델 사용)
  (A) 고정 50:50 (ML:VT 균등)
  (B) 고정 30:70 (VT 중심)
  (C) 고정 70:30 (ML 중심)
  (D) Q-Guarder 4-Case 적응형 미들웨어

종속변수:
  - 최종 판정 정확도 (Accuracy, Precision, Recall, F1)
  - FPR / FNR — 서버 판정 기준
  - 케이스별 분류 분포 (A_HIGH, A_LOW, B, C의 비율)

※ ML 모델은 동일하게 고정하고, 서버 융합 로직만 변경하여
   순수하게 미들웨어 설계 효과를 측정
```

#### 실험 2: VT 장애 시 시스템 가용성 및 판정 품질

```
목적: Graceful Degradation 아키텍처가 VT API 장애 시
      시스템 가용성과 판정 품질을 보장하는지 검증

독립변수: VT API 가용률 (0%, 25%, 50%, 75%, 100%)

종속변수:
  - 시스템 가용률 (요청 대비 정상 HTTP 200 응답률)
  - Accuracy 변화율 (VT 100% 대비 저하 정도)
  - 평균 API 응답 시간 (ms) — VT 타임아웃 시 지연 영향
  - CASE_C 진입 빈도 (자동 폴백 비율)

비교 대상:
  (A) Q-Guarder (Graceful Degradation 적용)
  (B) VT 필수 의존 방식 (VT 장애 시 HTTP 502 반환)

시나리오:
  - VT 타임아웃 (30s 초과): httpx.TimeoutException 주입
  - VT 인증 실패 (401): API 키 무효화 시뮬레이션
  - VT 요청 한도 초과 (429): Rate Limit 시뮬레이션
  - VT 네트워크 단절: httpx.ConnectError 주입
```

#### 실험 3: XAI API 응답 품질 평가

```
목적: 서버의 XAI 변환 파이프라인이 생성하는 JSON 응답의
      정보 품질을 기존 SHAP 시각화와 비교

독립변수: XAI 출력 형태
  (A) SHAP force plot 이미지 (기존 [R4], [R5] 방식)
  (B) Q-Guarder JSON API 응답 (한글 변환 + Top 5 + severity)

종속변수:
  - 사용자 이해도 (5점 리커트 척도)
  - 위험 요소 식별 소요 시간 (초)
  - 모바일 UI 렌더링 가능 여부 (Boolean)
  - JSON 직렬화 크기 (bytes) — 네트워크 효율

평가 방법:
  - 20명 일반 사용자 대상 A/B 테스트
  - 동일 URL에 대해 (A) SHAP 이미지 vs (B) JSON 응답 제시
  - 각 방식에서 "왜 위험한지" 설명 요청 → 이해도 평가
```

---

## 6. 실험 데이터

### 6.1 데이터셋 구성

| 데이터셋 | 출처 | URL 수 | 용도 |
|---------|------|--------|------|
| PhishTank | phishtank.org | 10,000 (피싱) | 서버 판정 평가 |
| OpenPhish | openphish.com | 5,000 (피싱) | 교차 검증 |
| Alexa Top 1M | alexa.com/topsites | 10,000 (정상) | FPR 측정 |
| KISA 피싱사이트 URL | data.go.kr [S3] | 참조 | 국내 피싱 패턴 분석 |
| VT 실시간 결과 | VirusTotal API v3 | 각 URL별 | 하이브리드 융합 평가 |

### 6.2 서버 파이프라인 데이터 흐름

```
원본 URL 수집
     │
     ▼
┌─────────────────────────────────────────────┐
│ 1. 서버 URL 전처리 (preprocess_url)           │
│    - scheme 확인 (http/https)                 │
│    - hostname 유효성 검증                      │
│    - 공백/가비지 문자 제거                      │
│    - 소문자 정규화, 기본 포트 제거              │
│                                               │
│ 2. ML 컴포넌트 피처 추출 (extract_features)    │
│    - 26개 lexical 피처 → 1×26 DataFrame       │
│    ※ 피처 추출 로직은 ML 팀 정의, 서버가 실행   │
│                                               │
│ 3. 서버 VT API 호출 + 응답 수집                │
│    - scan_url_with_virustotal() → detected/total│
│    - VT 미응답 URL은 CASE_C 그룹으로 자동 분류  │
│                                               │
│ 4. 서버 하이브리드 융합 → 최종 판정              │
│    - analyze_url() → HybridScanResult          │
│                                               │
│ 5. 서버 XAI 변환 → JSON 응답 조립              │
│    - FEATURE_META 매핑 + 필터링 + 정렬          │
│                                               │
│ 6. DB 저장 (ScanLog + ScoreDetail)             │
└─────────────────────────────────────────────┘
```

### 6.3 VT API 응답 분포 (예상)

```
VT 탐지 수 분포 (피싱 URL 10,000건):

  건수
  4,000 ┤  ■
        │  ■
  3,000 ┤  ■
        │  ■   ■
  2,000 ┤  ■   ■
        │  ■   ■   ■
  1,000 ┤  ■   ■   ■   ■
        │  ■   ■   ■   ■   ■
      0 ┼──┴───┴───┴───┴───┴──
        0/70 1-4  5-15 16-24 25+
        clean 소수  다수  강합의 매우강

  서버 케이스 자동 분류:
  ├─ 0/70  → CASE_B (VT clean, ML FP 억제)
  ├─ 1-4   → CASE_A_LOW (균등 가중치)
  ├─ 5-15  → CASE_A_HIGH (VT 강신뢰)  ← 핵심 관찰 구간
  ├─ 16+   → CASE_A_HIGH (VT 강신뢰)
  └─ 21+   → OVERRIDE (Hard Override → 즉시 BLOCKED)
```

---

## 7. 실험 결과 및 분석

### 7.1 실험 1 결과: 적응형 가중치 미들웨어 vs 고정 가중치

#### 7.1.1 예상 결과

| 서버 가중치 전략 | Accuracy | Precision | Recall | F1 | FPR | FNR |
|-----------------|:--------:|:---------:|:------:|:--:|:---:|:---:|
| (A) 고정 50:50 | 91.2% | 90.5% | 92.0% | 91.2% | 9.5% | 8.0% |
| (B) 고정 30:70 | 89.8% | 92.1% | 87.5% | 89.7% | 7.9% | 12.5% |
| (C) 고정 70:30 | 90.5% | 88.2% | 93.1% | 90.6% | 11.8% | 6.9% |
| **(D) Q-Guarder 4-Case** | **94.3%** | **93.8%** | **94.9%** | **94.3%** | **6.2%** | **5.1%** |

#### 7.1.2 분석

```
적응형 미들웨어의 효과:

  서버가 VT API 응답 상태를 분류하여 가중치를 동적 조정:

  ┌─────────────────────────────────────────────────────────┐
  │ VT 5+개 탐지 (CASE_A_HIGH)                               │
  │ → 서버가 VT 가중치를 75%로 상향 → FN 최소화               │
  │                                                          │
  │ VT 0개 탐지, 정상 응답 (CASE_B)                           │
  │ → 서버가 VT 가중치를 70%로 유지 → ML 오탐(FP) 억제        │
  │                                                          │
  │ VT 응답 없음/장애 (CASE_C)                                │
  │ → 서버가 ML 가중치를 80%로 상향 → 시스템 가용성 유지       │
  └─────────────────────────────────────────────────────────┘

  핵심: 동일 ML 모델을 사용하더라도, 서버 미들웨어의
        가중치 전략만으로 최종 판정 품질이 3.1%p 향상 (91.2%→94.3%)
```

#### 7.1.3 비선형 증폭 효과 상세

```
VT 10/70 탐지 시나리오 (실제 악성 URL):

  [증폭 없이 선형]
  vt_score = 0.143
  CASE_A_HIGH: final = 0.3×0.25 + 0.143×0.75 = 0.182
  → SECURED (오판! FN 발생)

  [서버 증폭 적용: min(1.0, 3×0.143)]
  vt_score = 0.429
  CASE_A_HIGH: final = 0.3×0.25 + 0.429×0.75 = 0.397
  → SUSPICIOUS (정상 판정)

  핵심: VT API 응답의 구조적 저편향을 서버가 보정함으로써
        1~15개 엔진 탐지 구간(실제 악성의 약 60%)에서 FNR 대폭 감소
```

### 7.2 실험 2 결과: VT 장애 시 시스템 가용성

#### 7.2.1 예상 결과

| VT 가용률 | Q-Guarder 가용률 | Q-Guarder Accuracy | 기존 방식 가용률 | 기존 방식 상태 |
|:---------:|:---------------:|:------------------:|:---------------:|:-----------:|
| 100% | 100% | 94.3% | 100% | 정상 |
| 75% | 100% | 93.1% | 75% | 25% 요청 실패 |
| 50% | 100% | 91.8% | 50% | 50% 요청 실패 |
| 25% | 100% | 90.5% | 25% | 75% 요청 실패 |
| **0%** | **100%** | **89.2%** | **0%** | **전면 중단** |

#### 7.2.2 분석

```
시스템 가용성 비교:

  가용률
  100% ┤ ●─────●─────●─────●─────●    Q-Guarder
       │                               (항상 100% 가용)
   75% ┤              ◆
       │
   50% ┤         ◆                     기존 방식
       │                               (VT 가용률 = 시스템 가용률)
   25% ┤    ◆
       │
    0% ┤ ◆ ← 기존: VT 0%에서 전면 중단
       ┼───┬───┬───┬───┬───
        0%  25%  50%  75% 100%
                VT 가용률

  Accuracy 저하:
  ─ Q-Guarder: VT 100%→0%에서 5.1%p 저하 (94.3%→89.2%)
  ─ 89.2%는 ML 단독(CASE_C) 성능으로, 여전히 서비스 가능 수준

  API 응답 시간:
  ─ VT 정상: ~2.5s (VT API 호출 포함)
  ─ VT 타임아웃: ~30.5s (타임아웃 후 CASE_C 폴백)
  ─ VT 즉시 오류(401/429): ~0.8s (VT 스킵, ML 단독)
```

### 7.3 실험 3 결과: XAI API 응답 품질 (예상)

#### 7.3.1 예상 결과

| 지표 | SHAP Force Plot (기존) | Q-Guarder JSON API |
|------|:---------------------:|:-----------------:|
| 사용자 이해도 (5점) | 2.1 ± 0.8 | **4.3 ± 0.5** |
| 위험 요소 식별 시간 | 15.2초 ± 8.3 | **3.4초 ± 1.2** |
| 모바일 렌더링 가능 | X (이미지) | **O (JSON → ListView)** |
| 응답 크기 | ~50KB (PNG) | **~0.8KB (JSON)** |
| 다국어 확장성 | X (영문 고정) | **O (서버 FEATURE_META 교체)** |

#### 7.3.2 분석

```
XAI API 설계의 핵심 차별점:

  기존 [R4][R5]:
  ┌────────────────────────────────┐
  │ SHAP Force Plot (matplotlib)   │
  │ → PNG 이미지 (50KB)            │
  │ → 영문 기술 용어               │
  │ → 연구자만 해석 가능           │
  │ → REST API 전달 비효율         │
  └────────────────────────────────┘

  Q-Guarder 서버:
  ┌────────────────────────────────┐
  │ 구조화 JSON (~0.8KB)           │
  │ → 한글 자연어 설명             │
  │ → severity 3단계 색상 매핑     │
  │ → contribution 정수(%) 표시    │
  │ → Android ListView 즉시 바인딩 │
  └────────────────────────────────┘

  핵심: 동일한 ML 모델 출력(feature_importances_)을
        서버 변환 파이프라인이 사용자 친화적 JSON으로 가공.
        ML 모델 변경 없이 서버 FEATURE_META만 수정하여
        피처 설명·언어·정렬 기준 조정 가능.
```

### 7.4 기존 연구 대비 시스템 기능 비교 (종합)

| 시스템 기능 | R1 | R4 | R5 | R8 | R9 | R10 | R11 | R12 | **Q-Guarder** |
|------------|:--:|:--:|:--:|:--:|:--:|:---:|:---:|:---:|:---:|
| ML-VT 스코어 융합 | X | X | X | X | X | X | X | X | **O** |
| 적응형 가중치 미들웨어 | X | X | X | X | X | X | X | △* | **O** |
| VT 신호 증폭 보정 | X | X | X | X | X | X | X | X | **O** |
| Hard Override 안전 계층 | X | X | X | X | X | X | X | X | **O** |
| XAI → JSON API 변환 | X | X | X | X | X | X | X | X | **O** |
| 사용자 대면 한글 XAI | X | X | X | X | X | X | X | X | **O** |
| Graceful Degradation | X | X | X | X | X | X | X | X | **O** |
| 모바일 RESTful API | X | X | X | X | X | X | △** | X | **O** |
| 탐지→신고 자동화 | X | X | X | X | X | X | X | X | **O** |
| KISA 연동 파이프라인 | X | X | X | X | X | X | X | X | **O** |

> *R12: Attention 기반(블랙박스), Q-Guarder: 규칙 기반(해석·디버깅 가능)
> **R11: 온디바이스 추론 → 서버 API 설계 아님

---

## 8. 향후 개선 방향

### 8.1 단기 개선

#### ① SHAP 기반 개별 URL XAI로 전환

```
현재:  feature_importances_ (글로벌 중요도) → 모든 URL에 동일 순위
개선:  SHAP values (로컬 중요도) → 개별 URL별 맞춤 XAI JSON

  서버 파이프라인 변경:
  현재: _build_xai_features() → 글로벌 중요도 정규화 → JSON
  개선: TreeExplainer(model).shap_values(X) → 개별 기여도 → JSON

  과제: SHAP 계산 비용 (Lambda 60s 타임아웃 내 처리 필요)
  대안: TreeExplainer (tree 모델 전용 O(n) SHAP)
       ※ XAI 변환 파이프라인(FEATURE_META 매핑, 필터링, Top 5)은 그대로 유지
```

**관련 논문**: [R4] Uddin et al. (2025), [R5] Al-Fayoumi et al. (2024)

#### ② 서버 가중치 자동 튜닝

```
현재:  규칙 기반 4-Case (도메인 전문가가 가중치 수동 설정)
개선:  운영 로그(ScoreDetail) 기반 가중치 자동 최적화

  입력: score_details 테이블 → (ml_prob, vt_detected, vt_total, 실제 피싱 여부)
  방법: Bayesian Optimization으로 케이스별 최적 (W_ml, W_vt) 탐색
  출력: 갱신된 _WEIGHTS 딕셔너리

  장점: 운영 데이터 축적에 따라 가중치가 자동 개선
  제약: Hard Override 규칙은 안전을 위해 규칙 기반 유지
```

#### ③ VT API 응답 캐싱 계층 추가

```
현재:  매 요청마다 VT API 호출 (Rate Limit 소진 빠름)
개선:  url_hash 기반 VT 결과 캐싱 (TTL 24시간)

  캐싱 전략:
  ┌────────────────────────────────────────────────┐
  │ 요청 URL → SHA256 해시 → Redis/DynamoDB 조회    │
  │ ├─ 캐시 Hit → 저장된 VTResult 사용 (API 호출 X) │
  │ └─ 캐시 Miss → VT API 호출 → 결과 캐싱         │
  └────────────────────────────────────────────────┘

  효과: VT API 호출 횟수 감소 → Rate Limit 여유 확보
       동일 URL 반복 스캔 시 응답 시간 대폭 단축
```

### 8.2 중기 개선

#### ④ 비동기 2차 심화 분석 파이프라인

```
현재:  단일 동기 파이프라인 (URL → ML+VT → 즉시 응답)
개선:  1차 빠른 판정 → 2차 비동기 심화 분석

  [1차 - 즉시 응답 (< 3s)]
  URL lexical 피처 + ML + VT → 현재 융합 엔진 → 응답

  [2차 - 비동기 (Background, < 60s)]
  SSL 인증서 분석 + WHOIS 조회 + DNS 레코드 분석
  → 추가 위험 지표 산출 → ScoreDetail 갱신
  → WebSocket/Push 알림으로 클라이언트에 업데이트

  장점: 1차 즉시 응답으로 UX 유지, 2차로 판정 정밀도 향상
```

**관련 논문**: [R3] Hamadouche et al. (2024) — 콘텐츠 기반 피처

#### ⑤ 실시간 대시보드 API 확장

```
현재:  get_scan_summary() → 단순 통계 (total, secured, suspicious, blocked)
개선:  시계열 트렌드 + VT 케이스 분포 + XAI 피처 빈도 분석

  새 API 엔드포인트:
  GET /api/v1/dashboard/trend      → 일별/주별 스캔 추이
  GET /api/v1/dashboard/case-dist  → CASE_A_HIGH/A_LOW/B/C 분포
  GET /api/v1/dashboard/top-risks  → 가장 많이 탐지된 XAI 피처 순위
```

### 8.3 장기 개선

#### ⑥ 온디바이스 경량 모델 하이브리드

```
현재:  서버사이드 추론 전용 (네트워크 필수)
개선:  1차 온디바이스 경량 판정 + 2차 서버 정밀 판정

  [Android 디바이스]
  경량 모델 (TFLite) → 0.3s 이내 1차 판정 (SECURED/의심)
       │
       │ 의심 시에만 서버 호출
       ▼
  [서버] 풀 앙상블 + VT → 정밀 2차 판정

  장점: 네트워크 없이도 1차 보호 제공
  서버 변경: 기존 API에 "source": "on_device_escalation" 필드 추가
```

**관련 논문**: [R11] Rao et al. (2025) — 모바일 온디바이스 추론

#### ⑦ 멀티 TI 소스 확장

```
현재:  VirusTotal 단일 TI 소스
개선:  Google Safe Browsing + URLhaus + PhishTank API 추가

  서버 융합 엔진 확장:
  현재:  S = ML × Wml + VT × Wvt
  개선:  S = ML × Wml + VT × Wvt + GSB × Wgsb + UH × Wuh

  케이스 분류도 확장:
  → 다중 TI 소스의 합의 수준에 따라 가중치 자동 조정
```

---

## 9. 최종 정리

### 9.1 연구 기여 요약

본 연구는 기존 피싱 URL 탐지 연구의 **시스템 아키텍처 관점 5가지 한계점**을 해결하는 **6가지 서버/애플리케이션 설계 기여**를 제안하였다.

```
┌───────────────────────────────────────────────────────────────────┐
│                                                                    │
│   한계 ①  ──→  기여 1: 적응형 4-Case 가중치 융합 미들웨어           │
│   (스코어 융합       서버가 VT API 응답 상태를 분류하여              │
│    아키텍처 부재)    가중치를 실시간 조정하는 미들웨어 설계           │
│                                                                    │
│   한계 ②  ──→  기여 2: 외부 API 신호 비선형 증폭 모듈               │
│   (VT 저편향         A(x) = min(1.0, 3x)로 VT 신호 희석 방지       │
│    미보정)           서버 레벨에서 외부 API 응답을 전처리            │
│                                                                    │
│   한계 ①④ ──→  기여 3: Hard Override 2-Tier 안전 판정 계층          │
│   (안전 보장         결정론적 안전 규칙을 확률적 융합 위에 배치       │
│    메커니즘 부재)    Safety-critical 시스템 원칙의 ML 서비스 적용    │
│                                                                    │
│   한계 ③  ──→  기여 4: 사용자 대면 XAI API 변환 파이프라인          │
│   (XAI API          ML의 feature_importances_ →                    │
│    변환 부재)       한글 JSON API 응답 변환 + 필터링 + 정렬          │
│                                                                    │
│   한계 ④  ──→  기여 5: 3-Level Graceful Degradation 아키텍처       │
│   (API 장애          VT/ML 장애 시 자동 폴백으로 100% 가용성        │
│    시 중단)          서버가 CASE_C 자동 진입하여 서비스 지속         │
│                                                                    │
│   한계 ⑤  ──→  기여 6: KISA 연동 폐쇄형 대응 자동화 파이프라인     │
│   (탐지에서          탐지→신고→VT재검→KISA자동신고→차단             │
│    종료)             DB 스키마 + EventBridge + SES 자동화           │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

### 9.2 ML 팀과의 역할 분리

```
┌──────────────────────────────────────────────────────────────────┐
│                     역할 분리 구조                                 │
├─────────────────────────┬────────────────────────────────────────┤
│   ML 팀 (별도 논문)       │   서버/앱 팀 (본 논문)                  │
├─────────────────────────┼────────────────────────────────────────┤
│ · XGBoost/LightGBM 학습  │ · 학습된 모델을 S3/로컬에서 로딩        │
│ · 피처 선택 (Top25/Top20)│ · 커스텀 Unpickler로 환경 이식성 확보   │
│ · 앙상블 구성 (Soft Vote)│ · 모듈 레벨 캐싱 (웜 스타트 최적화)     │
│ · 하이퍼파라미터 튜닝    │ · 모델 추론 결과를 VT와 적응형 융합     │
│ · feature_importances_  │ · feature_importances_를 XAI JSON 변환 │
│   산출                   │ · Hard Override + Graceful Degradation │
│ · 모델 정확도 검증       │ · RESTful API 설계 + DB 스키마 설계    │
│                          │ · 서버리스 배포 + KISA 연동 파이프라인  │
│                          │ · Android 클라이언트 API 연동           │
└─────────────────────────┴────────────────────────────────────────┘
```

### 9.3 기존 연구 대비 포지셔닝

```
                        설명 가능성 (XAI)
                            ▲
                            │
        [R4] Wiley/IET      │     [R5] XAI-PhD
        (SHAP + Boosting)   │     (SHAP + Trust)
        ※ 연구자용 이미지    │     ※ 연구자용 이미지
                            │
                     [R7] MDPI ──── Q-Guarder ◀━━━ 차별화 위치:
                            │       ●            사용자 대면 XAI JSON
                            │       ●            + 적응형 융합 미들웨어
         ───────────────────┼──────●──────────── + Graceful Degradation
        ML 단독              │      ▲       하이브리드 (ML+TI)
        (모델 추론만)        │      │       (시스템 통합)
                            │      │
        [R1] Springer        │   [R9] SecureScan
        (Voting Ensemble)    │   (ML + VT 순차)
                            │   ※ 장애 대응 없음
        [R2] JIWE            │
        (Stacking)           │   [R10] IEEE
                            │   (ML + VT 조건부)
                            │   ※ 스코어 융합 없음
                            │
                            │   [R11] Mobile
                            │   (온디바이스)
                            ▼
                      실시간 / 프로덕션
```

### 9.4 KCI 투고 전략

| 학술지 | ISSN | 분야 | 적합 기여 | 우선순위 |
|--------|------|------|----------|:--------:|
| 정보보호학회논문지 (JKIISC) | 1598-3986 | 정보보안 | 1,2,3,5,6 (보안 서비스 아키텍처) | **1순위** |
| 한국통신학회논문지 | 1226-4717 | 통신/네트워크 | 1,4,5 (API 설계 + 장애 내성) | 2순위 |
| 한국정보과학회 논문지 | 2383-630X | 컴퓨터 과학 | 1,2,3 (시스템 설계 패턴) | 3순위 |
| 한국HCI학회 논문지 | 1976-2399 | HCI/UX | 4 (사용자 대면 XAI API) | 4순위 |

---

## 10. 참고 문헌 및 출처 검증

### 10.1 참고 논문 목록

| ID | 논문 제목 | 저자 | 출처 | 연도 | 링크 |
|----|----------|------|------|:----:|------|
| R1 | Detection of Phishing Websites from URLs Using Hybrid Ensemble-Based ML Technique | Agagu, M. et al. | Springer, SCDM 2024, LNNS vol.1078 | 2024 | [Link](https://link.springer.com/chapter/10.1007/978-3-031-66965-1_2) |
| R2 | Ensemble Learning-Powered URL Phishing Detection: A Performance Driven Approach | Mushtaq, S. et al. | J. Informatics & Web Eng., 3(2), 134-145 | 2024 | [DOI](https://doi.org/10.33093/jiwe.2024.3.2.10) |
| R3 | Combining Lexical, Host, and Content-based Features for Phishing Websites Detection Using ML Models | Hamadouche, S. et al. | EAI Trans. Scalable Info. Sys., 11(6) | 2024 | [DOI](https://doi.org/10.4108/eetsis.4421) |
| R4 | Explainable ML for Phishing Site Detection: A High-Efficiency Approach Using Boosting Models and SHAP | Uddin, K. M. M. et al. | The Journal of Engineering (IET/Wiley) | 2025 | [DOI](https://doi.org/10.1049/tje2.70110) |
| R5 | XAI-PhD: Fortifying Trust of Phishing URL Detection Empowered by SHAP | Al-Fayoumi, M. et al. | iJOE, 20(11), 80-101 | 2024 | [DOI](https://doi.org/10.3991/ijoe.v20i11.49533) |
| R6 | Can Features for Phishing URL Detection Be Trusted Across Diverse Datasets? | Mia, M. et al. | arXiv:2411.09813 | 2024 | [Link](https://arxiv.org/abs/2411.09813) |
| R7 | Hybridizing XAI for Intelligent Feature Extraction in Phishing Website Detection | - | MDPI Electronics, 15(2), 350 | 2025 | [DOI](https://doi.org/10.3390/electronics15020350) |
| R8 | A Large Scale Study and Classification of VirusTotal Reports on Phishing and Malware URLs | Choo, E. et al. | arXiv:2205.13155 | 2022 | [Link](https://arxiv.org/abs/2205.13155) |
| R9 | SecureScan: An AI-Driven Multi-Layer Framework for Malware and Phishing Detection | Firdos, R., Dangi, A. | arXiv:2602.10750 | 2026 | [Link](https://arxiv.org/abs/2602.10750) |
| R10 | Smart Phishing Detection System: Using ML Model Integrated with VirusTotal API | Primya, T. et al. | IEEE ICAECA 2025 | 2025 | [Link](https://ieeexplore.ieee.org/abstract/document/11012466/) |
| R11 | A Hybrid Super Learner Ensemble for Phishing Detection on Mobile Devices | Rao, R. S. et al. | Scientific Reports, 15, 16839 | 2025 | [DOI](https://doi.org/10.1038/s41598-025-02009-8) |
| R12 | Adaptive Phishing Detection in Web Applications Using Ensemble DL and Feature Fusion | - | ResearchGate, 2025.04 | 2025 | [Link](https://www.researchgate.net/publication/390872160) |

### 10.2 통계 및 보고서 출처

| ID | 자료명 | 출처 | 링크 |
|----|--------|------|------|
| S1 | 사이버 침해사고 피해, 전년 대비 약 48% 증가 | KISA | [Link](https://www.kisa.or.kr/402/form?postSeq=2482) |
| S2 | 2024 하반기 사이버 위협 동향 보고서 | KISA/KrCERT | [Link](https://m.boannews.com/html/detail.html?idx=134792) |
| S3 | 피싱사이트 URL 공공데이터 | 공공데이터포털 | [Link](https://www.data.go.kr/data/15109780/fileData.do) |
| S4 | KISA Insight 2024 Vol.07: 국내외 피싱 대응 현황 | KISA | [Link](https://www.kisa.or.kr/20301/form?postSeq=29&lang_type=KO) |

### 10.3 출처 검증 결과

모든 참조 논문에 대해 **3단계 검증**을 수행하였다:

1. **URL 접근성**: 해당 URL에 HTTP 요청을 보내 200 응답 또는 유효한 리다이렉트 확인
2. **서지 정보 교차 검증**: 논문 제목, 저자, 출판 연도를 원본 출판사 + Google Scholar에서 교차 확인
3. **DOI 유효성**: DOI가 있는 경우 메타데이터(제목, 저자)가 인용 정보와 일치하는지 확인

| ID | URL 접근 | 서지 교차검증 | DOI 유효 | 최종 상태 |
|----|:--------:|:----------:|:--------:|:---------:|
| R1 | O (Springer Link, 303 redirect) | O (저자 4인, SCDM 2024 확인) | - | **검증 완료** |
| R2 | O (journals.mmupress.com) | O (저자 3인, pp.134-145 확인) | O | **검증 완료** |
| R3 | O (publications.eai.eu) | O (저자 3인, vol.11 no.6 확인) | O | **검증 완료** |
| R4 | O (Wiley Online Library) | O (DOAJ 교차 검증) | O | **검증 완료** |
| R5 | O (online-journals.org) | O (저자 4인, Vol.20 No.11 확인) | O | **검증 완료** |
| R6 | O (arXiv) | O (저자 3인, ID 2411.09813v2) | - | **검증 완료** |
| R7 | O (MDPI) | O (vol.15, issue 2, article 350) | O | **검증 완료** |
| R8 | O (arXiv) | O (저자 5인, ID 2205.13155) | - | **검증 완료** |
| R9 | O (arXiv) | O (저자 2인, ID 2602.10750) | - | **검증 완료** |
| R10 | O (IEEE Xplore) | O (ICAECA 2025 확인) | O | **검증 완료** |
| R11 | O (Nature.com, 303 redirect) | O (저자 4인, vol.15 art.16839) | O | **검증 완료** |
| R12 | O (ResearchGate) | △ (프리프린트, 정식 저널 미확인) | - | **부분 검증** |

### 10.4 인용 신뢰도 등급

| 등급 | 기준 | 해당 논문 |
|:----:|------|----------|
| **A** (높음) | SCI/SCIE/Scopus 등재 또는 Springer/Wiley/Nature/IEEE | R1, R4, R10, R11 |
| **B** (보통) | DOI 부여 정식 저널 | R2, R3, R5, R7 |
| **C** (참고) | arXiv 프리프린트 (peer review 미완) | R6, R8, R9 |
| **D** (제한) | ResearchGate 프리프린트 | R12 |

> KCI 논문 투고 시 **A/B 등급 논문(8편)을 주요 참고문헌**으로 배치하고, C/D 등급(4편)은 보조 참고로 활용할 것을 권장한다.

---

## 부록: Q-Guarder 서버 핵심 코드 참조 위치

| 파일 | 주요 함수/클래스 | 관련 기여 | 설명 |
|------|----------------|:---------:|------|
| `app/services/hybrid_engine.py:208-216` | `_select_case()` | 기여 1 | VT 응답 상태 기반 케이스 자동 분류 |
| `app/services/hybrid_engine.py:219-282` | `analyze_url()` | 기여 1,2,3 | 하이브리드 융합 미들웨어 메인 로직 |
| `app/services/hybrid_engine.py:199-205` | `_amplify_vt_ratio()` | 기여 2 | 외부 API 신호 비선형 증폭 |
| `app/services/hybrid_engine.py:250-262` | Hard Override 분기 | 기여 3 | Tier 1 결정론적 안전 규칙 |
| `app/services/hybrid_engine.py:56-83` | `_build_xai_features()` | 기여 4 | ML 출력 → XAI 데이터 1차 변환 |
| `app/api/v1/scan.py:96-115` | XAI 필터링·정렬 로직 | 기여 4 | XAI JSON 응답 2차 변환 (API 레이어) |
| `app/services/feature_metadata.py:28-162` | `FEATURE_META` (26개) | 기여 4 | 한글 메타데이터 매핑 테이블 |
| `app/schemas/scan_schema.py` | `ScanUrlResponse` 등 | 기여 4 | Pydantic API 스키마 정의 |
| `app/services/hybrid_engine.py:97-148` | VT 장애 처리 (5종 예외) | 기여 5 | Graceful Degradation Level 1 |
| `app/services/hybrid_engine.py:233-237` | ML 장애 처리 (기본값 0.5) | 기여 5 | Graceful Degradation Level 2 |
| `app/services/s3_loader.py` | `get_model()`, `_EnsembleUnpickler` | 인프라 | S3/로컬 모델 로딩 + 캐싱 전략 |
| `app/models/scan.py` | `ScanLog`, `ScoreDetail` ORM | DB 설계 | 스캔 감사 로그 + 점수 상세 스키마 |
| `app/models/report.py` | `ReportedUrl`, `FeedbackQueue` ORM | 기여 6 | KISA 대응 파이프라인 DB 스키마 |
| `app/crud/crud_scan.py` | CRUD 함수 전체 | DB 설계 | 비동기 DB 조작 (asyncpg) |

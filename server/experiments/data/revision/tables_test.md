# 재심 대응 재실험 결과 (2026-10-20T08:45:48 UTC)

## 테스트 집합 최종 평가 (n=500) — 파라미터 고정 `α=18.4 d≥5 τL=0.45 τH=0.65 W=(0.25/0.5/0.3·deep 0.5/0.8) θ=0.05`

| 방법 | TP | FP | TN | FN | Accuracy | Precision | Recall [95% CI] | F1 | FPR | BLOCKED Recall | BLOCKED FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ML only (threshold 0.41) | 211 | 171 | 79 | 39 | 58.00 | 55.24 | 84.40 [79.4, 88.4] | 66.77 | 68.40 | 84.40 | 68.40 |
| VT only (d≥1) — 참고 | 243 | 16 | 234 | 7 | 95.40 | 93.82 | 97.20 [94.3, 98.6] | 95.48 | 6.40 | 97.20 | 6.40 |
| VT only (d≥5) — 참고 | 225 | 0 | 250 | 25 | 95.00 | 100.00 | 90.00 [85.7, 93.1] | 94.74 | 0.00 | 90.00 | 0.00 |
| Fixed 0.5:0.5 — 1차 심사본 설정(α=3.0) | 210 | 128 | 122 | 40 | 66.40 | 62.13 | 84.00 [78.9, 88.0] | 71.43 | 51.20 | 24.80 | 0.00 |
| Fixed 0.5:0.5 — 수정 α·τ 적용 | 242 | 93 | 157 | 8 | 79.80 | 72.24 | 96.80 [93.8, 98.4] | 82.74 | 37.20 | 84.80 | 1.60 |
| Fixed 0.5:0.5 — 검증 집합 자체 τ (τL 0.5, τH 0.6) | 241 | 11 | 239 | 9 | 96.00 | 95.63 | 96.40 [93.3, 98.1] | 96.02 | 4.40 | 88.80 | 1.60 |
| Adaptive — 1차 심사본 파라미터 | 209 | 26 | 224 | 41 | 86.60 | 88.94 | 83.60 [78.5, 87.7] | 86.19 | 10.40 | 11.60 | 2.00 |
| Adaptive — 수정 파라미터, Override 없음 | 245 | 22 | 228 | 5 | 94.60 | 91.76 | 98.00 [95.4, 99.1] | 94.78 | 8.80 | 96.00 | 3.60 |
| Adaptive — 수정 파라미터 + Override | 245 | 22 | 228 | 5 | 94.60 | 91.76 | 98.00 [95.4, 99.1] | 94.78 | 8.80 | 96.00 | 3.60 |

### 케이스별 — Adaptive — 1차 심사본 파라미터

| Case | n | 정상 | 피싱 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|
| CASE_A_HIGH | 225 | 0 | 225 | 191 | 34 | 0 | 0 |
| CASE_A_LOW | 34 | 16 | 18 | 13 | 5 | 11 | 5 |
| CASE_B | 173 | 173 | 0 | 0 | 0 | 0 | 173 |
| CASE_C | 68 | 61 | 7 | 5 | 2 | 15 | 46 |

### 케이스별 — Adaptive — 수정 파라미터, Override 없음

| Case | n | 정상 | 피싱 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|
| CASE_A_HIGH | 225 | 0 | 225 | 225 | 0 | 0 | 0 |
| CASE_A_LOW | 34 | 16 | 18 | 16 | 2 | 11 | 5 |
| CASE_B | 173 | 173 | 0 | 0 | 0 | 0 | 173 |
| CASE_C | 68 | 61 | 7 | 4 | 3 | 11 | 50 |

### 케이스별 — Adaptive — 수정 파라미터 + Override

| Case | n | 정상 | 피싱 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|
| CASE_A_HIGH | 225 | 0 | 225 | 225 | 0 | 0 | 0 |
| CASE_A_LOW | 34 | 16 | 18 | 16 | 2 | 11 | 5 |
| CASE_B | 173 | 173 | 0 | 0 | 0 | 0 | 173 |
| CASE_C | 68 | 61 | 7 | 4 | 3 | 11 | 50 |

### McNemar

| 비교 | b | c | p | 방법 |
|---|---:|---:|---|---|
| Fixed 0.5:0.5 — 1차 심사본 설정(α=3.0) vs Adaptive — 1차 심사본 파라미터 | 22 | 123 | 1e-16 | chi2-continuity |
| Fixed 0.5:0.5 — 수정 α·τ 적용 vs Adaptive — 수정 파라미터 + Override | 10 | 84 | 5.1e-14 | chi2-continuity |
| Fixed 0.5:0.5 — 검증 집합 자체 τ (τL 0.5, τH 0.6) vs Adaptive — 수정 파라미터 + Override | 11 | 4 | 0.118 | exact-binomial |
| Adaptive — 1차 심사본 파라미터 vs Adaptive — 수정 파라미터 + Override | 1 | 41 | 1.77e-09 | chi2-continuity |
| Adaptive — 수정 파라미터, Override 없음 vs Adaptive — 수정 파라미터 + Override | 0 | 0 | 1 | no-discordant-pairs |
| ML only (threshold 0.41) vs Adaptive — 수정 파라미터 + Override | 1 | 184 | 7.82e-41 | chi2-continuity |
| VT only (d≥1) — 참고 vs Adaptive — 수정 파라미터 + Override | 13 | 9 | 0.523 | exact-binomial |
| VT only (d≥5) — 참고 vs Adaptive — 수정 파라미터 + Override | 22 | 20 | 0.877 | chi2-continuity |

### VT 미등재 피싱

{
 "n_zero_day_phishing": 7,
 "n_case_b_phishing": 0,
 "ML only (threshold 0.41)": {
  "hit": 5,
  "n": 7,
  "recall_pct": 71.43,
  "wilson_ci_pct": [
   35.9,
   91.8
  ]
 },
 "Fixed 0.5:0.5 — 1차 심사본 설정(α=3.0)": {
  "hit": 1,
  "n": 7,
  "recall_pct": 14.29,
  "wilson_ci_pct": [
   2.6,
   51.3
  ]
 },
 "Fixed 0.5:0.5 — 수정 α·τ 적용": {
  "hit": 1,
  "n": 7,
  "recall_pct": 14.29,
  "wilson_ci_pct": [
   2.6,
   51.3
  ]
 },
 "Fixed 0.5:0.5 — 검증 집합 자체 τ (τL 0.5, τH 0.6)": {
  "hit": 0,
  "n": 7,
  "recall_pct": 0.0,
  "wilson_ci_pct": [
   0.0,
   35.4
  ]
 },
 "Adaptive — 1차 심사본 파라미터": {
  "hit": 5,
  "n": 7,
  "recall_pct": 71.43,
  "wilson_ci_pct": [
   35.9,
   91.8
  ]
 },
 "Adaptive — 수정 파라미터, Override 없음": {
  "hit": 4,
  "n": 7,
  "recall_pct": 57.14,
  "wilson_ci_pct": [
   25.0,
   84.2
  ]
 },
 "Adaptive — 수정 파라미터 + Override": {
  "hit": 4,
  "n": 7,
  "recall_pct": 57.14,
  "wilson_ci_pct": [
   25.0,
   84.2
  ]
 },
 "paired_fixed_v1_vs_paper_v1": {
  "b": 0,
  "c": 4,
  "p_value": 0.125,
  "method": "exact-binomial"
 },
 "paired_fixed_same_vs_proposed": {
  "b": 0,
  "c": 3,
  "p_value": 0.25,
  "method": "exact-binomial"
 },
 "paired_fixed_own_vs_proposed (공식 비교)": {
  "b": 0,
  "c": 4,
  "p_value": 0.125,
  "method": "exact-binomial"
 },
 "paired_paper_v1_vs_proposed": {
  "b": 1,
  "c": 0,
  "p_value": 1.0,
  "method": "exact-binomial"
 }
}

## ① 누수·중복 확인

```json
{
 "splits": {
  "validation": 500,
  "test": 500
 },
 "between_splits": {
  "pair": [
   "test",
   "validation"
  ],
  "url_overlap": 0,
  "domain_overlap": 13,
  "domains_shared": [
   "blogspot.com",
   "cisco.com",
   "com.ml",
   "github.io",
   "google.com",
   "mybluehost.me",
   "netlify.app",
   "pages.dev",
   "tinyurl.com",
   "typedream.app",
   "vercel.app",
   "weebly.com",
   "workers.dev"
  ]
 },
 "offline": {
  "file": "C:\\Users\\user\\Desktop\\프로젝트 모음집\\Q-Guarder-Server\\Q-Guarder-Server\\experiments\\data\\raw\\offline_urls.csv",
  "status": "없음 — Drive Q-Guard/dataset/preprocessed_dataset.csv 를 experiments/data/raw/offline_urls.csv 로 두면 자동 검사"
 },
 "parameter_selection_history": "1차 심사본: results.json 의 sweeps(α·τH·d_high·W_ML(B))와 override 실험이 동일 500건에서 수행됨 → 500건은 독립 테스트셋이 아니라 검증 집합으로 선언"
}
```

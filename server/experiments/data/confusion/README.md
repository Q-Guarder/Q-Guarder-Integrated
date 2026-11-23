# experiments/data/confusion — 심사위원 1 · 9번(온라인 융합 평가) 혼동행렬 산출물

생성: 2026-10-18, `python experiments/confusion_report.py --paper-check`
입력: experiments/data/evalset.csv (500건), vt_cache.jsonl (2026-08-08~09 수집), local_models/final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl
융합 계산: app/services/fusion.py 의 fuse() (fusion_experiment.py 와 동일, VT 재호출 0건)

| 파일 | 내용 |
|---|---|
| confusion_summary.json | 레이블 분포, 전략별 TP/FP/TN/FN, 지표(+95% Wilson CI), 케이스별 분해, BLOCKED 기준, McNemar, 논문 Table 4 대조(ALL_MATCH) |
| confusion_tables.md | 위 내용을 Markdown 표로 (논문/답변서 복사용) |
| per_url_predictions.csv | URL별: label, path_type, source, vt_status, d, n, p_ml, 전략별 case / S_final / risk / detected |
| repro_run_2026-10-18.log | fusion_experiment.py --skip-sweeps 재실행 로그 (results.json 재현 확인) |
| confusion_report_run_2026-10-18.log | confusion_report.py 실행 로그 |

⚠ 이 500건은 1차 심사본에서 파라미터 선정(α·τ·d·W_ML 스윕, θ)에도 사용되었다.
데이터 분리 재실험 후 evalset.csv 에 `split` 열(validation/test)을 추가하고
`python experiments/confusion_report.py --final-split test --paper-check` 를 다시 실행해
test split 결과로 논문 Table 5 를 채운다. (PAPER_TABLE4 상수는 수정본 Table 값으로 갱신)

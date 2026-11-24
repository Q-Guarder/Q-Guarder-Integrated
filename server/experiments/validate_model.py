"""오프라인 모델 검증 — 논문 §3.2 보강 자료

두 가지를 산출한다.

  ① Table 3(모델 성능 비교) **재현 검증**
     서버의 피처 추출기 + 앙상블 경로로 테스트셋을 다시 채점하여,
     논문에 실린 수치가 재현 가능함을 보인다. 심사에서 재현성을 물을 때의 답.

  ② URL 구조(path 깊이)별 성능 층화
     학습 데이터의 정상 URL 중 루트 URL 비율이 극히 낮아, 모델이 루트 URL을
     피싱으로 학습한 편향이 있다. 그 편향을 정량화하여 §4 한계 서술의 근거로 쓴다.

입력: test_feature_dataset.csv (26개 피처 + label, 학습 측 제공)
출력: experiments/data/model_validation.json

사용법
  python experiments/validate_model.py --csv <경로>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

import pandas as pd  # noqa: E402

from app.services.ensemble_model import MODEL_THRESHOLD  # noqa: E402
from app.services.model_loader import _LOCAL_MODEL_PATH, get_model  # noqa: E402
from app.services.url_features import FEATURE_COLUMNS  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("validate_model")

DATA_DIR = Path(__file__).resolve().parent / "data"
OUT = DATA_DIR / "model_validation.json"

# 논문 §3.2 Table 3 — With Feature Selection · XGB + LGBM
PAPER_TABLE3 = {
    "Accuracy": 0.9351,
    "Precision": 0.9225,
    "Recall": 0.9452,
    "F1-score": 0.9337,
}


def metrics(y_true, y_pred) -> dict:
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    n = len(y_true)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "n": n, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": (tp + tn) / n if n else 0.0,
        "precision": prec,
        "recall": rec,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="오프라인 모델 검증 (§3.2 보강)")
    ap.add_argument("--csv", type=Path,
                    default=PROJECT_ROOT.parent / "test_feature_dataset.csv",
                    help="테스트셋 CSV (26개 피처 + label)")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    if not args.csv.exists():
        raise SystemExit(f"테스트셋을 찾을 수 없습니다: {args.csv}")

    df = pd.read_csv(args.csv)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV에 없는 피처: {missing}")

    X, y = df[FEATURE_COLUMNS], df["label"].values
    model = get_model()
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= MODEL_THRESHOLD).astype(int)

    results: dict = {
        "model_file": _LOCAL_MODEL_PATH.name,
        "threshold": MODEL_THRESHOLD,
        "n_rows": len(df),
        "label_distribution": {int(k): int(v)
                               for k, v in df["label"].value_counts().items()},
    }

    # ── ① Table 3 재현 ──
    print("=" * 74)
    print(" ① 논문 §3.2 Table 3 재현 — With FS · XGB+LGBM · threshold "
          f"{MODEL_THRESHOLD}")
    print("=" * 74)
    m = metrics(y, pred)
    mine = {"Accuracy": m["accuracy"], "Precision": m["precision"],
            "Recall": m["recall"], "F1-score": m["f1"]}
    results["table3_reproduction"] = {"paper": PAPER_TABLE3, "reproduced": mine,
                                      "confusion": {k: m[k] for k in
                                                    ("tp", "tn", "fp", "fn")}}
    print(f"\n{'지표':<12} {'논문':>10} {'재현':>10} {'차이':>10}")
    print("-" * 46)
    max_diff = 0.0
    for k, paper_v in PAPER_TABLE3.items():
        diff = mine[k] - paper_v
        max_diff = max(max_diff, abs(diff))
        print(f"{k:<12} {paper_v:>10.4f} {mine[k]:>10.4f} {diff:>+10.4f}")
    print(f"\n혼동행렬  TP={m['tp']:,}  TN={m['tn']:,}  FP={m['fp']:,}  FN={m['fn']:,}")
    verdict = "재현 성공" if max_diff < 5e-4 else "불일치 — 확인 필요"
    results["table3_reproduction"]["max_abs_diff"] = max_diff
    results["table3_reproduction"]["verdict"] = verdict
    print(f"최대 절대 오차 {max_diff:.5f} → {verdict}")

    # ── ② URL 구조별 층화 ──
    print("\n" + "=" * 74)
    print(" ② URL 구조(path 깊이)별 성능 — 학습 데이터 편향의 정량화")
    print("=" * 74)

    benign, phish = df[df.label == 0], df[df.label == 1]
    b_root = int((benign.path_length == 0).sum())
    p_root = int((phish.path_length == 0).sum())
    results["root_url_composition"] = {
        "benign_root": b_root, "benign_total": len(benign),
        "phishing_root": p_root, "phishing_total": len(phish),
    }
    print(f"\n루트 URL(path_length = 0) 구성")
    print(f"  정상 중 루트 : {b_root:>6,} / {len(benign):>6,} = {b_root/len(benign)*100:6.2f}%")
    print(f"  피싱 중 루트 : {p_root:>6,} / {len(phish):>6,} = {p_root/len(phish)*100:6.2f}%")
    root_all = df[df.path_length == 0]
    if len(root_all):
        share = root_all.label.mean() * 100
        results["root_url_composition"]["phishing_share_of_root"] = share
        print(f"  → 전체 루트 URL {len(root_all):,}건 중 피싱 비율 {share:.2f}%")
        print("    학습 데이터가 '루트 URL ≈ 피싱'을 가르친 셈이다.")

    df2 = df.copy()
    df2["pred"] = pred
    bands = [
        ("root (path = 0)", df2[df2.path_length == 0]),
        ("shallow (1–20)", df2[(df2.path_length > 0) & (df2.path_length <= 20)]),
        ("deep (> 20)", df2[df2.path_length > 20]),
        ("overall", df2),
    ]
    print(f"\n{'구간':<20} {'n':>8} {'Recall':>9} {'FPR':>9} {'Precision':>10}")
    print("-" * 60)
    results["path_bands"] = {}
    for name, sub in bands:
        if not len(sub):
            continue
        bm = metrics(sub.label.values, sub.pred.values)
        results["path_bands"][name] = bm
        print(f"{name:<20} {bm['n']:>8,} {bm['recall']:>9.4f} {bm['fpr']:>9.4f} "
              f"{bm['precision']:>10.4f}")

    print("\n※ FPR이 path 깊이에 따라 급변한다. QR 실환경은 루트 URL 비중이 높으므로")
    print("  이 편향은 §4의 '데이터 수집 시점 편향' 한계로 서술한다.")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\n저장: {args.out}")


if __name__ == "__main__":
    main()

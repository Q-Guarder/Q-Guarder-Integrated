"""혼동행렬 보고서 — 심사위원 1 · 9번 (온라인 융합 평가) 대응 산출물

fusion_experiment.py와 **같은 데이터 로더·같은 fuse()**를 사용해 다음을 산출한다.

  1. 최종 평가셋의 레이블 분포 (정상/피싱 × root/deep × 출처, VT 응답 상태별)
  2. 전략별 혼동행렬 TP / FP / TN / FN  (ML 단독 · 고정 0.5:0.5 · 4-Case 적응형 · +Override)
     - 전체, 그리고 4-Case 적응형은 CASE_A_HIGH / A_LOW / B / C 별로 분해
     - 참고용: 융합 없는 VT 단독(d≥1, d≥5) 기준선
  3. 혼동행렬에서 재계산한 Accuracy / Precision / Recall / F1 / FPR (+95% Wilson CI)과
     논문 Table 4 보고값의 일치 여부 (--paper-check)
  4. URL별 예측 결과 CSV (재실험·검증 데이터 분리 후에도 그대로 재사용)
  5. 논문/답변서에 붙일 Markdown 표

데이터 분리(심사위원 2-2 / 3-2 대응) 지원
  evalset.csv에 `split` 열(예: validation / test)이 있으면 split별로 보고서를 나누고,
  --final-split 로 지정한 split(기본 test)만 "최종 보고용"으로 표시한다.
  `split` 열이 없으면 전체 500건을 하나의 집합으로 보고하되, 이 집합이 파라미터 선정에도
  사용되었음을 산출물에 명시한다 (독립 테스트셋 주장 금지).

사용법
  python experiments/confusion_report.py                 # 전체 보고
  python experiments/confusion_report.py --paper-check   # 1차 심사본 Table 4와 대조
  python experiments/confusion_report.py --final-split test
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, OrderedDict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fusion_experiment as fx  # noqa: E402  (같은 로더·같은 fuse() 재사용)
from app.services.fusion import (  # noqa: E402
    CASE_A_HIGH, CASE_A_LOW, CASE_B, CASE_C, CASE_OVERRIDE, VTStatus,
)

OUT_DIR = fx.DATA_DIR / "confusion"
CASE_ORDER = [CASE_A_HIGH, CASE_A_LOW, CASE_B, CASE_C, CASE_OVERRIDE]

# 1차 심사본(2026-08-12 제출본) Table 4 보고값 — --paper-check 대조 기준.
# 재실험 후에는 수정본 Table 값으로 갱신해서 다시 대조한다.
PAPER_TABLE4 = {
    "(1) ML Only":           {"recall": 82.80, "precision": 55.95, "f1": 66.77, "fpr": 65.20},
    "(2) Fixed 0.5:0.5":     {"recall": 89.20, "precision": 62.82, "f1": 73.72, "fpr": 52.80},
    "(4) 4-Case + Override": {"recall": 94.00, "precision": 92.16, "f1": 93.07, "fpr": 8.00},
}
PAPER_TEXT = {"fixed_fn": 27, "adaptive_fn": 15, "vt_undetected_phishing": 15}


# ═══════════════════════════════════════════════════════════════
#  데이터 로드 (split 열 지원)
# ═══════════════════════════════════════════════════════════════

def load_split_map() -> dict[str, str]:
    """evalset.csv의 split 열. 없으면 빈 dict."""
    with fx.EVALSET.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if "split" not in (reader.fieldnames or []):
            return {}
        return {r["url"]: (r["split"] or "").strip() for r in reader}


def vt_band(rec: fx.Record) -> str:
    if rec.vt_status == VTStatus.NOT_FOUND.value:
        return "not_found (미등재)"
    if rec.detected == 0:
        return "ok · d=0"
    if rec.detected < fx.FusionParams().d_high:
        return f"ok · 1≤d<{fx.FusionParams().d_high}"
    return f"ok · d≥{fx.FusionParams().d_high}"


# ═══════════════════════════════════════════════════════════════
#  1) 레이블 분포
# ═══════════════════════════════════════════════════════════════

def label_distribution(records: list[fx.Record]) -> dict:
    out: dict = {"n": len(records)}
    out["by_label"] = {
        "benign(0)": sum(1 for r in records if r.label == 0),
        "phishing(1)": sum(1 for r in records if r.label == 1),
    }
    out["by_label_path"] = {
        f"{'benign' if lb == 0 else 'phishing'}/{pt}": sum(
            1 for r in records if r.label == lb and r.path_type == pt)
        for lb in (0, 1) for pt in ("root", "deep")
    }
    out["by_source"] = dict(Counter(f"{r.source} (label={r.label})" for r in records))
    bands = OrderedDict()
    for band in ("ok · d≥5", "ok · 1≤d<5", "ok · d=0", "not_found (미등재)"):
        b = sum(1 for r in records if vt_band(r) == band and r.label == 0)
        p = sum(1 for r in records if vt_band(r) == band and r.label == 1)
        bands[band] = {"benign": b, "phishing": p, "total": b + p}
    out["by_vt_band"] = bands
    return out


# ═══════════════════════════════════════════════════════════════
#  2) 혼동행렬 (전체 / 케이스별)
# ═══════════════════════════════════════════════════════════════

def metrics_dict(m: fx.Metrics) -> dict:
    d = asdict(m)
    for k in ("accuracy", "precision", "recall", "fpr", "f1"):
        d[k + "_pct"] = round(d[k] * 100, 2)
    d["recall_ci_pct"] = [round(x * 100, 1) for x in m.recall_ci]
    d["precision_ci_pct"] = [round(x * 100, 1) for x in m.precision_ci]
    d["fpr_ci_pct"] = [round(x * 100, 1) for x in m.fpr_ci]
    return d


def confusion_by_case(records, results, preds) -> dict:
    """케이스별 TP/FN/FP/TN — 어떤 상황에서 미탐·오탐이 나오는지 분해"""
    out: dict = {}
    for case in CASE_ORDER:
        idx = [i for i, r in enumerate(results) if r.case == case]
        if not idx:
            continue
        sub = [records[i] for i in idx]
        sub_preds = [preds[i] for i in idx]
        m = fx.evaluate(sub, sub_preds)
        out[case] = {"n": m.n, "tp": m.tp, "fn": m.fn, "fp": m.fp, "tn": m.tn,
                     "benign": m.fp + m.tn, "phishing": m.tp + m.fn}
    return out


def run_strategies(records: list[fx.Record]) -> tuple[dict, dict]:
    """전략별 (혼동행렬·지표·케이스 분해) + URL별 예측 결과"""
    report: dict = {"baselines_reference": {}, "strategies": {}, "blocked_level": {}}
    per_url: dict[str, dict] = {
        r.url: {
            "url": r.url, "label": r.label, "path_type": r.path_type, "source": r.source,
            "vt_status": r.vt_status, "d": r.detected, "n": r.total,
            "vt_band": vt_band(r), "p_ml": round(r.p_ml, 4),
        } for r in records
    }

    # 참고 기준선 — 융합 없음 (논문 Table 4에는 없으나 심사 대응 시 투명성 확보용)
    for name, m in fx.evaluate_baselines(records):
        report["baselines_reference"][name] = metrics_dict(m)
    for name, fn in fx.BASELINES:
        for r in records:
            per_url[r.url][f"{name} detected"] = int(fn(r))

    truth = [r.label for r in records]
    preds_by: dict[str, list[bool]] = {}
    for name, make in fx.STRATEGIES:
        params = make()
        preds, results = fx.predict(records, params, blocked_only=False)
        m = fx.evaluate(records, preds)
        preds_by[name] = preds
        entry = metrics_dict(m)
        entry["by_case"] = confusion_by_case(records, results, preds)
        entry["fn_urls"] = [r.url for r, p in zip(records, preds) if r.label == 1 and not p]
        entry["fp_urls"] = [r.url for r, p in zip(records, preds) if r.label == 0 and p]
        report["strategies"][name] = entry

        bpreds, _ = fx.predict(records, params, blocked_only=True)
        report["blocked_level"][name] = metrics_dict(fx.evaluate(records, bpreds))

        for r, res, p in zip(records, results, preds):
            row = per_url[r.url]
            row[f"{name} case"] = res.case
            row[f"{name} S_final"] = res.final_score
            row[f"{name} risk"] = res.risk_level
            row[f"{name} detected"] = int(p)

    report["mcnemar_suspicious_level"] = {
        "(2) Fixed 0.5:0.5 vs (4) 4-Case + Override":
            fx.mcnemar(preds_by["(2) Fixed 0.5:0.5"], preds_by["(4) 4-Case + Override"], truth),
        "(1) ML Only vs (4) 4-Case + Override":
            fx.mcnemar(preds_by["(1) ML Only"], preds_by["(4) 4-Case + Override"], truth),
    }
    return report, per_url


# ═══════════════════════════════════════════════════════════════
#  3) 논문 보고값 대조
# ═══════════════════════════════════════════════════════════════

def paper_check(report: dict, tol: float = 0.005) -> dict:
    """혼동행렬 → 재계산 지표가 논문 Table 4(소수 둘째 자리)와 일치하는지 검사"""
    checks: dict = {}
    all_ok = True
    for name, expected in PAPER_TABLE4.items():
        got = report["strategies"].get(name)
        if got is None:
            checks[name] = "전략 없음"
            all_ok = False
            continue
        cells = {}
        for metric, exp_val in expected.items():
            val = got[metric + "_pct"]
            ok = abs(val - exp_val) <= tol
            cells[metric] = {"paper": exp_val, "from_confusion": val, "match": ok}
            all_ok &= ok
        checks[name] = cells
    fixed_fn = report["strategies"]["(2) Fixed 0.5:0.5"]["fn"]
    adapt_fn = report["strategies"]["(4) 4-Case + Override"]["fn"]
    checks["text_FN_27_to_15"] = {
        "paper": [PAPER_TEXT["fixed_fn"], PAPER_TEXT["adaptive_fn"]],
        "from_confusion": [fixed_fn, adapt_fn],
        "match": (fixed_fn, adapt_fn) == (PAPER_TEXT["fixed_fn"], PAPER_TEXT["adaptive_fn"]),
    }
    all_ok &= checks["text_FN_27_to_15"]["match"]
    checks["ALL_MATCH"] = all_ok
    return checks


# ═══════════════════════════════════════════════════════════════
#  4) Markdown 표
# ═══════════════════════════════════════════════════════════════

def md_tables(dist: dict, report: dict, set_label: str) -> str:
    L: list[str] = []
    L.append(f"## 평가셋 레이블 분포 — {set_label} (n={dist['n']})\n")
    L.append("| 구분 | root | deep | 합계 |")
    L.append("|---|---:|---:|---:|")
    for lb in ("benign", "phishing"):
        r = dist["by_label_path"][f"{lb}/root"]
        d = dist["by_label_path"][f"{lb}/deep"]
        L.append(f"| {'정상 (Tranco)' if lb == 'benign' else '피싱 (OpenPhish)'} | {r} | {d} | {r + d} |")
    L.append(f"| 합계 | {dist['by_label_path']['benign/root'] + dist['by_label_path']['phishing/root']} "
             f"| {dist['by_label_path']['benign/deep'] + dist['by_label_path']['phishing/deep']} | {dist['n']} |\n")

    L.append("| VT 응답 상태 (케이스) | 정상 | 피싱 | 합계 |")
    L.append("|---|---:|---:|---:|")
    case_of = {"ok · d≥5": "A_HIGH", "ok · 1≤d<5": "A_LOW", "ok · d=0": "B", "not_found (미등재)": "C"}
    for band, v in dist["by_vt_band"].items():
        L.append(f"| {band} → CASE_{case_of[band]} | {v['benign']} | {v['phishing']} | {v['total']} |")
    L.append("")

    L.append(f"## 전략별 혼동행렬 및 지표 — {set_label} (판정 기준: SUSPICIOUS 이상)\n")
    L.append("| Method | TP | FP | TN | FN | Accuracy | Precision | Recall [95% CI] | F1 | FPR |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, m in list(report["baselines_reference"].items()) + list(report["strategies"].items()):
        tag = " *(참고, 융합 없음)*" if name.startswith("(0") else ""
        L.append(f"| {name}{tag} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
                 f"{m['accuracy_pct']:.2f} | {m['precision_pct']:.2f} | "
                 f"{m['recall_pct']:.2f} [{m['recall_ci_pct'][0]:.1f}, {m['recall_ci_pct'][1]:.1f}] | "
                 f"{m['f1_pct']:.2f} | {m['fpr_pct']:.2f} |")
    L.append("")

    for name in ("(4) 4-Case + Override", "(3) 4-Case Adaptive"):
        if name not in report["strategies"]:
            continue
        L.append(f"## 케이스별 혼동행렬 — {name} ({set_label})\n")
        L.append("| Case | n | 정상 | 피싱 | TP | FN | FP | TN | Recall | FPR |")
        L.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for case, c in report["strategies"][name]["by_case"].items():
            rec = f"{c['tp'] / c['phishing'] * 100:.2f}%" if c["phishing"] else "—"
            fpr = f"{c['fp'] / c['benign'] * 100:.2f}%" if c["benign"] else "—"
            L.append(f"| {case} | {c['n']} | {c['benign']} | {c['phishing']} | {c['tp']} | {c['fn']} | "
                     f"{c['fp']} | {c['tn']} | {rec} | {fpr} |")
        L.append("")
        break  # Override 유무가 같으면 하나만

    L.append(f"## BLOCKED 기준 혼동행렬 — {set_label} (참고: Override 효과 확인용)\n")
    L.append("| Method | TP | FP | TN | FN | Recall | Precision | FPR |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for name, m in report["blocked_level"].items():
        L.append(f"| {name} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
                 f"{m['recall_pct']:.2f} | {m['precision_pct']:.2f} | {m['fpr_pct']:.2f} |")
    L.append("")
    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════
#  main
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(description="혼동행렬 보고서 (심사위원 1 · 9번)")
    ap.add_argument("--final-split", default="test",
                    help="최종 보고용 split 이름 (evalset.csv에 split 열이 있을 때)")
    ap.add_argument("--paper-check", action="store_true",
                    help="PAPER_TABLE4 보고값과 재계산 지표 대조")
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args()

    records = fx.attach_ml_probabilities(fx.load_records())
    split_map = load_split_map()

    sets: list[tuple[str, list[fx.Record], bool]] = []
    if split_map:
        names = sorted({s for s in split_map.values() if s})
        for s in names:
            subset = [r for r in records if split_map.get(r.url) == s]
            sets.append((s, subset, s == args.final_split))
        if not any(final for _, _, final in sets):
            fx.logger.warning("--final-split=%s 에 해당하는 레코드가 없습니다 (split 값: %s)",
                              args.final_split, names)
    else:
        fx.logger.warning("evalset.csv에 split 열이 없음 — 전체 %d건을 단일 집합으로 보고. "
                          "이 집합은 1차 심사본에서 파라미터 선정에도 사용되었으므로 "
                          "독립 테스트셋으로 기술하지 말 것.", len(records))
        sets.append(("all (split 미분리)", records, False))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model_file": fx._LOCAL_MODEL_PATH.name,
            "ml_threshold": fx.MODEL_THRESHOLD,
            "fusion_params_default": {
                "alpha": fx.FusionParams().alpha, "d_high": fx.FusionParams().d_high,
                "tau_suspicious": fx.FusionParams().tau_suspicious,
                "tau_blocked": fx.FusionParams().tau_blocked,
                "w_ml": fx.FusionParams().w_ml,
                "override_ratio_theta": fx.FusionParams().theta_override,
            },
            "split_column_present": bool(split_map),
            "final_split": args.final_split if split_map else None,
            "note": "혼동행렬·지표는 fusion_experiment.py와 동일한 fuse()로 계산 (VT 재호출 0건)",
        },
        "sets": {},
    }
    md_all: list[str] = [f"# 혼동행렬 보고서 (생성 {summary['meta']['generated_at'][:19]} UTC)\n"]
    if not split_map:
        md_all.append("> ⚠ `split` 열 없음: 아래 수치는 1차 심사본과 같은 500건 전체 기준이며, "
                      "이 500건은 파라미터 선정에도 사용되었다. 재실험 후 test split 결과로 교체할 것.\n")

    all_rows: list[dict] = []
    for set_label, subset, is_final in sets:
        if not subset:
            continue
        fx.section(f"[{set_label}] n={len(subset)}" + ("  ← 최종 보고용" if is_final else ""))
        dist = label_distribution(subset)
        report, per_url = run_strategies(subset)
        entry = {"is_final_report_set": is_final, "label_distribution": dist, **report}
        if args.paper_check:
            entry["paper_check"] = paper_check(report)
            print("\n논문 Table 4 대조:", json.dumps(entry["paper_check"], ensure_ascii=False, indent=1))
        summary["sets"][set_label] = entry
        for row in per_url.values():
            row["split"] = set_label
            all_rows.append(row)
        md = md_tables(dist, report, set_label + ("  ← 최종 보고용" if is_final else ""))
        print("\n" + md)
        md_all.append(md)

    # URL별 예측 결과
    cols = list(all_rows[0].keys())
    with (args.out_dir / "per_url_predictions.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(all_rows)

    (args.out_dir / "confusion_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (args.out_dir / "confusion_tables.md").write_text("\n".join(md_all), encoding="utf-8")
    print(f"\n산출물: {args.out_dir}/confusion_summary.json · confusion_tables.md · per_url_predictions.csv")


if __name__ == "__main__":
    main()

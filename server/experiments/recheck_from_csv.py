"""독립 재검산 — per_url_<split>.csv 한 장과 fixed_params.json 만으로 최종 표를 다시 계산한다.

서버 코드(app/services/fusion.py)를 import 하지 않고 식 (1)~(8)을 그대로 다시 구현해,
revision_results.json 의 전략별 혼동행렬·케이스별 혼동행렬·VT 미등재 피싱 탐지 수와 일치하는지 확인한다.
심사위원이 "재현 가능한가"를 물을 때 "CSV 한 장으로 재현된다"는 근거로 쓴다.

  python experiments/recheck_from_csv.py                    # validation
  python experiments/recheck_from_csv.py --split test       # 테스트 평가 후
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data" / "revision"
PROPOSED = "Adaptive — 수정 파라미터 + Override"


def fuse(p: float, d: int, n: int, status: str, path_type: str, P: dict, fixed_w: float | None = None,
         tau_s: float | None = None, tau_b: float | None = None, override: bool = True):
    """식 (2)~(8). fixed_w 가 주어지면 고정 융합(케이스 전환·Override 없음)."""
    tau_s = P["tau_s"] if tau_s is None else tau_s
    tau_b = P["tau_b"] if tau_b is None else tau_b
    if status != "ok":                       # not_found / unavailable → CASE_C, S_VT = 0
        case, w = "CASE_C", P["w_c"]
        s_vt, ratio = 0.0, 0.0
    else:
        ratio = d / n if n else 0.0
        s_vt = min(1.0, P["alpha"] * ratio)  # 식 (5)
        if d >= P["d_high"]:
            case, w = "CASE_A_HIGH", P["w_a_high"]
        elif d >= 1:
            case, w = "CASE_A_LOW", P["w_a_low"]
        else:
            case = "CASE_B"
            w = P["w_b_deep"] if (P.get("w_b_deep") is not None and path_type == "deep") else P["w_b"]
    if fixed_w is not None:
        w = fixed_w
    s = w * p + (1 - w) * s_vt                # 식 (6)
    if override and fixed_w is None and status == "ok" and P.get("theta") is not None and ratio >= P["theta"]:
        s = 1.0                               # 식 (7) 우선 판정
    level = "BLOCKED" if s >= tau_b else ("SUSPICIOUS" if s >= tau_s else "SECURED")   # 식 (8)
    return case, s, level


def confusion(rows, pred):
    tp = sum(1 for r, q in zip(rows, pred) if r["label"] == "1" and q)
    fp = sum(1 for r, q in zip(rows, pred) if r["label"] == "0" and q)
    tn = sum(1 for r, q in zip(rows, pred) if r["label"] == "0" and not q)
    fn = sum(1 for r, q in zip(rows, pred) if r["label"] == "1" and not q)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="validation")
    args = ap.parse_args()
    rows = list(csv.DictReader((DATA / f"per_url_{args.split}.csv").open(encoding="utf-8")))
    fixed = json.loads((DATA / "fixed_params.json").read_text(encoding="utf-8"))
    P = fixed["params"]
    bf = fixed.get("baseline_fixed") or {"alpha": P["alpha"], "tau_s": P["tau_s"], "tau_b": P["tau_b"]}
    V1 = {"alpha": 3.0, "d_high": 5, "tau_s": 0.35, "tau_b": 0.65, "w_a_high": 0.25, "w_a_low": 0.50, "w_b": 0.30,
          "w_b_deep": None, "w_c": 0.80, "theta": 0.30}
    ref_name = "revision_results.json" if args.split == "validation" else "revision_results_test.json"
    ref = json.loads((DATA / ref_name).read_text(encoding="utf-8"))
    ev = ref["evaluation_validation" if args.split == "validation" else "evaluation_test"]

    def run(P_, **kw):
        return [fuse(float(r["p_ml"]), int(r["d"]), int(r["n"]), r["vt_status"], r["path_type"], P_, **kw) for r in rows]

    strategies = {
        "ML only (threshold 0.41)": [("BLOCKED" if float(r["p_ml"]) >= 0.41 else "SECURED") for r in rows],
        "VT only (d≥1) — 참고": [("BLOCKED" if int(r["d"]) >= 1 else "SECURED") for r in rows],
        "VT only (d≥5) — 참고": [("BLOCKED" if int(r["d"]) >= 5 else "SECURED") for r in rows],
        "Fixed 0.5:0.5 — 1차 심사본 설정(α=3.0)": [x[2] for x in run(V1, fixed_w=0.5)],
        "Fixed 0.5:0.5 — 수정 α·τ 적용": [x[2] for x in run(P, fixed_w=0.5)],
        f"Fixed 0.5:0.5 — 검증 집합 자체 τ (τL {bf['tau_s']}, τH {bf['tau_b']})":
            [x[2] for x in run({**P, "alpha": bf["alpha"]}, fixed_w=0.5, tau_s=bf["tau_s"], tau_b=bf["tau_b"])],
        "Adaptive — 1차 심사본 파라미터": [x[2] for x in run(V1)],
        "Adaptive — 수정 파라미터, Override 없음": [x[2] for x in run(P, override=False)],
        PROPOSED: [x[2] for x in run(P)],
    }
    all_ok = True
    print(f"{'전략':58s} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4}  일치")
    for name, levels in strategies.items():
        c = confusion(rows, [lv != "SECURED" for lv in levels])
        r = ev["strategies"].get(name, {}).get("suspicious", {})
        ok = all(c[k] == r.get(k) for k in c)
        all_ok &= ok
        print(f"{name:58s} {c['tp']:>4} {c['fp']:>4} {c['tn']:>4} {c['fn']:>4}  {'✓' if ok else '✗ (json: ' + str({k: r.get(k) for k in c}) + ')'}")
    # 케이스별 (제안 방법)
    res = run(P)
    print("\n케이스별 — 제안 방법")
    for case in ("CASE_A_HIGH", "CASE_A_LOW", "CASE_B", "CASE_C"):
        idx = [i for i, x in enumerate(res) if x[0] == case]
        if not idx:
            continue
        c = confusion([rows[i] for i in idx], [res[i][2] != "SECURED" for i in idx])
        r = ev["strategies"][PROPOSED]["by_case"].get(case, {})
        ok = all(c[k] == r.get(k) for k in c)
        all_ok &= ok
        print(f"  {case:12s} n={len(idx):3d} TP {c['tp']} FN {c['fn']} FP {c['fp']} TN {c['tn']}  {'✓' if ok else '✗'}")
    # VT 미등재 피싱
    zd = [i for i, r in enumerate(rows) if r["label"] == "1" and r["vt_status"] != "ok"]
    hit = sum(1 for i in zd if res[i][2] != "SECURED")
    r = ev["zero_day"].get(PROPOSED, {})
    ok = hit == r.get("hit") and len(zd) == r.get("n")
    all_ok &= ok
    print(f"\nVT 미등재 피싱: {hit}/{len(zd)} 탐지  {'✓' if ok else '✗'}")
    print("\n결과:", "모두 일치 — CSV 한 장으로 재현됨" if all_ok else "불일치 있음 — 위 ✗ 확인")


if __name__ == "__main__":
    main()

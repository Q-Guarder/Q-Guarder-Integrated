"""검토 보완 계산 — 재심 대응 패키지 리뷰에서 지적된 항목의 재검산과 추가 표

revision_experiment.py --select 이후에 실행한다 (fixed_params.json 필요). 파라미터를 바꾸지 않는다 —
이미 고정된 값 주변의 추가 표와 수치 검증만 만든다.

  1. 수치 검증: CASE_C 혼동행렬, B 개선 전 Precision, α 증가 시 추가 오탐 URL, 15건 호스트 구성,
     τH 격자 양끝 행, 라벨별 루트/경로 비율
  2. τL 확장 격자 (0.25 ~ 0.64): 최종점 OAT 지표 + 각 τL 에서 B 재설계(W_ML(B, deep)) 실행 가능 여부
  3. W_ML(A_HIGH) 스윕 — Override 를 끈 상태 (d ≥ d_high 피싱이 BLOCKED 로 유지되는 조건)
  4. 고정 융합(0.5:0.5) 베이스라인의 자체 τL·τH 선정 (공정 비교) + VT 미등재 15건 대응표본 비교
  5. VT 단독 (d ≥ 5) 행 — Table 5 후보
  6. 선정 단계(α=18.4, τL=0.35, deep 미적용) W_ML(A_LOW)·W_ML(C)·W_ML(A_HIGH) 스윕 — R1 판단 근거 수치
  7. 1차 심사본 results.json 의 스윕 요약(w_ml_B, tau_blocked)과 생성 시각 — 2-2 '같은 500건' 근거

출력: data/revision/review_followup.json, data/revision/tables_review_followup.md
"""

from __future__ import annotations

import json
import math
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fusion_experiment as fx  # noqa: E402
import revision_experiment as rx  # noqa: E402
from app.services.fusion import fuse, params_fixed  # noqa: E402

OUT_JSON = rx.OUT_DIR / "review_followup.json"
OUT_MD = rx.OUT_DIR / "tables_review_followup.md"

TAU_S_EXT = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.64]
FIXED_TAU_S_GRID = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65]


def pct(x: float) -> float:
    return round(x * 100, 2)


def m_row(m: fx.Metrics) -> dict:
    return {"tp": m.tp, "fp": m.fp, "tn": m.tn, "fn": m.fn, "recall": pct(m.recall), "precision": pct(m.precision),
            "f1": pct(m.f1), "fpr": pct(m.fpr), "accuracy": pct(m.accuracy)}


def exact_binomial_two_sided(b: int, c: int) -> float:
    """대응표본 정확 이항검정 (불일치 쌍 b, c). 양측 p."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def zero_day_hits(records, preds) -> tuple[int, int]:
    zd = [(r, p) for r, p in zip(records, preds) if r.label == 1 and r.is_zero_day]
    return sum(1 for _, p in zd if p), len(zd)


def main() -> None:
    fixed = json.loads(rx.FIXED.read_text(encoding="utf-8"))
    final = rx.RevParams(**fixed["params"])
    records = fx.attach_ml_probabilities(fx.load_records())
    split_map = rx.load_split_map()
    val = [r for r in records if split_map.get(r.url, "validation") == "validation"] if split_map else records
    benign = [r for r in val if r.label == 0]
    phish = [r for r in val if r.label == 1]
    zd = [r for r in phish if r.is_zero_day]
    out: dict = {"final_params": fixed["params"], "n_validation": len(val)}
    md: list[str] = ["# 검토 보완 표 (검증 집합, 파라미터 변경 없음)\n"]

    # ── 1. 수치 검증 ──────────────────────────────────────────────
    chk: dict = {}
    preds_final, res_final = rx.predict_rp(val, final)
    chk["by_case_final"] = rx.by_case_confusion(val, res_final, preds_final, final)
    before = replace(final, w_b_deep=None)
    m_before = fx.evaluate(val, rx.predict_rp(val, before)[0])
    chk["case_b_before_redesign"] = m_row(m_before)
    chk["case_b_after_redesign"] = m_row(fx.evaluate(val, preds_final))
    # α 증가 시 추가 오탐 URL (Override 없음, 최종점)
    no_ov = replace(final, theta=None)
    alpha_grid = sorted(set(rx.GRIDS["alpha"] + [final.alpha]))
    flips = []
    prev = None
    for a in alpha_grid:
        rp = replace(no_ov, alpha=a)
        preds, res = rx.predict_rp(val, rp)
        if prev is not None:
            for r, p0, p1, x in zip(val, prev[1], preds, res):
                if p0 != p1:
                    flips.append({"alpha_from": prev[0], "alpha_to": a, "url": r.url, "label": r.label, "path_type": r.path_type,
                                  "case": rx.case_of(r, rp), "d": r.detected, "n": r.total, "p_ml": round(r.p_ml, 4),
                                  "s_final": round(x.final_score, 4), "now_detected": bool(p1)})
        prev = (a, preds)
    chk["alpha_flips_no_override"] = flips
    hosts = Counter()
    for r in zd:
        h = (urlsplit(r.url).hostname or "").lower()
        hosts["github.io" if h.endswith("github.io") else h] += 1
    chk["zero_day_hosts"] = dict(hosts)
    chk["zero_day_github_io"] = hosts.get("github.io", 0)
    chk["zero_day_url_contains_clone"] = sum(1 for r in zd if "clone" in r.url.lower())
    rows_tb = rx.sweep(val, final, "tau_b", rx.GRIDS["tau_b"])
    chk["tau_b_edges"] = [{"tau_b": r["value"], "blocked_recall": r["blocked"]["recall_pct"], "blocked_fpr": r["blocked"]["fpr_pct"],
                           "benign_to_blocked_pct": r["benign_to_blocked_pct"], "phish_to_secured_pct": r["phish_to_secured_pct"],
                           "risk_levels": r["risk_levels"]} for r in rows_tb if r["value"] in (0.45, 0.85)]
    chk["root_ratio"] = {lb: {"root": sum(1 for r in val if r.label == lb and r.path_type == "root"),
                              "deep": sum(1 for r in val if r.label == lb and r.path_type == "deep"),
                              "n": sum(1 for r in val if r.label == lb)} for lb in (0, 1)}
    out["checks"] = chk
    md.append("## 1. 수치 검증\n")
    md.append(f"- CASE_C (최종 설정): {chk['by_case_final']['CASE_C']}")
    md.append(f"- B 개선 전 (W_ML(B)=0.30 전체): {chk['case_b_before_redesign']}")
    md.append(f"- B 개선 후 (deep 0.50): {chk['case_b_after_redesign']}")
    md.append(f"- 15건 호스트: {chk['zero_day_hosts']} · URL 에 'clone' 포함 {chk['zero_day_url_contains_clone']}건")
    md.append(f"- 라벨별 루트/경로: 정상 root {chk['root_ratio'][0]['root']}/{chk['root_ratio'][0]['n']}, 피싱 root {chk['root_ratio'][1]['root']}/{chk['root_ratio'][1]['n']}\n")
    md.append("| α 구간 | URL | 라벨 | 상황 | d/n | p_ML | 변화 |\n|---|---|---|---|---|---|---|")
    for f in flips:
        md.append(f"| {f['alpha_from']} → {f['alpha_to']} | {f['url']} | {'피싱' if f['label'] else '정상'} | {f['case']} | {f['d']}/{f['n']} | {f['p_ml']} | {'탐지(오탐)' if f['now_detected'] and not f['label'] else ('탐지' if f['now_detected'] else '미탐')} |")
    md.append("")

    # ── 2. τL 확장 격자 ──────────────────────────────────────────
    ext_rows = []
    for t in TAU_S_EXT:
        rp = replace(final, tau_s=t)                       # OAT: W_ML(B, deep)=0.50 고정
        preds, res = rx.predict_rp(val, rp)
        ms = fx.evaluate(val, preds)
        mb = fx.evaluate(val, [x.blocked for x in res])
        zh, zn = zero_day_hits(val, preds)
        levels = {lb: Counter(x.risk_level for r, x in zip(val, res) if r.label == lb) for lb in (0, 1)}
        # 절차 일관성: 이 τL 에서 B 재설계를 다시 수행했을 때 선택되는 W_ML(B, deep)
        cb = rx.case_b_redesign(val, replace(final, tau_s=t, w_b_deep=None))
        w_sel = cb["selected_w_b_deep"]
        proc = None
        if w_sel is not None:
            rp2 = replace(final, tau_s=t, w_b_deep=w_sel)
            p2, r2 = rx.predict_rp(val, rp2)
            m2 = fx.evaluate(val, p2)
            proc = {"w_b_deep": w_sel, "f1": pct(m2.f1), "recall": pct(m2.recall), "fpr": pct(m2.fpr),
                    "zero_day": zero_day_hits(val, p2)[0]}
        ext_rows.append({"tau_s": t, "oat": m_row(ms), "blocked": m_row(mb), "zero_day_hits": zh, "zero_day_n": zn,
                         "c_p_star": round(t / final.w_c, 4), "b_deep_p_star": round(t / final.w_b_deep, 4),
                         "suspicious_band_width": round(final.tau_b - t, 2),
                         "risk_levels": {"benign": dict(levels[0]), "phishing": dict(levels[1])},
                         "w_b_deep_feasible": w_sel, "procedure_consistent": proc,
                         "within_original_grid": t in rx.GRIDS["tau_s"]})
    out["tau_s_extended"] = {"grid": TAU_S_EXT, "original_grid": rx.GRIDS["tau_s"], "rows": ext_rows,
                             "note": "OAT = W_ML(B, deep)=0.50 등 다른 파라미터 고정. '절차 일관' = 그 τL 에서 B 재설계 규칙(W > τL, 추가 FPR ≤ 2.0%p)을 다시 적용한 결과. "
                                     "W 후보가 없으면 B 구조 제약을 만족하는 설계가 없다는 뜻."}
    md.append("## 2. τL 확장 격자 (최종점, 다른 파라미터 고정)\n")
    md.append("| τL | 격자 | Recall | Precision | F1 | FPR | BLOCKED R / FPR | 미등재 15건 | C p* (τL/0.8) | SUSPICIOUS 폭 (τH−τL) | B 재설계 가능 W | 절차 일관 F1 / FPR / 15건 |")
    md.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for e in ext_rows:
        o, b = e["oat"], e["blocked"]
        pc = e["procedure_consistent"]
        md.append(f"| {e['tau_s']} | {'원 격자' if e['within_original_grid'] else '확장'} | {o['recall']} | {o['precision']} | {o['f1']} | {o['fpr']} | {b['recall']} / {b['fpr']} | "
                  f"{e['zero_day_hits']}/{e['zero_day_n']} | {e['c_p_star']} | {e['suspicious_band_width']} | "
                  f"{e['w_b_deep_feasible'] if e['w_b_deep_feasible'] is not None else '없음'} | "
                  f"{(str(pc['f1']) + ' / ' + str(pc['fpr']) + ' / ' + str(pc['zero_day'])) if pc else '—'} |")
    md.append("")

    # ── 3. W_ML(A_HIGH) — Override 없음 ─────────────────────────
    rows_on = rx.sweep(val, final, "w_a_high", rx.GRIDS["w_a_high"])
    rows_off = rx.sweep(val, no_ov, "w_a_high", rx.GRIDS["w_a_high"])
    out["w_a_high_override_off"] = [{"w_a_high": a["value"], "blocked_recall_override_on": a["blocked"]["recall_pct"],
                                     "blocked_recall_override_off": b["blocked"]["recall_pct"],
                                     "a_high_min_score_at_p0": round((1 - a["value"]) * 1.0, 3),
                                     "a_high_always_blocked": (1 - a["value"]) >= final.tau_b,
                                     "f1": a["suspicious"]["f1_pct"], "fpr": a["suspicious"]["fpr_pct"]}
                                    for a, b in zip(rows_on, rows_off)]
    md.append("## 3. W_ML(A_HIGH) — Override 유무별 BLOCKED Recall\n")
    md.append("| W_ML(A_HIGH) | d≥5 최소 점수 (p_ML=0) | 항상 BLOCKED (≥ τH 0.65) | BLOCKED Recall (Override 켬) | BLOCKED Recall (Override 끔) | F1 | FPR |\n|---|---|---|---|---|---|---|")
    for r in out["w_a_high_override_off"]:
        md.append(f"| {r['w_a_high']} | {r['a_high_min_score_at_p0']} | {'예' if r['a_high_always_blocked'] else '아니오'} | {r['blocked_recall_override_on']} | {r['blocked_recall_override_off']} | {r['f1']} | {r['fpr']} |")
    md.append("")

    # ── 4. 고정 융합 베이스라인 자체 τ 선정 ────────────────────
    def fixed_eval(alpha: float, ts: float, tb: float):
        p = params_fixed(0.50, alpha=alpha, tau_suspicious=ts, tau_blocked=tb)
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in val]
        return [x.detected for x in res], [x.blocked for x in res]

    fixed_out: dict = {}
    for alpha in (final.alpha, 3.0):
        cand = []
        for ts in FIXED_TAU_S_GRID:
            ps, _ = fixed_eval(alpha, ts, 0.65)
            m = fx.evaluate(val, ps)
            cand.append((ts, m))
        best_ts, best_m = max(cand, key=lambda c: (round(c[1].f1, 6), round(c[1].recall, 6), -round(c[1].fpr, 6)))
        tb_rows = []
        for tb in rx.GRIDS["tau_b"]:
            if tb <= best_ts:
                continue
            _, pb = fixed_eval(alpha, best_ts, tb)
            mb = fx.evaluate(val, pb)
            tb_rows.append((tb, mb))
        ok = [c for c in tb_rows if c[1].fpr <= rx.BLOCKED_FPR_CAP + 1e-9]
        best_tb, best_mb = max(ok or tb_rows, key=lambda c: (round(c[1].recall, 6), round(c[1].precision, 6)))
        ps, pb = fixed_eval(alpha, best_ts, best_tb)
        zh, zn = zero_day_hits(val, ps)
        fixed_out[f"alpha_{alpha}"] = {
            "alpha": alpha, "tau_s_selected": best_ts, "tau_b_selected": best_tb,
            "tau_s_grid": [{"tau_s": ts, **m_row(m), "zero_day": zero_day_hits(val, fixed_eval(alpha, ts, 0.65)[0])[0]} for ts, m in cand],
            "suspicious": m_row(best_m), "blocked": m_row(best_mb), "zero_day_hits": zh, "zero_day_n": zn,
        }
        # 15건 대응표본: 제안(최종) vs 고정(자체 τ)
        zd_idx = [i for i, r in enumerate(val) if r.label == 1 and r.is_zero_day]
        b = sum(1 for i in zd_idx if preds_final[i] and not ps[i])
        c = sum(1 for i in zd_idx if ps[i] and not preds_final[i])
        fixed_out[f"alpha_{alpha}"]["paired_vs_proposed_zero_day"] = {"proposed_hits": sum(1 for i in zd_idx if preds_final[i]),
                                                                       "fixed_hits": zh, "b_proposed_only": b, "c_fixed_only": c,
                                                                       "p_exact_two_sided": round(exact_binomial_two_sided(b, c), 4)}
        # 전체 500건 McNemar
        fixed_out[f"alpha_{alpha}"]["mcnemar_vs_proposed_all"] = fx.mcnemar(preds_final, ps, [r.label for r in val])
    out["fixed_baseline_self_tuned"] = fixed_out
    md.append("## 4. 고정 융합(0.5:0.5) 베이스라인 — 검증 집합에서 자체 τL·τH 선정\n")
    for k, f in fixed_out.items():
        s, bl, pz = f["suspicious"], f["blocked"], f["paired_vs_proposed_zero_day"]
        md.append(f"**α = {f['alpha']}** → τL = {f['tau_s_selected']} (F1 최대), τH = {f['tau_b_selected']} (정상→BLOCKED ≤ 1%, BLOCKED Recall 최대)\n")
        md.append("| τL | TP | FP | TN | FN | Recall | Precision | F1 | FPR | 미등재 15건 |\n|---|---|---|---|---|---|---|---|---|---|")
        for g in f["tau_s_grid"]:
            md.append(f"| {g['tau_s']} | {g['tp']} | {g['fp']} | {g['tn']} | {g['fn']} | {g['recall']} | {g['precision']} | {g['f1']} | {g['fpr']} | {g['zero_day']}/15 |")
        md.append(f"\n선정 결과: Recall {s['recall']} / Precision {s['precision']} / F1 {s['f1']} / FPR {s['fpr']} · BLOCKED Recall {bl['recall']} / 정상→BLOCKED {bl['fpr']} · 미등재 15건 {f['zero_day_hits']}/15")
        md.append(f"제안(최종) 11/15 vs 고정(자체 τ) {pz['fixed_hits']}/15: 제안만 탐지 b = {pz['b_proposed_only']}, 고정만 탐지 c = {pz['c_fixed_only']}, 정확 이항검정 p = {pz['p_exact_two_sided']}")
        mc = f["mcnemar_vs_proposed_all"]
        md.append(f"전체 500건 McNemar(제안 vs 고정 자체 τ): {mc}\n")

    # ── 5. VT 단독 d ≥ 5 ─────────────────────────────────────────
    vt5 = [r.detected >= 5 for r in val]
    vt1 = [r.detected >= 1 for r in val]
    out["vt_only"] = {"d_ge_5": {**m_row(fx.evaluate(val, vt5)), "zero_day_hits": zero_day_hits(val, vt5)[0],
                                 "mcnemar_vs_proposed": fx.mcnemar(preds_final, vt5, [r.label for r in val])},
                      "d_ge_1": {**m_row(fx.evaluate(val, vt1)), "zero_day_hits": zero_day_hits(val, vt1)[0],
                                 "mcnemar_vs_proposed": fx.mcnemar(preds_final, vt1, [r.label for r in val])}}
    md.append("## 5. VT 단독 행 (Table 5 후보)\n")
    md.append("| 방법 | TP | FP | TN | FN | Recall | Precision | F1 | FPR | 미등재 15건 |\n|---|---|---|---|---|---|---|---|---|---|")
    for k, v in out["vt_only"].items():
        md.append(f"| VT only ({k.replace('d_ge_', 'd ≥ ')}) | {v['tp']} | {v['fp']} | {v['tn']} | {v['fn']} | {v['recall']} | {v['precision']} | {v['f1']} | {v['fpr']} | {v['zero_day_hits']}/15 |")
    md.append(f"\nMcNemar 제안 vs VT d≥5: {out['vt_only']['d_ge_5']['mcnemar_vs_proposed']}\n")

    # ── 6. 선정 단계 ML 가중치 스윕 ─────────────────────────────
    stage = replace(rx.PAPER_V1, w_b_deep=None, alpha=final.alpha)   # d_high 유지, α 앵커 적용 직후
    stage_out = {}
    for name in ("w_a_high", "w_a_low", "w_c"):
        rows = rx.sweep(val, stage, name, rx.GRIDS[name])
        stage_out[name] = [{"value": r["value"], "recall": r["suspicious"]["recall_pct"], "precision": r["suspicious"]["precision_pct"],
                            "f1": r["suspicious"]["f1_pct"], "fpr": r["suspicious"]["fpr_pct"],
                            "blocked_recall": r["blocked"]["recall_pct"], "blocked_fpr": r["blocked"]["fpr_pct"]} for r in rows]
    out["selection_stage_weight_sweeps"] = {"base": stage.label(), "rows": stage_out}
    md.append(f"## 6. 선정 단계 가중치 스윕 (기준점: {stage.label()})\n")
    for name, rows in stage_out.items():
        here = next(r for r in rows if r["value"] == getattr(stage, name))
        best = max(rows, key=lambda r: (r["f1"], r["recall"], -r["fpr"]))
        md.append(f"**{name}** — 1차 값 {getattr(stage, name)} F1 {here['f1']} / 격자 최적 {best['value']} F1 {best['f1']} / 차이 {round(best['f1'] - here['f1'], 2)}%p → {'유지 (R1, < 1.0%p)' if best['f1'] - here['f1'] < rx.PLATEAU_PP else '이동'}\n")
        md.append("| 값 | Recall | Precision | F1 | FPR | BLOCKED R | BLOCKED FPR |\n|---|---|---|---|---|---|---|")
        for r in rows:
            md.append(f"| {r['value']} | {r['recall']} | {r['precision']} | {r['f1']} | {r['fpr']} | {r['blocked_recall']} | {r['blocked_fpr']} |")
        md.append("")

    # ── 7. 1차 심사본 results.json 발췌 ─────────────────────────
    if rx.RESULTS_JSON.exists():
        r1 = json.loads(rx.RESULTS_JSON.read_text(encoding="utf-8"))
        sw = r1.get("sweeps", {})
        out["paper_v1_results_json"] = {
            "generated_at": r1.get("meta", {}).get("generated_at"), "n_records": r1.get("meta", {}).get("n_records"),
            "sweep_keys": list(sw.keys()), "sweep_design": sw.get("design"),
            "w_ml_B": [{k: (pct(v[k]) if isinstance(v.get(k), float) and k != "value" else v.get(k)) for k in ("value", "recall", "precision", "f1", "fpr", "zero_day_recall")} for v in sw.get("w_ml_B", [])],
            "tau_blocked": [{k: (pct(v[k]) if isinstance(v.get(k), float) and k != "value" else v.get(k)) for k in ("value", "recall", "precision", "f1", "fpr", "zero_day_recall")} for v in sw.get("tau_blocked", [])],
            "latency": r1.get("latency"),
        }
        md.append(f"## 7. 1차 심사본 results.json 발췌 (생성 {out['paper_v1_results_json']['generated_at']}, n = {out['paper_v1_results_json']['n_records']}, sweeps = {out['paper_v1_results_json']['sweep_keys']})\n")
        md.append("**W_ML(B) 스윕 (1차, SUSPICIOUS 기준)**\n\n| W_ML(B) | Recall | Precision | F1 | FPR | 미등재 Recall |\n|---|---|---|---|---|---|")
        for v in out["paper_v1_results_json"]["w_ml_B"]:
            md.append(f"| {v['value']} | {v['recall']} | {v['precision']} | {v['f1']} | {v['fpr']} | {v['zero_day_recall']} |")
        md.append("\n**τH 스윕 (1차, BLOCKED 기준)**\n\n| τH | Recall | Precision | F1 | FPR | 미등재 Recall |\n|---|---|---|---|---|---|")
        for v in out["paper_v1_results_json"]["tau_blocked"]:
            md.append(f"| {v['value']} | {v['recall']} | {v['precision']} | {v['f1']} | {v['fpr']} | {v['zero_day_recall']} |")
        md.append("")

    OUT_JSON.write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    print(f"\n저장: {OUT_JSON}\n저장: {OUT_MD}")


if __name__ == "__main__":
    main()

"""재심 대응 재실험 — 검증/테스트 분리 · B상황 재설계 · 파라미터 민감도(OAT 좌표 탐색) · 최종 평가

심사위원 1(4·5·6·7·8·9·11번), 심사위원 2(1·2·3번), 심사위원 3(세 의견)에 대응하는 계산을
한 번에 수행한다. 융합 계산은 app/services/fusion.py의 fuse()를 그대로 호출한다(서버와 동일).
VirusTotal 재호출은 없다(vt_cache.jsonl 재사용).

두 가지 실행 모드 — 데이터 누수 방지를 위해 분리한다.
  --select    검증 집합(split=validation, 또는 split 열이 없으면 전체)에서
              B상황 재설계 → 파라미터 OAT 좌표 탐색 → 선정값 고정(fixed_params.json) → 검증 집합 평가
  --evaluate  fixed_params.json을 읽어 테스트 집합(split=test)을 평가만 한다. 선정 로직은 돌지 않는다.

산출: experiments/data/revision/
  revision_results.json   모든 표의 원자료
  tables.md               논문·답변서용 Markdown 표
  fixed_params.json       고정 파라미터와 선정 기준·근거
  per_url_<split>.csv     URL별 전략별 점수·판정
  zero_day_<split>.csv    VT 미등재 피싱 개별 비교
  figures/*.png           민감도 그래프
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fusion_experiment as fx  # noqa: E402
from app.services.fusion import (  # noqa: E402
    CASE_A_HIGH, CASE_A_LOW, CASE_B, CASE_C, CASE_OVERRIDE, FusionParams, OverrideRules,
    VTStatus, fuse, params_fixed, params_ml_only, select_case,
)

OUT_DIR = fx.DATA_DIR / "revision"
FIG_DIR = OUT_DIR / "figures"
FIXED = OUT_DIR / "fixed_params.json"
RESULTS_JSON = fx.DATA_DIR / "results.json"          # 1차 심사본 실험 산출물 (지연 측정값 재사용)
OFFLINE_URLS = fx.DATA_DIR / "raw" / "offline_urls.csv"  # 오프라인 학습·테스트 URL 목록 (있으면 중복 검사)

# ── 선정 기준 (사전에 고정 — 결과를 보고 바꾸지 않는다) ──
CRITERIA = {
    "R1_parsimony": "1차 심사본 값이 검증 집합의 성능 고원(최적 대비 F1 차이 < 1.0%p) 안에 있으면 그 값을 유지한다 (과적합 방지). "
                    "고원 밖이면 F1 최대 값으로 이동(동률: Recall 최대, FPR 최소).",
    "R2_anchor": "VT 쪽 파라미터는 d_high 하나에 정합시킨다: α = n̄/d_high (d ≥ d_high 에서 S_VT 가 1로 포화 → 'd_high 이상 = 높은 합의'라는 정의가 점수에 그대로 반영), "
                 "θ = d_high/n̄ (Override 가 A_HIGH 경계와 같은 지점에서 작동). n̄ = 검증 집합 VT 응답 엔진 수 중앙값.",
    "suspicious_level": "탐지 기준 = SUSPICIOUS 이상. 비교 지표 F1 (Recall·FPR 병기)",
    "blocked_level": "τH: 정상→BLOCKED 비율 ≤ 1.0% 인 후보 중 BLOCKED Recall 최대 (R1 적용: 1차 값 대비 개선 < 1.0%p 면 유지)",
    "case_b": "구조 제약: 최종 점수 상한 W_ML(B)·1.0 이 τL 을 넘어야 함(ML 확신이 매우 높으면 SUSPICIOUS 가능). "
              "ML 신뢰도가 확인된 경로 포함 URL(deep)에만 적용하고, 검증 집합에서 추가 오탐률이 2.0%p 이하인 가장 큰 W 를 택한다.",
    "note": "모든 선정은 검증 집합(1차 심사본 500건)에서만 수행. 테스트 집합 결과를 보고 파라미터를 바꾸지 않는다.",
}
BLOCKED_FPR_CAP = 0.010
CASE_B_FPR_CAP_PP = 2.0

GRIDS = {
    "alpha": [1.0, 2.0, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 18.4, 20.0, 25.0],
    "d_high": [1, 2, 3, 4, 5, 6, 7, 8, 10],
    "w_a_high": [0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50],
    "w_a_low": [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70],
    "w_c": [0.50, 0.60, 0.70, 0.80, 0.90, 1.00],
    "tau_s": [0.25, 0.30, 0.35, 0.40, 0.45],
    "tau_b": [0.45, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85],
    "theta": [None, 0.30, 0.25, 0.20, 0.15, 0.10, 0.075, 0.05, 0.03],
    "w_b_deep": [0.36, 0.38, 0.40, 0.42, 0.45, 0.50, 0.55, 0.60, 0.70],
    "w_b_all": [0.30, 0.35, 0.36, 0.38, 0.40, 0.45, 0.50, 0.60],
}
# 좌표 탐색 순서 — 영향이 큰 것부터. SUSPICIOUS 기준 → BLOCKED 기준.
SEARCH_ORDER_S = ["alpha", "d_high", "w_a_high", "w_a_low", "w_c", "tau_s"]
SEARCH_ORDER_B = ["tau_b", "theta"]


# ═══════════════════════════════════════════════════════════════
#  파라미터
# ═══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class RevParams:
    alpha: float = 3.0
    d_high: int = 5
    tau_s: float = 0.35
    tau_b: float = 0.65
    w_a_high: float = 0.25
    w_a_low: float = 0.50
    w_b: float = 0.30               # CASE_B 가중치 (루트 URL, 또는 w_b_deep 미설정 시 전체)
    w_b_deep: float | None = None   # CASE_B 경로 포함 URL 전용 가중치 (수정안 C)
    w_c: float = 0.80
    theta: float | None = 0.30      # Override 비율 임계값. None = Override 없음

    def fusion_params(self, path_type: str) -> FusionParams:
        w_b = self.w_b_deep if (self.w_b_deep is not None and path_type == "deep") else self.w_b
        return FusionParams(
            alpha=self.alpha, d_high=self.d_high,
            tau_blocked=self.tau_b, tau_suspicious=self.tau_s,
            w_ml={CASE_A_HIGH: self.w_a_high, CASE_A_LOW: self.w_a_low, CASE_B: w_b, CASE_C: self.w_c},
            override=OverrideRules(ratio_threshold=self.theta) if self.theta is not None else None,
        )

    def label(self) -> str:
        return (f"α={self.alpha} d≥{self.d_high} τL={self.tau_s} τH={self.tau_b} "
                f"W=({self.w_a_high}/{self.w_a_low}/{self.w_b}"
                f"{'·deep ' + str(self.w_b_deep) if self.w_b_deep is not None else ''}/{self.w_c}) "
                f"θ={self.theta}")


PAPER_V1 = RevParams()  # 1차 심사본 설정 (θ=0.30 → Override 발동 0건)


def fuse_rec(rec: fx.Record, rp: RevParams):
    return fuse(rec.p_ml, rec.detected, rec.total, rec.vt_status, rp.fusion_params(rec.path_type))


def predict_rp(records, rp: RevParams, blocked_only=False):
    results = [fuse_rec(r, rp) for r in records]
    preds = [(res.blocked if blocked_only else res.detected) for res in results]
    return preds, results


def metrics_dict(m: fx.Metrics) -> dict:
    d = asdict(m)
    for k in ("accuracy", "precision", "recall", "fpr", "f1"):
        d[k + "_pct"] = round(d[k] * 100, 2)
    d["recall_ci_pct"] = [round(x * 100, 1) for x in m.recall_ci]
    d["precision_ci_pct"] = [round(x * 100, 1) for x in m.precision_ci]
    d["fpr_ci_pct"] = [round(x * 100, 1) for x in m.fpr_ci]
    return d


def case_of(rec: fx.Record, rp: RevParams) -> str:
    return select_case(rec.detected, rec.total, VTStatus(rec.vt_status), rp.fusion_params(rec.path_type))


# ═══════════════════════════════════════════════════════════════
#  데이터
# ═══════════════════════════════════════════════════════════════

def load_split_map() -> dict[str, str]:
    with fx.EVALSET.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if "split" not in (reader.fieldnames or []):
            return {}
        return {r["url"]: (r.get("split") or "").strip() for r in reader}


def composition(records) -> dict:
    out: dict = {"n": len(records)}
    out["by_label_path"] = {f"{'benign' if lb == 0 else 'phishing'}/{pt}":
                            sum(1 for r in records if r.label == lb and r.path_type == pt)
                            for lb in (0, 1) for pt in ("root", "deep")}
    bands = OrderedDict()
    for key, test in [("ok · d≥5 (A_HIGH)", lambda r: r.vt_status == "ok" and r.detected >= 5),
                      ("ok · 1≤d<5 (A_LOW)", lambda r: r.vt_status == "ok" and 1 <= r.detected < 5),
                      ("ok · d=0 (B)", lambda r: r.vt_status == "ok" and r.detected == 0),
                      ("not_found (C)", lambda r: r.vt_status == "not_found")]:
        bands[key] = {"benign": sum(1 for r in records if test(r) and r.label == 0),
                      "phishing": sum(1 for r in records if test(r) and r.label == 1)}
    out["by_vt_band"] = bands
    out["static_resources"] = sum(1 for r in records if fx.is_static_resource(r.url))
    return out


def registrable(url: str) -> str:
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def overlap_check(records, split_map) -> dict:
    """① 누수·중복 확인 — 검증/테스트 간, 그리고 오프라인 데이터와의 URL·도메인 중복"""
    from app.services.url_features import preprocess_url
    out: dict = {}
    by_split: dict[str, list[fx.Record]] = {}
    for r in records:
        by_split.setdefault(split_map.get(r.url, "validation") or "validation", []).append(r)
    names = sorted(by_split)
    out["splits"] = {s: len(v) for s, v in by_split.items()}
    if len(names) >= 2:
        a, b = by_split[names[0]], by_split[names[1]]
        ka = {preprocess_url(r.url) or r.url for r in a}
        kb = {preprocess_url(r.url) or r.url for r in b}
        da = {registrable(r.url) for r in a}
        db = {registrable(r.url) for r in b}
        out["between_splits"] = {"pair": names[:2], "url_overlap": len(ka & kb),
                                 "domain_overlap": len(da & db), "domains_shared": sorted(da & db)[:50]}
    if OFFLINE_URLS.exists():
        off_keys, off_domains = set(), set()
        with OFFLINE_URLS.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            col = "url" if "url" in (reader.fieldnames or []) else (reader.fieldnames or ["url"])[0]
            for row in reader:
                u = (row.get(col) or "").strip()
                if not u:
                    continue
                off_keys.add(preprocess_url(u) or u)
                off_domains.add(registrable(u if "://" in u else "http://" + u))
        res = {}
        for s, recs in by_split.items():
            keys = {preprocess_url(r.url) or r.url for r in recs}
            doms = {registrable(r.url) for r in recs}
            res[s] = {"url_overlap": len(keys & off_keys), "domain_overlap": len(doms & off_domains),
                      "overlapping_urls": sorted(keys & off_keys)[:50]}
        out["offline"] = {"file": str(OFFLINE_URLS), "n_offline_urls": len(off_keys), "by_split": res}
    else:
        out["offline"] = {"file": str(OFFLINE_URLS), "status": "없음 — Drive Q-Guard/dataset/preprocessed_dataset.csv 를 "
                          "experiments/data/raw/offline_urls.csv 로 두면 자동 검사"}
    out["parameter_selection_history"] = (
        "1차 심사본: results.json 의 sweeps(α·τH·d_high·W_ML(B))와 override 실험이 동일 500건에서 수행됨 "
        "→ 500건은 독립 테스트셋이 아니라 검증 집합으로 선언")
    return out


# ═══════════════════════════════════════════════════════════════
#  스윕
# ═══════════════════════════════════════════════════════════════

def set_param(rp: RevParams, name: str, v) -> RevParams:
    return replace(rp, **{name: v})


def sweep(records, base: RevParams, name: str, values) -> list[dict]:
    base_results = [fuse_rec(r, base) for r in records]
    zd = [r for r in records if r.is_zero_day and r.label == 1]
    a_high_phish = [r for r in records if r.label == 1 and r.vt_status == "ok" and r.detected >= 5]
    rows = []
    for v in values:
        rp = set_param(base, name, v)
        res = [fuse_rec(r, rp) for r in records]
        preds_s = [x.detected for x in res]
        preds_b = [x.blocked for x in res]
        ms = fx.evaluate(records, preds_s)
        mb = fx.evaluate(records, preds_b)
        # 케이스 분포 (라벨별)
        dist: dict = {}
        for r, x in zip(records, res):
            c = x.case if x.case != CASE_OVERRIDE else case_of(r, rp)
            dist.setdefault(c, {"benign": 0, "phishing": 0})["phishing" if r.label else "benign"] += 1
        # 등급 분포 (라벨별)
        levels = {lb: Counter(x.risk_level for r, x in zip(records, res) if r.label == lb) for lb in (0, 1)}
        fired = [(r.label, x) for r, x in zip(records, res) if x.override_rule == "RATIO"]
        changed = sum(1 for a, b in zip(base_results, res) if a.risk_level != b.risk_level)
        row = {
            "value": v,
            "suspicious": metrics_dict(ms), "blocked": metrics_dict(mb),
            "case_distribution": dist,
            "risk_levels": {"benign": dict(levels[0]), "phishing": dict(levels[1])},
            "phish_to_secured_pct": round(levels[1].get("SECURED", 0) / max(1, sum(levels[1].values())) * 100, 2),
            "benign_to_blocked_pct": round(levels[0].get("BLOCKED", 0) / max(1, sum(levels[0].values())) * 100, 2),
            "zero_day_recall_pct": round(sum(1 for r, x in zip(records, res) if r in zd and x.detected) / len(zd) * 100, 2) if zd else None,
            "a_high_recall_pct": round(sum(1 for r, x in zip(records, res) if r in a_high_phish and x.detected) / len(a_high_phish) * 100, 2) if a_high_phish else None,
            "override_fired": len(fired),
            "override_fired_phishing": sum(1 for lb, _ in fired if lb == 1),
            "risk_level_changed_vs_base": changed,
            "delta_tp_vs_base": ms.tp - fx.evaluate(records, [x.detected for x in base_results]).tp,
            "delta_fp_vs_base": ms.fp - fx.evaluate(records, [x.detected for x in base_results]).fp,
        }
        rows.append(row)
    return rows


def pick_suspicious(rows: list[dict]):
    """F1 최대 → Recall 최대 → FPR 최소"""
    return max(rows, key=lambda r: (round(r["suspicious"]["f1"], 6), round(r["suspicious"]["recall"], 6),
                                    -round(r["suspicious"]["fpr"], 6)))


def pick_blocked(rows: list[dict]):
    ok = [r for r in rows if r["blocked"]["fpr"] <= BLOCKED_FPR_CAP + 1e-9]
    pool = ok if ok else rows
    return max(pool, key=lambda r: (round(r["blocked"]["recall"], 6), round(r["blocked"]["precision"], 6)))


def coordinate_search(records, start: RevParams, log: list) -> tuple[RevParams, dict]:
    """OAT 좌표 탐색. 각 파라미터를 순서대로 격자에서 선정하고, 변화가 없을 때까지 반복."""
    current = start
    passes = []
    for p in range(1, 4):
        changed_any = False
        pass_log = {"pass": p, "steps": []}
        for name in SEARCH_ORDER_S + SEARCH_ORDER_B:
            rows = sweep(records, current, name, GRIDS[name])
            best = pick_blocked(rows) if name in SEARCH_ORDER_B else pick_suspicious(rows)
            old = getattr(current, name)
            new = best["value"]
            pass_log["steps"].append({"param": name, "from": old, "to": new,
                                      "criterion": "blocked_level" if name in SEARCH_ORDER_B else "suspicious_level",
                                      "f1_pct": best["suspicious"]["f1_pct"], "recall_pct": best["suspicious"]["recall_pct"],
                                      "fpr_pct": best["suspicious"]["fpr_pct"],
                                      "blocked_recall_pct": best["blocked"]["recall_pct"], "blocked_fpr_pct": best["blocked"]["fpr_pct"]})
            if new != old:
                changed_any = True
                current = set_param(current, name, new)
        passes.append(pass_log)
        log.append(pass_log)
        if not changed_any:
            break
    return current, {"passes": passes, "converged": not changed_any}



PLATEAU_PP = 1.0  # R1: 이 차이(%p) 미만이면 1차 심사본 값 유지


def principled_selection(records, start: RevParams, n_ref: float) -> tuple[RevParams, list[dict], dict]:
    """사전 고정 규칙(R1 parsimony, R2 anchor, BLOCKED cap, B 구조 제약)에 따른 선정.
    순서: d_high → α → ML 가중치 → τL → B상황 재설계(τL 기준) → τH → θ.  τL 과 B 는 서로 영향을 주므로 한 번 더 확인한다.
    결과를 보고 규칙을 바꾸지 않는다."""
    log: list[dict] = []
    cur = replace(start, w_b_deep=None)
    case_b_out: dict = {}

    def record(param, old, new, rule, rows, basis="suspicious"):
        cur_row = next((r for r in rows if r["value"] == old), None)
        new_row = next((r for r in rows if r["value"] == new), None)
        log.append({"param": param, "from": old, "to": new, "rule": rule,
                    "f1_before": cur_row["suspicious"]["f1_pct"] if cur_row else None,
                    "f1_after": new_row["suspicious"]["f1_pct"] if new_row else None,
                    "recall_after": new_row["suspicious"]["recall_pct"] if new_row else None,
                    "fpr_after": new_row["suspicious"]["fpr_pct"] if new_row else None,
                    "blocked_recall_after": new_row["blocked"]["recall_pct"] if new_row else None,
                    "blocked_fpr_after": new_row["blocked"]["fpr_pct"] if new_row else None,
                    "best_in_grid": max(rows, key=lambda r: r[basis]["f1"] if basis == "suspicious" else r[basis]["recall"])["value"]})

    def r1(name, grid):
        nonlocal cur
        rows = sweep(records, cur, name, grid)
        best = pick_suspicious(rows)
        here = next(r for r in rows if r["value"] == getattr(cur, name))
        new = getattr(cur, name) if best["suspicious"]["f1_pct"] - here["suspicious"]["f1_pct"] < PLATEAU_PP else best["value"]
        record(name, getattr(cur, name), new, "R1_parsimony", rows)
        cur = set_param(cur, name, new)

    # 1) d_high — R1
    r1("d_high", [d for d in GRIDS["d_high"] if d >= 2])
    # 2) α — R2 anchor
    alpha_anchor = round(n_ref / cur.d_high, 1)
    rows = sweep(records, cur, "alpha", sorted(set(GRIDS["alpha"] + [alpha_anchor])))
    record("alpha", cur.alpha, alpha_anchor, f"R2_anchor (n̄={n_ref} / d_high={cur.d_high})", rows)
    cur = replace(cur, alpha=alpha_anchor)
    # 3) ML 가중치 — R1
    for name in ("w_a_high", "w_a_low", "w_c"):
        r1(name, GRIDS[name])
    # 4) τL — R1, 5) B 재설계 (τL 기준) — 두 번 반복해 상호 영향 확인
    for it in range(2):
        r1("tau_s", GRIDS["tau_s"])
        case_b_out = case_b_redesign(records, cur)
        new_b = case_b_out["selected_w_b_deep"]
        log.append({"param": "w_b_deep", "from": cur.w_b_deep, "to": new_b, "rule": f"case_b 구조 제약 (τL={cur.tau_s}, 추가 FPR ≤ {CASE_B_FPR_CAP_PP}%p)",
                    "f1_before": None, "f1_after": None, "recall_after": None, "fpr_after": None,
                    "blocked_recall_after": None, "blocked_fpr_after": None, "best_in_grid": None, "iteration": it + 1})
        cur = replace(cur, w_b_deep=new_b)
        rows = sweep(records, cur, "tau_s", GRIDS["tau_s"])
        best = pick_suspicious(rows)
        here = next(r for r in rows if r["value"] == cur.tau_s)
        if best["suspicious"]["f1_pct"] - here["suspicious"]["f1_pct"] < PLATEAU_PP:
            break  # τL 안정 → 종료
    # 6) τH — BLOCKED cap + R1
    rows = sweep(records, cur, "tau_b", GRIDS["tau_b"])
    best = pick_blocked(rows)
    here = next(r for r in rows if r["value"] == cur.tau_b)
    ok_here = here["blocked"]["fpr"] <= BLOCKED_FPR_CAP + 1e-9
    new = cur.tau_b if (ok_here and best["blocked"]["recall_pct"] - here["blocked"]["recall_pct"] < PLATEAU_PP) else best["value"]
    record("tau_b", cur.tau_b, new, "blocked_level + R1_parsimony", rows, basis="blocked")
    cur = replace(cur, tau_b=new)
    # 7) θ — R2 anchor
    theta_anchor = cur.d_high / n_ref
    grid_t = [t for t in GRIDS["theta"] if t is not None]
    theta_pick = min(grid_t, key=lambda t: abs(t - theta_anchor))
    rows = sweep(records, cur, "theta", GRIDS["theta"])
    record("theta", cur.theta, theta_pick, f"R2_anchor (d_high/n̄ = {theta_anchor:.3f} → 격자 {theta_pick})", rows, basis="blocked")
    cur = replace(cur, theta=theta_pick)
    return cur, log, case_b_out


# ═══════════════════════════════════════════════════════════════
#  B상황 재설계
# ═══════════════════════════════════════════════════════════════

def case_b_redesign(records, base: RevParams) -> dict:
    """구조 문제 수식 검증 + W_ML(B) 비용 곡선(전체/경로 포함 URL 한정) + 시뮬레이션"""
    b_recs = [r for r in records if r.vt_status == "ok" and r.detected == 0]
    b_benign = [r for r in b_recs if r.label == 0]
    phish = [r for r in records if r.label == 1]
    benign = [r for r in records if r.label == 0]

    def moved_to_b(r: fx.Record) -> fx.Record:
        c = fx.Record(**asdict(r))
        c.detected = 0
        c.total = r.total or 92
        c.vt_status = VTStatus.OK.value
        return c

    sim_phish = [moved_to_b(r) for r in phish]
    p_hist = {}
    for pt in ("root", "deep"):
        vals = sorted(r.p_ml for r in b_benign if r.path_type == pt)
        p_hist[pt] = {"n": len(vals),
                      "median": round(vals[len(vals) // 2], 4) if vals else None,
                      "ge_0.875": sum(v >= 0.875 for v in vals), "ge_0.95": sum(v >= 0.95 for v in vals),
                      "ge_0.70": sum(v >= 0.70 for v in vals), "ge_0.41": sum(v >= 0.41 for v in vals)}
    out: dict = {
        "structural_check": {
            "w_b": base.w_b, "ceiling": base.w_b * 1.0, "tau_s": base.tau_s,
            "detectable_at_p1": base.w_b * 1.0 >= base.tau_s,
            "formula": "S_final = W_ML·p_ML + (1−W_ML)·S_VT, CASE_B 에서는 S_VT = 0 → S_final ≤ W_ML",
        },
        "case_b_in_validation": {"n": len(b_recs), "benign": len(b_benign), "phishing": len(b_recs) - len(b_benign)},
        "benign_p_ml_distribution": p_hist,
        "option_a_all": [], "option_c_deep_only": [],
    }
    base_fp = fx.evaluate(records, [x.detected for x in [fuse_rec(r, base) for r in records]]).fp
    # 수정안 A: CASE_B 전체 가중치 상향 (심사의견 문면대로)
    for w in GRIDS["w_b_all"]:
        rp = replace(base, w_b=w, w_b_deep=None)
        m = fx.evaluate(records, [fuse_rec(r, rp).detected for r in records])
        sim = sum(1 for r in sim_phish if fuse_rec(r, rp).detected)
        sim_deep = sum(1 for r in sim_phish if r.path_type == "deep" and fuse_rec(r, rp).detected)
        out["option_a_all"].append({"w_b": w, "p_star": round(base.tau_s / w, 3), "fp": m.fp, "fp_added": m.fp - base_fp,
                                    "fpr_pct": m.fpr * 100, "f1_pct": m.f1 * 100, "recall_pct": m.recall * 100,
                                    "sim_b_recall_pct": round(sim / len(sim_phish) * 100, 2),
                                    "sim_b_recall_deep_pct": round(sim_deep / sum(1 for r in sim_phish if r.path_type == "deep") * 100, 2)})
    # 수정안 C: 경로 포함 URL 에만 상향 (루트 URL 은 ML 신뢰도 낮음)
    for w in GRIDS["w_b_deep"]:
        rp = replace(base, w_b_deep=w)
        m = fx.evaluate(records, [fuse_rec(r, rp).detected for r in records])
        sim_deep_n = sum(1 for r in sim_phish if r.path_type == "deep")
        sim_deep = sum(1 for r in sim_phish if r.path_type == "deep" and fuse_rec(r, rp).detected)
        out["option_c_deep_only"].append({"w_b_deep": w, "p_star": round(base.tau_s / w, 3), "fp": m.fp, "fp_added": m.fp - base_fp,
                                          "fpr_added_pp": round((m.fp - base_fp) / len(benign) * 100, 2),
                                          "fpr_pct": m.fpr * 100, "f1_pct": m.f1 * 100, "recall_pct": m.recall * 100,
                                          "sim_b_recall_deep_pct": round(sim_deep / sim_deep_n * 100, 2),
                                          "sim_b_recall_all_pct": round(sim_deep / len(sim_phish) * 100, 2)})
    # 선정: 제약(상한 > τL) + 추가 오탐률 ≤ CAP 인 가장 큰 W
    ok = [r for r in out["option_c_deep_only"] if r["w_b_deep"] > base.tau_s and r["fpr_added_pp"] <= CASE_B_FPR_CAP_PP]
    chosen = max(ok, key=lambda r: r["w_b_deep"]) if ok else None
    out["selected_w_b_deep"] = chosen["w_b_deep"] if chosen else None
    out["selection_rule"] = CRITERIA["case_b"]
    return out


# ═══════════════════════════════════════════════════════════════
#  최종 평가 (검증 또는 테스트 집합)
# ═══════════════════════════════════════════════════════════════

FIXED_BASELINE_TAU_S_GRID = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65]


def select_fixed_baseline_tau(records, alpha: float) -> dict:
    """고정 융합(0.5:0.5) 베이스라인의 자체 임계값 — 제안 방법과 같은 규칙(τL: F1 최대, τH: 정상→BLOCKED ≤ cap 중 BLOCKED Recall 최대)을
    검증 집합에서 적용한다. 제안 방법용 τL을 그대로 쓰면 베이스라인에 불리한 비교가 되므로(검토 지적) 공정 비교용 행을 만든다."""
    def run(ts, tb):
        p = params_fixed(0.50, alpha=alpha, tau_suspicious=ts, tau_blocked=tb)
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in records]
        return fx.evaluate(records, [x.detected for x in res]), fx.evaluate(records, [x.blocked for x in res])
    cand = [(ts, run(ts, 0.65)[0]) for ts in FIXED_BASELINE_TAU_S_GRID]
    ts_best, m_best = max(cand, key=lambda c: (round(c[1].f1, 6), round(c[1].recall, 6), -round(c[1].fpr, 6)))
    tb_rows = [(tb, run(ts_best, tb)[1]) for tb in GRIDS["tau_b"] if tb > ts_best]
    ok = [c for c in tb_rows if c[1].fpr <= BLOCKED_FPR_CAP + 1e-9]
    tb_best, _ = max(ok or tb_rows, key=lambda c: (round(c[1].recall, 6), round(c[1].precision, 6)))
    return {"alpha": alpha, "tau_s": ts_best, "tau_b": tb_best,
            "rule": "검증 집합에서 고정 융합 자체 선정: τL = F1 최대(격자 0.25~0.65), τH = 정상→BLOCKED ≤ 1% 중 BLOCKED Recall 최대",
            "tau_s_grid": [{"tau_s": ts, "f1_pct": round(m.f1 * 100, 2), "recall_pct": round(m.recall * 100, 2), "fpr_pct": round(m.fpr * 100, 2)} for ts, m in cand]}


def strategies(final: RevParams, baseline_fixed: dict | None = None):
    bf = baseline_fixed or {"alpha": final.alpha, "tau_s": final.tau_s, "tau_b": final.tau_b}
    return [
        ("ML only (threshold 0.41)", "ml"),
        ("VT only (d≥1) — 참고", "vt1"),
        ("VT only (d≥5) — 참고", "vt5"),
        ("Fixed 0.5:0.5 — 1차 심사본 설정(α=3.0)", "fixed"),
        ("Fixed 0.5:0.5 — 수정 α·τ 적용", ("fixed_same", final)),
        (f"Fixed 0.5:0.5 — 검증 집합 자체 τ (τL {bf['tau_s']}, τH {bf['tau_b']})", ("fixed_own", bf)),
        ("Adaptive — 1차 심사본 파라미터", PAPER_V1),
        ("Adaptive — 수정 파라미터, Override 없음", replace(final, theta=None)),
        ("Adaptive — 수정 파라미터 + Override", final),
    ]


def run_strategy(records, strat):
    if strat == "ml":
        p = params_ml_only(fx.MODEL_THRESHOLD)
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in records]
        return [x.detected for x in res], [x.blocked for x in res], res
    if strat == "vt1":
        pr = [r.detected >= 1 for r in records]
        return pr, pr, None
    if strat == "vt5":
        pr = [r.detected >= 5 for r in records]
        return pr, pr, None
    if strat == "fixed":
        p = params_fixed(0.50)
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in records]
        return [x.detected for x in res], [x.blocked for x in res], res
    if isinstance(strat, tuple) and strat[0] == "fixed_same":
        f = strat[1]
        p = params_fixed(0.50, alpha=f.alpha, tau_suspicious=f.tau_s, tau_blocked=f.tau_b)
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in records]
        return [x.detected for x in res], [x.blocked for x in res], res
    if isinstance(strat, tuple) and strat[0] == "fixed_own":
        bf = strat[1]
        p = params_fixed(0.50, alpha=bf["alpha"], tau_suspicious=bf["tau_s"], tau_blocked=bf["tau_b"])
        res = [fuse(r.p_ml, r.detected, r.total, r.vt_status, p) for r in records]
        return [x.detected for x in res], [x.blocked for x in res], res
    preds, res = predict_rp(records, strat)
    return preds, [x.blocked for x in res], res


def by_case_confusion(records, res, preds, rp: RevParams) -> dict:
    out: dict = {}
    for case in (CASE_A_HIGH, CASE_A_LOW, CASE_B, CASE_C):
        idx = [i for i, r in enumerate(records) if case_of(r, rp) == case]
        if not idx:
            continue
        sub = [records[i] for i in idx]
        m = fx.evaluate(sub, [preds[i] for i in idx])
        out[case] = {"n": m.n, "benign": m.fp + m.tn, "phishing": m.tp + m.fn,
                     "tp": m.tp, "fn": m.fn, "fp": m.fp, "tn": m.tn}
    return out


def final_evaluation(records, final: RevParams, split_name: str, baseline_fixed: dict | None = None) -> tuple[dict, list[dict], dict]:
    out: dict = {"split": split_name, "n": len(records), "composition": composition(records), "strategies": OrderedDict(),
                 "baseline_fixed_tau": baseline_fixed}
    per_url = {r.url: {"url": r.url, "split": split_name, "label": r.label, "path_type": r.path_type, "source": r.source,
                       "vt_status": r.vt_status, "d": r.detected, "n": r.total, "p_ml": round(r.p_ml, 4)} for r in records}
    truth = [r.label for r in records]
    preds_by = {}
    strats = strategies(final, baseline_fixed)
    for name, strat in strats:
        ps, pb, res = run_strategy(records, strat)
        preds_by[name] = ps
        entry = {"suspicious": metrics_dict(fx.evaluate(records, ps)), "blocked": metrics_dict(fx.evaluate(records, pb))}
        if isinstance(strat, RevParams):
            entry["params"] = asdict(strat)
            entry["by_case"] = by_case_confusion(records, res, ps, strat)
            entry["fn_urls"] = [r.url for r, p in zip(records, ps) if r.label == 1 and not p]
            entry["fp_urls"] = [r.url for r, p in zip(records, ps) if r.label == 0 and p]
            entry["override_fired"] = sum(1 for x in res if x.override_rule == "RATIO")
        out["strategies"][name] = entry
        for i, r in enumerate(records):
            row = per_url[r.url]
            row[f"{name} | detected"] = int(ps[i])
            row[f"{name} | blocked"] = int(pb[i])
            if res is not None:
                row[f"{name} | S_final"] = res[i].final_score
                row[f"{name} | case"] = res[i].case
    names = list(out["strategies"])
    FIXED1, FIXED2, FIXED3, V1, NEW_NO, NEW = names[3], names[4], names[5], names[6], names[7], names[8]
    pairs = [(FIXED1, V1), (FIXED2, NEW), (FIXED3, NEW), (V1, NEW), (NEW_NO, NEW), (names[0], NEW), (names[1], NEW), (names[2], NEW)]
    out["mcnemar"] = {f"{a} vs {b}": fx.mcnemar(preds_by[a], preds_by[b], truth) for a, b in pairs}

    # VT 미등재 피싱 개별 비교 (11번 · 3-3)
    zd = [r for r in records if r.is_zero_day and r.label == 1]
    zrows = []
    for r in zd:
        row = {"url": r.url, "path_type": r.path_type, "p_ml": round(r.p_ml, 4)}
        for name, strat in strats:
            if strat in ("vt1", "vt5"):
                continue
            ps, _, res = run_strategy([r], strat)
            row[f"{name} | S_final"] = res[0].final_score if res else None
            row[f"{name} | detected"] = int(ps[0])
        zrows.append(row)
    zsum = {"n_zero_day_phishing": len(zd), "n_case_b_phishing": sum(1 for r in records if r.label == 1 and r.vt_status == "ok" and r.detected == 0)}
    for name, strat in strats:
        if strat in ("vt1", "vt5"):
            continue
        hit = sum(row[f"{name} | detected"] for row in zrows)
        zsum[name] = {"hit": hit, "n": len(zd), "recall_pct": round(hit / len(zd) * 100, 2) if zd else None,
                      "wilson_ci_pct": [round(x * 100, 1) for x in fx.wilson_ci(hit, len(zd))] if zd else None}
    # 대응표본 — 고정 vs 수정 적응형 (정확 이항). 공식 비교 = 고정 융합(검증 집합 자체 τ) vs 제안(고정 파라미터)
    if zd:
        a = [row[f"{FIXED1} | detected"] for row in zrows]
        a2 = [row[f"{FIXED2} | detected"] for row in zrows]
        a3 = [row[f"{FIXED3} | detected"] for row in zrows]
        b = [row[f"{NEW} | detected"] for row in zrows]
        a1 = [row[f"{V1} | detected"] for row in zrows]
        zsum["paired_fixed_v1_vs_paper_v1"] = fx.mcnemar([bool(x) for x in a], [bool(x) for x in a1], [1] * len(zd))
        zsum["paired_fixed_same_vs_proposed"] = fx.mcnemar([bool(x) for x in a2], [bool(x) for x in b], [1] * len(zd))
        zsum["paired_fixed_own_vs_proposed (공식 비교)"] = fx.mcnemar([bool(x) for x in a3], [bool(x) for x in b], [1] * len(zd))
        zsum["paired_paper_v1_vs_proposed"] = fx.mcnemar([bool(x) for x in a1], [bool(x) for x in b], [1] * len(zd))
    out["zero_day"] = zsum
    return out, list(per_url.values()), {"rows": zrows, "summary": zsum}


# ═══════════════════════════════════════════════════════════════
#  그림
# ═══════════════════════════════════════════════════════════════

def make_figures(sweeps: dict, final: RevParams, case_b: dict) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    style = {"recall": dict(color="#000000", ls="-", marker="o", label="Recall"),
             "precision": dict(color="#5A5A5A", ls="--", marker="s", label="Precision"),
             "f1": dict(color="#9A9A9A", ls="-.", marker="^", label="F1-score"),
             "fpr": dict(color="#000000", ls=":", marker="D", label="FPR")}
    made = []

    def line_fig(key, xlabel, chosen, basis="suspicious", fname=None, series=("recall", "precision", "f1", "fpr")):
        rows = sweeps[key]
        xs = [("none" if r["value"] is None else r["value"]) for r in rows]
        xnum = list(range(len(xs)))
        fig, ax = plt.subplots(figsize=(6.0, 3.6), dpi=150)
        for s in series:
            ys = [r[basis][s] * 100 for r in rows]
            ax.plot(xnum, ys, **style[s])
        ax.set_xticks(xnum)
        ax.set_xticklabels([str(x) for x in xs])
        ax.set_xlabel(xlabel)
        ax.set_ylabel("%")
        ax.set_ylim(0, 102)
        ax.grid(True, color="#D9D9D9", lw=0.6)
        if chosen in [r["value"] for r in rows]:
            ax.axvline(xs.index("none" if chosen is None else chosen), color="#000000", lw=0.8, alpha=0.6)
        ax.set_title(f"{xlabel} sweep — {'BLOCKED' if basis == 'blocked' else 'SUSPICIOUS+'} basis (validation, OAT)", fontsize=9)
        ax.legend(fontsize=8, ncol=2, loc="center right")
        fig.tight_layout()
        path = FIG_DIR / (fname or f"sweep_{key}.png")
        fig.savefig(path)
        plt.close(fig)
        made.append(str(path))

    line_fig("alpha_no_override", "alpha (VT amplification), override off", final.alpha, fname="sweep_alpha.png")
    line_fig("d_high_no_override", "d_high (CASE_A_HIGH boundary), override off", final.d_high, fname="sweep_d_high.png")
    line_fig("tau_s", "tau_L (SUSPICIOUS threshold)", final.tau_s)
    line_fig("tau_b", "tau_H (BLOCKED threshold)", final.tau_b, basis="blocked")
    line_fig("theta", "theta (override ratio)", final.theta, basis="blocked")
    line_fig("w_a_high", "W_ML (CASE_A_HIGH)", final.w_a_high)
    line_fig("w_a_low", "W_ML (CASE_A_LOW)", final.w_a_low)
    line_fig("w_c", "W_ML (CASE_C)", final.w_c)

    # B상황 비용 곡선
    fig, ax = plt.subplots(figsize=(6.0, 3.6), dpi=150)
    a = case_b["option_a_all"]
    c = case_b["option_c_deep_only"]
    ax.plot([r["w_b"] for r in a], [r["fpr_pct"] for r in a], color="#000000", ls="-", marker="o", label="FPR — option A (all CASE_B)")
    ax.plot([r["w_b_deep"] for r in c], [r["fpr_pct"] for r in c], color="#5A5A5A", ls="--", marker="s", label="FPR — option C (deep URLs only)")
    ax.plot([r["w_b"] for r in a], [r["sim_b_recall_pct"] for r in a], color="#000000", ls=":", marker="D", label="simulated CASE_B recall — A")
    ax.plot([r["w_b_deep"] for r in c], [r["sim_b_recall_deep_pct"] for r in c], color="#9A9A9A", ls="-.", marker="^", label="simulated CASE_B recall (deep) — C")
    ax.set_xlabel("W_ML (CASE_B)")
    ax.set_ylabel("%")
    ax.grid(True, color="#D9D9D9", lw=0.6)
    ax.set_title("CASE_B redesign cost curve (validation)", fontsize=9)
    ax.legend(fontsize=7)
    fig.tight_layout()
    path = FIG_DIR / "case_b_cost_curve.png"
    fig.savefig(path)
    plt.close(fig)
    made.append(str(path))
    return made


# ═══════════════════════════════════════════════════════════════
#  Markdown 표
# ═══════════════════════════════════════════════════════════════

def md_sweep(rows, name, chosen, basis="suspicious") -> str:
    L = [f"| {name} | Recall | Precision | F1 | FPR | BLOCKED Recall | BLOCKED FPR | 피싱→SECURED | 정상→BLOCKED | 미등재 피싱 Recall | A_HIGH 피싱 Recall | 판정 변경 수 |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        v = "없음" if r["value"] is None else r["value"]
        mark = " **(선정)**" if r["value"] == chosen else ""
        s, b = r["suspicious"], r["blocked"]
        L.append(f"| {v}{mark} | {s['recall_pct']:.2f} | {s['precision_pct']:.2f} | {s['f1_pct']:.2f} | {s['fpr_pct']:.2f} | "
                 f"{b['recall_pct']:.2f} | {b['fpr_pct']:.2f} | {r['phish_to_secured_pct']:.2f} | {r['benign_to_blocked_pct']:.2f} | "
                 f"{r['zero_day_recall_pct']} | {r['a_high_recall_pct']} | {r['risk_level_changed_vs_base']} |")
    return "\n".join(L)


def md_theta(rows, chosen) -> str:
    L = ["| θ | 발동 건수 | 발동 중 피싱 | SUSPICIOUS+ TP | FP | FN | Recall | BLOCKED TP | BLOCKED FP | BLOCKED Recall | BLOCKED Precision | 판정 변경 수 |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        v = "없음" if r["value"] is None else r["value"]
        mark = " **(선정)**" if r["value"] == chosen else ""
        s, b = r["suspicious"], r["blocked"]
        L.append(f"| {v}{mark} | {r['override_fired']} | {r['override_fired_phishing']} | {s['tp']} | {s['fp']} | {s['fn']} | {s['recall_pct']:.2f} | "
                 f"{b['tp']} | {b['fp']} | {b['recall_pct']:.2f} | {b['precision_pct']:.2f} | {r['risk_level_changed_vs_base']} |")
    return "\n".join(L)


def md_case_dist(rows, name) -> str:
    L = [f"| {name} | A_HIGH 정상/피싱 | A_LOW 정상/피싱 | B 정상/피싱 | C 정상/피싱 |", "|---|---|---|---|---|"]
    for r in rows:
        d = r["case_distribution"]
        def cell(c):
            x = d.get(c, {"benign": 0, "phishing": 0}); return f"{x['benign']}/{x['phishing']}"
        L.append(f"| {r['value']} | {cell(CASE_A_HIGH)} | {cell(CASE_A_LOW)} | {cell(CASE_B)} | {cell(CASE_C)} |")
    return "\n".join(L)


def md_final(ev: dict) -> str:
    L = [f"| 방법 | TP | FP | TN | FN | Accuracy | Precision | Recall [95% CI] | F1 | FPR | BLOCKED Recall | BLOCKED FPR |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, e in ev["strategies"].items():
        s, b = e["suspicious"], e["blocked"]
        L.append(f"| {name} | {s['tp']} | {s['fp']} | {s['tn']} | {s['fn']} | {s['accuracy_pct']:.2f} | {s['precision_pct']:.2f} | "
                 f"{s['recall_pct']:.2f} [{s['recall_ci_pct'][0]}, {s['recall_ci_pct'][1]}] | {s['f1_pct']:.2f} | {s['fpr_pct']:.2f} | "
                 f"{b['recall_pct']:.2f} | {b['fpr_pct']:.2f} |")
    return "\n".join(L)


def md_by_case(e: dict) -> str:
    L = ["| Case | n | 정상 | 피싱 | TP | FN | FP | TN |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for c, x in e["by_case"].items():
        L.append(f"| {c} | {x['n']} | {x['benign']} | {x['phishing']} | {x['tp']} | {x['fn']} | {x['fp']} | {x['tn']} |")
    return "\n".join(L)


# ═══════════════════════════════════════════════════════════════
#  main
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(description="재심 대응 재실험")
    ap.add_argument("--select", action="store_true", help="검증 집합에서 파라미터 선정 + 검증 집합 평가")
    ap.add_argument("--evaluate", action="store_true", help="fixed_params.json 으로 test split 평가 (선정 없음)")
    ap.add_argument("--validation-split", default="validation")
    ap.add_argument("--test-split", default="test")
    args = ap.parse_args()
    if not (args.select or args.evaluate):
        ap.error("--select 또는 --evaluate 를 지정하세요")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records = fx.attach_ml_probabilities(fx.load_records())
    split_map = load_split_map()
    if split_map:
        val = [r for r in records if split_map.get(r.url) == args.validation_split]
        test = [r for r in records if split_map.get(r.url) == args.test_split]
    else:
        fx.logger.warning("evalset.csv 에 split 열이 없음 — 전체 %d건을 검증 집합으로 취급 (테스트 집합 없음)", len(records))
        val, test = records, []

    results: dict = {"meta": {
        "generated_at": datetime.now(timezone.utc).isoformat(), "mode": "select" if args.select else "evaluate",
        "model_file": fx._LOCAL_MODEL_PATH.name, "ml_threshold": fx.MODEL_THRESHOLD,
        "n_validation": len(val), "n_test": len(test), "split_column_present": bool(split_map),
        "criteria": CRITERIA, "grids": {k: v for k, v in GRIDS.items()},
        "note": "융합 계산은 app.services.fusion.fuse() — 서버와 동일. VT 재호출 0건.",
    }}
    results["overlap_check"] = overlap_check(records, split_map)
    md: list[str] = [f"# 재심 대응 재실험 결과 ({results['meta']['generated_at'][:19]} UTC)\n"]

    if args.select:
        if not val:
            raise SystemExit("검증 집합이 비어 있습니다.")
        fx.section(f"[select] 검증 집합 n={len(val)}")
        # ③ B상황 재설계 — 1차 심사본 기준점에서의 비용 곡선(보고용). 최종 선정은 τL 확정 후 선정 함수 안에서 다시 수행.
        cb_v1 = case_b_redesign(val, PAPER_V1)
        results["case_b_redesign_at_paper_point"] = cb_v1
        start = PAPER_V1
        print(f"\nB상황 재설계(1차 기준점 τL={PAPER_V1.tau_s}): W_ML(B, deep) 후보 = {cb_v1['selected_w_b_deep']}")
        # ④ 규칙 기반 선정 (R1 parsimony · R2 anchor · BLOCKED cap)
        n_ref = float(sorted(r.total for r in val if r.vt_status == "ok")[len([r for r in val if r.vt_status == "ok"]) // 2])
        results["n_ref_engines_median"] = n_ref
        final, sel_log, cb = principled_selection(val, start, n_ref)
        results["selection_log"] = sel_log
        results["case_b_redesign"] = cb
        print(f"B상황 재설계(최종 τL={final.tau_s}): W_ML(B, deep) = {final.w_b_deep} (루트 URL 은 {final.w_b} 유지)")
        results["start_params"] = asdict(start)
        results["final_params"] = asdict(final)
        print("\n규칙 기반 선정 결과:", final.label())
        for s_ in sel_log:
            print(f"  {s_['param']:<9} {s_['from']} → {s_['to']}  [{s_['rule']}]  F1 {s_['f1_before']} → {s_['f1_after']}  R {s_['recall_after']} FPR {s_['fpr_after']} | B-R {s_['blocked_recall_after']} B-FPR {s_['blocked_fpr_after']} | 격자 최적 {s_['best_in_grid']}")
        greedy_start = replace(start, w_b_deep=final.w_b_deep)
        # 부록: 제약 없는 탐욕 좌표 탐색 (과적합 경고용 — 채택하지 않음)
        glog: list = []
        greedy_final, greedy = coordinate_search(val, greedy_start, glog)
        results["appendix_greedy_unconstrained"] = {"warning": "F1 최대만 좇는 좌표 탐색 — 검증 집합에 과적합되고 설계 의미(A_HIGH 가중·4-Case 구조)가 무너지므로 채택하지 않음",
                                                   "final_params": asdict(greedy_final), "passes": greedy["passes"]}
        # 최종점 주변 OAT 스윕 (논문 민감도 표·그림용)
        sweeps = {}
        for name in SEARCH_ORDER_S + SEARCH_ORDER_B:
            sweeps[name] = sweep(val, final, name, GRIDS[name])
        # Override 를 끈 상태의 α·d_high 스윕 — 융합 점수 자체의 민감도 (Override 가 A_HIGH 를 가리지 않도록)
        no_ov = replace(final, theta=None)
        sweeps["alpha_no_override"] = sweep(val, no_ov, "alpha", sorted(set(GRIDS["alpha"] + [final.alpha])))
        sweeps["d_high_no_override"] = sweep(val, no_ov, "d_high", GRIDS["d_high"])
        # 1차 심사본 설정 주변 스윕도 보관 (개선 전 비교용)
        sweeps_v1 = {name: sweep(val, PAPER_V1, name, GRIDS[name]) for name in ("alpha", "d_high", "tau_s", "tau_b", "theta")}
        results["sweeps_final"] = sweeps
        results["sweeps_paper_v1"] = sweeps_v1
        # τL × τH 격자 (등급 분포)
        grid = []
        for ts in GRIDS["tau_s"]:
            for tb in GRIDS["tau_b"]:
                if tb <= ts:
                    continue
                rp = replace(final, tau_s=ts, tau_b=tb)
                res = [fuse_rec(r, rp) for r in val]
                lv = {lb: Counter(x.risk_level for r, x in zip(val, res) if r.label == lb) for lb in (0, 1)}
                ms = fx.evaluate(val, [x.detected for x in res]); mb = fx.evaluate(val, [x.blocked for x in res])
                grid.append({"tau_s": ts, "tau_b": tb,
                             "phishing": {k: lv[1].get(k, 0) for k in ("SECURED", "SUSPICIOUS", "BLOCKED")},
                             "benign": {k: lv[0].get(k, 0) for k in ("SECURED", "SUSPICIOUS", "BLOCKED")},
                             "phish_to_secured_pct": round(lv[1].get("SECURED", 0) / 250 * 100, 2) if val else None,
                             "benign_to_blocked_pct": round(lv[0].get("BLOCKED", 0) / max(1, sum(lv[0].values())) * 100, 2),
                             "f1_pct": round(ms.f1 * 100, 2), "recall_pct": round(ms.recall * 100, 2), "fpr_pct": round(ms.fpr * 100, 2),
                             "blocked_recall_pct": round(mb.recall * 100, 2), "blocked_fpr_pct": round(mb.fpr * 100, 2)})
        results["tau_grid"] = grid
        # 고정 융합 베이스라인의 자체 τ (공정 비교용 — 테스트 평가에서도 이 값을 그대로 쓴다)
        baseline_fixed = select_fixed_baseline_tau(val, final.alpha)
        results["baseline_fixed_tau"] = baseline_fixed
        print(f"고정 융합 베이스라인 자체 τ (검증 집합): τL={baseline_fixed['tau_s']} τH={baseline_fixed['tau_b']} (α={final.alpha})")
        # ⑤ 고정
        fixed = {"params": asdict(final), "selected_on": f"{args.validation_split} (n={len(val)})",
                 "criteria": CRITERIA, "case_b_rule": cb["selection_rule"], "selected_at": results["meta"]["generated_at"],
                 "n_ref_engines_median": n_ref, "selection_log": sel_log,
                 "baseline_fixed": {k: baseline_fixed[k] for k in ("alpha", "tau_s", "tau_b", "rule")}}
        FIXED.write_text(json.dumps(fixed, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        # 검증 집합 최종 평가
        ev, per_url, zd = final_evaluation(val, final, args.validation_split, baseline_fixed)
        results["evaluation_validation"] = ev
        _write_csv(OUT_DIR / f"per_url_{args.validation_split}.csv", per_url)
        _write_csv(OUT_DIR / f"zero_day_{args.validation_split}.csv", zd["rows"])
        figs = make_figures(sweeps, final, cb)
        results["figures"] = figs
        # Markdown
        md.append("## 선정 기준\n" + "\n".join(f"- **{k}**: {v}" for k, v in CRITERIA.items()) + "\n")
        md.append(f"## ③ B상황 재설계 — 비용 곡선 (검증 집합, 최종 τL={final.tau_s} 기준; 1차 기준점 τL=0.35 곡선은 JSON case_b_redesign_at_paper_point)\n")
        md.append(f"구조 검증: CASE_B 최종 점수 상한 = W_ML(B)×1.0 = {cb['structural_check']['ceiling']:.2f} < τL {cb['structural_check']['tau_s']} → p_ML=1.0 이어도 SECURED. "
                  f"검증 집합 CASE_B {cb['case_b_in_validation']['n']}건은 전부 정상(피싱 0건). CASE_B 정상 URL 의 p_ML: 루트 {cb['benign_p_ml_distribution']['root']['n']}건 중앙값 {cb['benign_p_ml_distribution']['root']['median']}, "
                  f"경로 포함 {cb['benign_p_ml_distribution']['deep']['n']}건 중앙값 {cb['benign_p_ml_distribution']['deep']['median']}.\n")
        md.append("수정안 A — CASE_B 전체 W_ML 상향 (심사의견 문면)\n\n| W_ML(B) | p* = τL/W | FP | 추가 FP | FPR | F1 | 시뮬레이션 B 재현율(전체 피싱) |\n|---|---:|---:|---:|---:|---:|---:|")
        for r in cb["option_a_all"]:
            md.append(f"| {r['w_b']} | {r['p_star']} | {r['fp']} | {r['fp_added']} | {r['fpr_pct']:.2f} | {r['f1_pct']:.2f} | {r['sim_b_recall_pct']:.2f} |")
        md.append("\n수정안 C — 경로 포함 URL 에만 W_ML 상향 (루트 URL 은 0.30 유지)\n\n| W_ML(B, deep) | p* | FP | 추가 FP | 추가 FPR(%p) | FPR | F1 | 시뮬레이션 B 재현율(경로 포함 피싱) | (전체 피싱 기준) |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for r in cb["option_c_deep_only"]:
            mark = " **(선정)**" if r["w_b_deep"] == cb["selected_w_b_deep"] else ""
            md.append(f"| {r['w_b_deep']}{mark} | {r['p_star']} | {r['fp']} | {r['fp_added']} | {r['fpr_added_pp']} | {r['fpr_pct']:.2f} | {r['f1_pct']:.2f} | {r['sim_b_recall_deep_pct']:.2f} | {r['sim_b_recall_all_pct']:.2f} |")
        md.append(f"\n## ④ 규칙 기반 선정 로그 (n̄ = {n_ref})\n\n| 파라미터 | 1차 심사본 | 선정 | 규칙 | F1 전 → 후 | Recall | FPR | BLOCKED Recall | BLOCKED FPR | 격자 내 최적값 |\n|---|---|---|---|---|---:|---:|---:|---:|---|")
        for s_ in sel_log:
            md.append(f"| {s_['param']} | {s_['from']} | {s_['to']} | {s_['rule']} | {s_['f1_before']} → {s_['f1_after']} | {s_['recall_after']} | {s_['fpr_after']} | {s_['blocked_recall_after']} | {s_['blocked_fpr_after']} | {s_['best_in_grid']} |".replace("None", "—"))
        md.append(f"\n최종: `{final.label()}`\n")
        md.append("부록 — 제약 없는 탐욕 좌표 탐색 결과(채택 안 함, 과적합 경고): `" + RevParams(**results["appendix_greedy_unconstrained"]["final_params"]).label() + "`\n")
        md.append("## ④ 최종점 주변 OAT 민감도 (검증 집합)\n")
        for name, label in [("alpha", "α"), ("d_high", "d_high"), ("w_a_high", "W_ML(A_HIGH)"), ("w_a_low", "W_ML(A_LOW)"), ("w_c", "W_ML(C)"), ("tau_s", "τL"), ("tau_b", "τH")]:
            md.append(f"### {label}\n\n" + md_sweep(sweeps[name], label, getattr(final, name)) + "\n")
            if name == "d_high":
                md.append("케이스 분포 (정상/피싱)\n\n" + md_case_dist(sweeps[name], "d_high") + "\n")
        md.append("### θ (Override)\n\n" + md_theta(sweeps["theta"], final.theta) + "\n")
        md.append("### α — Override 없음 (융합 점수 자체의 민감도)\n\n" + md_sweep(sweeps["alpha_no_override"], "α", final.alpha) + "\n")
        md.append("### d_high — Override 없음\n\n" + md_sweep(sweeps["d_high_no_override"], "d_high", final.d_high) + "\n")
        md.append("### τL × τH 격자 — 등급 분포 (피싱 S/Su/B · 정상 S/Su/B)\n\n| τL | τH | 피싱 SECURED/SUSPICIOUS/BLOCKED | 정상 SECURED/SUSPICIOUS/BLOCKED | 피싱→SECURED % | 정상→BLOCKED % | F1 | BLOCKED Recall |\n|---|---|---|---|---:|---:|---:|---:|")
        for g in grid:
            p_, b_ = g["phishing"], g["benign"]
            md.append(f"| {g['tau_s']} | {g['tau_b']} | {p_['SECURED']}/{p_['SUSPICIOUS']}/{p_['BLOCKED']} | {b_['SECURED']}/{b_['SUSPICIOUS']}/{b_['BLOCKED']} | {g['phish_to_secured_pct']} | {g['benign_to_blocked_pct']} | {g['f1_pct']} | {g['blocked_recall_pct']} |")
        md.append("\n## 1차 심사본 설정 주변 스윕 (개선 전 — 비교용)\n")
        for name, label in [("alpha", "α"), ("d_high", "d_high"), ("tau_s", "τL"), ("tau_b", "τH")]:
            md.append(f"### {label} (1차 심사본 기준점)\n\n" + md_sweep(sweeps_v1[name], label, getattr(PAPER_V1, name)) + "\n")
        md.append("### θ (1차 심사본 기준점)\n\n" + md_theta(sweeps_v1["theta"], PAPER_V1.theta) + "\n")
        md.append(f"## 검증 집합 최종 평가 (n={len(val)})\n\n" + md_final(ev) + "\n")
        md.append(f"고정 융합 베이스라인 자체 τ 선정 (검증 집합, α={baseline_fixed['alpha']}): τL={baseline_fixed['tau_s']}, τH={baseline_fixed['tau_b']} — {baseline_fixed['rule']}\n\n| τL | F1 | Recall | FPR |\n|---|---:|---:|---:|")
        for g in baseline_fixed["tau_s_grid"]:
            md.append(f"| {g['tau_s']} | {g['f1_pct']} | {g['recall_pct']} | {g['fpr_pct']} |")
        md.append("")
        for name in list(ev["strategies"])[6:]:
            md.append(f"### 케이스별 — {name}\n\n" + md_by_case(ev["strategies"][name]) + "\n")
        md.append("### McNemar\n\n| 비교 | b (앞만 정답) | c (뒤만 정답) | p | 방법 |\n|---|---:|---:|---|---|")
        for k, v in ev["mcnemar"].items():
            md.append(f"| {k} | {v['b']} | {v['c']} | {v['p_value']:.3g} | {v['method']} |")
        md.append("\n### VT 미등재 피싱 (11번·3-3)\n\n" + json.dumps(zd["summary"], ensure_ascii=False, indent=1, default=str) + "\n")

    if args.evaluate:
        if not FIXED.exists():
            raise SystemExit("fixed_params.json 이 없습니다 — 먼저 --select 를 실행하세요")
        fixed = json.loads(FIXED.read_text(encoding="utf-8"))
        final = RevParams(**fixed["params"])
        baseline_fixed = fixed.get("baseline_fixed")  # 검증 집합에서 정한 고정 융합 자체 τ — 여기서 재선정하지 않는다
        if baseline_fixed is None:
            fx.logger.warning("fixed_params.json 에 baseline_fixed 가 없음 — 고정 융합 자체 τ 행은 제안 방법의 τ 로 대체됩니다 (--select 재실행 권장)")
        results["final_params"] = asdict(final)
        results["baseline_fixed_tau"] = baseline_fixed
        results["fixed_params_selected_at"] = fixed.get("selected_at")
        if not test:
            fx.logger.warning("테스트 집합(split=%s)이 비어 있습니다 — evalset.csv 에 split 열과 test 행을 추가하세요", args.test_split)
        else:
            fx.section(f"[evaluate] 테스트 집합 n={len(test)}  (파라미터 고정: {fixed.get('selected_at')})")
            ev, per_url, zd = final_evaluation(test, final, args.test_split, baseline_fixed)
            results["evaluation_test"] = ev
            _write_csv(OUT_DIR / f"per_url_{args.test_split}.csv", per_url)
            _write_csv(OUT_DIR / f"zero_day_{args.test_split}.csv", zd["rows"])
            md.append(f"## 테스트 집합 최종 평가 (n={len(test)}) — 파라미터 고정 `{final.label()}`\n\n" + md_final(ev) + "\n")
            for name in list(ev["strategies"])[6:]:
                md.append(f"### 케이스별 — {name}\n\n" + md_by_case(ev["strategies"][name]) + "\n")
            md.append("### McNemar\n\n| 비교 | b | c | p | 방법 |\n|---|---:|---:|---|---|")
            for k, v in ev["mcnemar"].items():
                md.append(f"| {k} | {v['b']} | {v['c']} | {v['p_value']:.3g} | {v['method']} |")
            md.append("\n### VT 미등재 피싱\n\n" + json.dumps(zd["summary"], ensure_ascii=False, indent=1, default=str) + "\n")
            print(md_final(ev))

    # 처리 지연 (12번) — 1차 심사본 results.json 의 측정값 재사용
    if RESULTS_JSON.exists():
        try:
            results["latency_from_results_json"] = json.loads(RESULTS_JSON.read_text(encoding="utf-8")).get("latency")
        except Exception:
            pass

    md.append("## ① 누수·중복 확인\n\n```json\n" + json.dumps(results["overlap_check"], ensure_ascii=False, indent=1, default=str) + "\n```\n")
    out_json = OUT_DIR / ("revision_results.json" if args.select else "revision_results_test.json")
    out_json.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (OUT_DIR / ("tables.md" if args.select else "tables_test.md")).write_text("\n".join(md), encoding="utf-8")
    print(f"\n산출물: {OUT_DIR}")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()

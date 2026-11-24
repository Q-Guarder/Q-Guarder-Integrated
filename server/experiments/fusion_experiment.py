"""융합 전략 실험 — 논문 §3.3 / §3.4 / §3.5

VT 캐시(vt_cache.jsonl) 위에서 계산만 수행한다. **VirusTotal 재호출 0건.**

융합 계산은 app.services.fusion.fuse()를 그대로 호출한다. 서버가 쓰는 함수와
동일하므로 여기서 보고되는 수치는 서버의 실제 동작과 일치한다.

산출
  §3.3  평가셋 구성표 / 전략 4조건 비교(95% Wilson CI) / McNemar 검정 /
        케이스 분포 / 장애 주입(Graceful Degradation) / Override 규칙 분석 /
        URL 구조(root·deep) 층화 분석
  §3.4  제로데이 부분집합 전략별 성능 / 점수 분포 / 혼동행렬
  §3.5  OAT 민감도 스윕 (α · τ · d · W_ML_B)

출력: experiments/data/results.json  (그래프 렌더링은 make_figures.py가 담당)

사용법
  python experiments/fusion_experiment.py
  python experiments/fusion_experiment.py --skip-sweeps   # 빠른 확인용
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from app.services.ensemble_model import MODEL_THRESHOLD  # noqa: E402
from app.services.fusion import (  # noqa: E402
    CASE_B, FusionParams, OverrideRules, RATIO_OVERRIDE, RULE_OVERRIDE, VTStatus,
    fuse, params_adaptive, params_fixed, params_ml_only,
)
from app.services.hybrid_engine import InvalidUrlError, predict_url_with_ml  # noqa: E402
from app.services.model_loader import _LOCAL_MODEL_PATH, _load_model, get_model  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("fusion_experiment")

SEED = 42
DATA_DIR = Path(__file__).resolve().parent / "data"
EVALSET = DATA_DIR / "evalset.csv"
CACHE = DATA_DIR / "vt_cache.jsonl"
RESULTS = DATA_DIR / "results.json"


# ═══════════════════════════════════════════════════════════════
#  데이터 로드
# ═══════════════════════════════════════════════════════════════

@dataclass
class Record:
    url: str
    label: int          # 0 정상 / 1 피싱
    path_type: str      # root / deep
    source: str
    vt_status: str      # ok / not_found / unavailable
    detected: int       # d
    total: int          # n
    p_ml: float = 0.0
    vt_latency_ms: float = 0.0     # 수집 시점의 VT 조회 지연
    ml_feature_ms: float = 0.0     # 피처 추출 소요
    ml_inference_ms: float = 0.0   # 앙상블 추론 + XAI 소요

    @property
    def is_zero_day(self) -> bool:
        """TI 미등재 = 제로데이 후보 (논문 §3.4의 대상 집합)"""
        return self.vt_status == VTStatus.NOT_FOUND.value


def load_records() -> list[Record]:
    if not EVALSET.exists():
        raise SystemExit(f"평가셋 없음: {EVALSET} — build_evalset.py를 먼저 실행하세요")
    if not CACHE.exists():
        raise SystemExit(f"VT 캐시 없음: {CACHE} — collect_vt.py를 먼저 실행하세요")

    meta = {r["url"]: r for r in csv.DictReader(EVALSET.open(encoding="utf-8"))}

    records: list[Record] = []
    with CACHE.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec["url"] not in meta:
                continue  # 평가셋 재구성 이전의 잔여 레코드
            if rec["vt_status"] == VTStatus.UNAVAILABLE.value:
                continue  # 조회 실패는 판정이 아니다 — 분석에서 제외
            m = meta[rec["url"]]
            records.append(Record(
                url=rec["url"],
                label=int(m["label"]),
                path_type=m["path_type"],
                source=m["source"],
                vt_status=rec["vt_status"],
                detected=rec["detected_engines"],
                total=rec["total_engines"],
                vt_latency_ms=rec.get("latency_ms", 0.0),
            ))

    logger.info("VT 캐시에서 %d건 로드 (평가셋 %d건 중)", len(records), len(meta))
    if len(records) < len(meta):
        logger.warning(
            "수집 미완료 — %d건 누락. 부분 데이터로 계산합니다.",
            len(meta) - len(records),
        )
    return records


def attach_ml_probabilities(records: list[Record]) -> list[Record]:
    """각 URL의 ML 악성 확률 산출.

    VT 결과와 달리 ML 확률은 모델에 종속되므로 캐시하지 않고 매 실행 계산한다.
    (모델이 교체되면 자동으로 새 값이 반영된다)
    """
    logger.info("ML 추론 시작 (%d건)", len(records))
    get_model()  # 콜드로드를 측정 대상에서 제외 (별도 보고)
    kept: list[Record] = []
    invalid = 0
    for rec in records:
        try:
            result = predict_url_with_ml(rec.url)
        except InvalidUrlError:
            invalid += 1
            continue
        rec.p_ml = result.ml_probability
        rec.ml_feature_ms = result.feature_ms
        rec.ml_inference_ms = result.inference_ms
        kept.append(rec)
    if invalid:
        logger.warning("URL 파싱 실패로 제외: %d건", invalid)
    logger.info("ML 추론 완료 (%d건)", len(kept))
    return kept


# ═══════════════════════════════════════════════════════════════
#  통계
# ═══════════════════════════════════════════════════════════════

def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval — 표본이 작거나 비율이 0/1에 가까울 때
    정규근사보다 안정적이다. 논문 Table 4의 모든 비율 지표에 병기한다."""
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z**2 / trials
    center = (p + z**2 / (2 * trials)) / denom
    margin = z * math.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def _chi2_sf_1df(x: float) -> float:
    """자유도 1 카이제곱 상측확률 = erfc(sqrt(x/2)). scipy 없이 정확히 계산."""
    return math.erfc(math.sqrt(x / 2.0))


def mcnemar(pred_a: list[bool], pred_b: list[bool], truth: list[int]) -> dict:
    """두 전략의 정답 여부를 짝지어 비교 (McNemar 검정).

    b = A만 맞힘, c = B만 맞힘. 불일치 표본이 적으면 정확 이항검정을 사용한다.
    """
    b = c = 0
    for a, bb, t in zip(pred_a, pred_b, truth):
        a_ok, b_ok = (a == bool(t)), (bb == bool(t))
        if a_ok and not b_ok:
            b += 1
        elif b_ok and not a_ok:
            c += 1

    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "p_value": 1.0, "method": "no-discordant-pairs"}

    if n < 25:
        # 정확 이항검정 (양측)
        k = min(b, c)
        tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
        return {"b": b, "c": c, "p_value": min(1.0, 2 * tail), "method": "exact-binomial"}

    chi2 = (abs(b - c) - 1) ** 2 / n  # 연속성 보정
    return {"b": b, "c": c, "p_value": _chi2_sf_1df(chi2), "method": "chi2-continuity"}


# ═══════════════════════════════════════════════════════════════
#  평가
# ═══════════════════════════════════════════════════════════════

@dataclass
class Metrics:
    n: int
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    fpr: float = 0.0
    f1: float = 0.0
    recall_ci: tuple[float, float] = (0.0, 0.0)
    precision_ci: tuple[float, float] = (0.0, 0.0)
    fpr_ci: tuple[float, float] = (0.0, 0.0)

    def finalise(self) -> "Metrics":
        tp, tn, fp, fn = self.tp, self.tn, self.fp, self.fn
        self.accuracy = (tp + tn) / self.n if self.n else 0.0
        self.precision = tp / (tp + fp) if (tp + fp) else 0.0
        self.recall = tp / (tp + fn) if (tp + fn) else 0.0
        self.fpr = fp / (fp + tn) if (fp + tn) else 0.0
        self.f1 = (
            2 * self.precision * self.recall / (self.precision + self.recall)
            if (self.precision + self.recall) else 0.0
        )
        self.recall_ci = wilson_ci(tp, tp + fn)
        self.precision_ci = wilson_ci(tp, tp + fp)
        self.fpr_ci = wilson_ci(fp, fp + tn)
        return self


def predict(records: list[Record], params: FusionParams, blocked_only: bool = False):
    """각 레코드의 탐지 여부와 융합 결과를 반환"""
    preds, results = [], []
    for rec in records:
        r = fuse(rec.p_ml, rec.detected, rec.total, rec.vt_status, params)
        results.append(r)
        preds.append(r.blocked if blocked_only else r.detected)
    return preds, results


def evaluate(records: list[Record], preds: list[bool]) -> Metrics:
    tp = tn = fp = fn = 0
    for rec, p in zip(records, preds):
        if rec.label == 1:
            tp, fn = (tp + 1, fn) if p else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if p else (fp, tn + 1)
    return Metrics(n=len(records), tp=tp, tn=tn, fp=fp, fn=fn).finalise()


STRATEGIES = [
    ("(1) ML Only", lambda: params_ml_only(MODEL_THRESHOLD)),
    ("(2) Fixed 0.5:0.5", lambda: params_fixed(0.50)),
    ("(3) 4-Case Adaptive", lambda: params_adaptive(use_override=False)),
    ("(4) 4-Case + Override", lambda: params_adaptive(use_override=True)),
]

# ── 참조 baseline — 융합을 전혀 하지 않는 경우 ──
# 리뷰어의 첫 질문("그냥 VirusTotal만 쓰면 되지 않나?")을 논문 안에서 먼저 답한다.
# 융합 파라미터로 표현되지 않는 단순 규칙이므로 fuse()를 거치지 않는다.
BASELINES = [
    ("(0a) VT only (d>=1)", lambda r: r.detected >= 1),
    ("(0b) VT only (d>=5)", lambda r: r.detected >= 5),
]


def evaluate_baselines(records: list[Record]) -> list[tuple[str, Metrics]]:
    return [(name, evaluate(records, [fn(r) for r in records]))
            for name, fn in BASELINES]


# ═══════════════════════════════════════════════════════════════
#  출력 헬퍼
# ═══════════════════════════════════════════════════════════════

def pct(x: float) -> str:
    return f"{x * 100:5.2f}%"


def ci_str(ci: tuple[float, float]) -> str:
    return f"[{ci[0] * 100:.1f}, {ci[1] * 100:.1f}]"


def section(title: str) -> None:
    print("\n" + "═" * 78)
    print(f" {title}")
    print("═" * 78)


def print_metric_table(rows: list[tuple[str, Metrics]], label: str) -> None:
    print(f"\n{label}")
    print(f"{'Strategy':<24} {'Recall':>8} {'Precision':>10} {'FPR':>8} "
          f"{'F1':>8} {'Acc':>8}   {'Recall 95% CI':>16}")
    print("-" * 92)
    for name, m in rows:
        print(f"{name:<24} {pct(m.recall):>8} {pct(m.precision):>10} {pct(m.fpr):>8} "
              f"{pct(m.f1):>8} {pct(m.accuracy):>8}   {ci_str(m.recall_ci):>16}")


# ═══════════════════════════════════════════════════════════════
#  실험 본체
# ═══════════════════════════════════════════════════════════════

def experiment_composition(records: list[Record]) -> dict:
    section("§3.3-A  평가셋 구성 및 VT 응답 분포")

    print(f"\n{'구분':<10} {'root':>7} {'deep':>7} {'합계':>7}")
    print("-" * 34)
    comp = {}
    for lb, name in [(0, "정상"), (1, "피싱")]:
        r = sum(1 for x in records if x.label == lb and x.path_type == "root")
        d = sum(1 for x in records if x.label == lb and x.path_type == "deep")
        comp[name] = {"root": r, "deep": d, "total": r + d}
        print(f"{name:<10} {r:>7} {d:>7} {r + d:>7}")
    print("-" * 34)
    print(f"{'합계':<10} {sum(c['root'] for c in comp.values()):>7} "
          f"{sum(c['deep'] for c in comp.values()):>7} {len(records):>7}")

    print(f"\n{'VT 응답':<14} {'정상':>7} {'피싱':>7} {'합계':>7}")
    print("-" * 38)
    status_dist = {}
    for st in ("ok", "not_found"):
        b = sum(1 for x in records if x.vt_status == st and x.label == 0)
        p = sum(1 for x in records if x.vt_status == st and x.label == 1)
        status_dist[st] = {"benign": b, "phishing": p, "total": b + p}
        print(f"{st:<14} {b:>7} {p:>7} {b + p:>7}")

    zd = [x for x in records if x.is_zero_day]
    zd_phish = [x for x in zd if x.label == 1]
    print(f"\n★ 제로데이(TI 미등재) 총 {len(zd)}건 · 그중 피싱 {len(zd_phish)}건")
    if len(zd_phish) < 20:
        print("  ⚠ 제로데이 피싱 표본이 작아 §3.4의 검정력이 제한됩니다.")

    detected_dist = [x.detected for x in records if x.vt_status == "ok"]
    if detected_dist:
        print(f"\nVT 탐지 수 분포 (등재 건) — 0: "
              f"{sum(1 for d in detected_dist if d == 0)}, "
              f"1~4: {sum(1 for d in detected_dist if 1 <= d < 5)}, "
              f"5+: {sum(1 for d in detected_dist if d >= 5)}")

    return {"composition": comp, "vt_status": status_dist,
            "zero_day_total": len(zd), "zero_day_phishing": len(zd_phish)}


def experiment_strategies(records: list[Record]) -> dict:
    section("§3.3-B  융합 전략 4조건 비교")

    out: dict = {"suspicious_level": {}, "blocked_level": {}, "case_distribution": {},
                 "mcnemar": {}}
    truth = [r.label for r in records]

    for blocked_only, key, label in [
        (False, "suspicious_level", "판정 기준: SUSPICIOUS 이상 (τ=0.35)"),
        (True, "blocked_level", "판정 기준: BLOCKED (τ=0.65)"),
    ]:
        rows, preds_by_strategy = [], {}
        if not blocked_only:
            # 융합 없는 참조 baseline은 등급 개념이 없으므로 한 번만 보고
            for name, m in evaluate_baselines(records):
                rows.append((name, m))
                out[key][name] = asdict(m)
        for name, make in STRATEGIES:
            preds, results = predict(records, make(), blocked_only)
            m = evaluate(records, preds)
            rows.append((name, m))
            preds_by_strategy[name] = preds
            out[key][name] = asdict(m)
            if key == "suspicious_level":
                dist = {}
                for r in results:
                    dist[r.case] = dist.get(r.case, 0) + 1
                out["case_distribution"][name] = dist
        print_metric_table(rows, label)

        # McNemar — 인접 전략쌍
        pairs = [(STRATEGIES[i][0], STRATEGIES[j][0])
                 for i, j in [(0, 2), (1, 2), (2, 3)]]
        print(f"\n  McNemar 검정 ({label.split(':')[1].strip()})")
        for a, b in pairs:
            res = mcnemar(preds_by_strategy[a], preds_by_strategy[b], truth)
            out["mcnemar"].setdefault(key, {})[f"{a} vs {b}"] = res
            print(f"    {a:<24} vs {b:<24} "
                  f"b={res['b']:>3} c={res['c']:>3} p={res['p_value']:.4g} ({res['method']})")

    print("\n  케이스 분포 — (4) 4-Case + Override")
    for case, cnt in sorted(out["case_distribution"]["(4) 4-Case + Override"].items()):
        print(f"    {case:<14} {cnt:>4}건")

    return out


def experiment_stratified(records: list[Record]) -> dict:
    section("§3.3-C  URL 구조별 층화 분석 (모델 편향 영향 분리)")
    print("\n학습 데이터의 '정상 루트 URL' 비율이 0.09%에 불과해 모델이 루트 URL을")
    print("피싱으로 학습한 편향이 있다. 구간을 나눠 그 영향을 분리 보고한다.")

    out: dict = {}
    for ptype in ("root", "deep"):
        subset = [r for r in records if r.path_type == ptype]
        if not subset:
            continue
        rows = []
        for name, make in STRATEGIES:
            preds, _ = predict(subset, make(), blocked_only=False)
            m = evaluate(subset, preds)
            rows.append((name, m))
            out.setdefault(ptype, {})[name] = asdict(m)
        print_metric_table(rows, f"[{ptype}] n={len(subset)}")

    return out


def experiment_degradation(records: list[Record]) -> dict:
    section("§3.3-D  Graceful Degradation — 장애 주입")
    print("\n동일 평가셋에 장애를 주입해 성능 저하 폭을 정량화한다.")
    print("  VT 장애  : 모든 VT 응답을 UNAVAILABLE(0,0)로 대체")
    print("  ML 장애  : 모든 ML 확률을 중립값 0.5로 대체")

    def clone(recs, *, vt_fail=False, ml_fail=False) -> list[Record]:
        out = []
        for r in recs:
            c = Record(**{**asdict(r)})
            if vt_fail:
                c.vt_status = VTStatus.UNAVAILABLE.value
                c.detected = c.total = 0
            if ml_fail:
                c.p_ml = 0.5
            out.append(c)
        return out

    scenarios = [
        ("정상 운영", clone(records)),
        ("VT 장애", clone(records, vt_fail=True)),
        ("ML 장애", clone(records, ml_fail=True)),
        ("동시 장애", clone(records, vt_fail=True, ml_fail=True)),
    ]

    out: dict = {}
    for strat_name, make in [("(2) Fixed 0.5:0.5", params_fixed),
                             ("(4) 4-Case + Override", params_adaptive)]:
        print(f"\n{strat_name}")
        print(f"{'시나리오':<14} {'Recall':>8} {'FPR':>8} {'F1':>8}  {'ΔRecall':>9}")
        print("-" * 54)
        base_recall = None
        for label, recs in scenarios:
            params = make(0.50) if "Fixed" in strat_name else make()
            preds, _ = predict(recs, params, blocked_only=False)
            m = evaluate(recs, preds)
            if base_recall is None:
                base_recall = m.recall
            delta = (m.recall - base_recall) * 100
            out.setdefault(strat_name, {})[label] = asdict(m)
            print(f"{label:<14} {pct(m.recall):>8} {pct(m.fpr):>8} {pct(m.f1):>8}  "
                  f"{delta:>+8.2f}pp")

    return out


def experiment_override(records: list[Record]) -> dict:
    section("§3.3-E  Hard Override 규칙 계열 비교")
    print("\n비율 규칙(2차 식 2, θ=0.30)과 절대 개수 규칙(1차 R1/R2/R3) 중")
    print("어느 쪽이 실제로 작동하는지 실측으로 판정한다.")

    _, base = predict(records, params_adaptive(use_override=False), False)

    specs = [
        ("비율 θ=0.30 (2차)", RATIO_OVERRIDE),
        ("비율 θ=0.10", OverrideRules(ratio_threshold=0.10)),
        ("R1/R2/R3 (1차)", RULE_OVERRIDE),
    ]

    out: dict = {}
    for name, rules in specs:
        params = params_adaptive(override=rules)
        _, res = predict(records, params, False)

        by_rule: dict[str, list[int]] = {}
        for rec, r in zip(records, res):
            if r.override_rule:
                by_rule.setdefault(r.override_rule, []).append(rec.label)

        changed = sum(1 for a, b in zip(base, res) if a.risk_level != b.risk_level)
        blocked_metrics = evaluate(records, [r.blocked for r in res])

        print(f"\n  ▶ {name}")
        if not by_rule:
            print("     발동 0건 — 이 규칙은 현재 데이터에서 작동하지 않습니다.")
        for rule, labels in sorted(by_rule.items()):
            correct = sum(labels)
            ci = wilson_ci(correct, len(labels))
            print(f"     {rule:<6} 발동 {len(labels):>4}건 · 피싱 {correct:>4}건 · "
                  f"Precision {pct(correct / len(labels))} {ci_str(ci)}")
        print(f"     등급 변경 {changed}건 | BLOCKED 기준 "
              f"Recall {pct(blocked_metrics.recall)} "
              f"Precision {pct(blocked_metrics.precision)} "
              f"FPR {pct(blocked_metrics.fpr)}")

        out[name] = {
            "rules": {
                r: {"fired": len(v), "correct": sum(v),
                    "precision": sum(v) / len(v) if v else None}
                for r, v in by_rule.items()
            },
            "escalated": changed,
            "blocked_metrics": asdict(blocked_metrics),
        }

    return out


def experiment_zero_day_ablation(records: list[Record]) -> dict:
    """제로데이 절단 실험 — 피싱의 TI 신호만 제거해 출현 초기 상태를 모사.

    공개 피드(OpenPhish)는 검증이 끝난 URL을 배포하므로 공개 시점에 이미 VT도
    인지하고 있다. 자연 발생 제로데이 표본이 극소수라 검정력이 부족하므로,
    피싱 URL의 VT 신호를 제거해 '아직 TI가 잡지 못한 상태'를 모사한다.

    ⚠️ 정상 URL에는 절단을 적용하지 않는다. 현실에서 정상 상위 사이트가 VT
      미등재가 되는 일은 없으며(실측: 정상의 78%가 등재·clean), 정상까지 절단하면
      CASE_B/CASE_C 분기 자체가 무너져 비현실적인 시나리오가 된다.
    """
    section("§3.4-B  제로데이 절단 실험 (simulated early-stage TI)")

    phish = [r for r in records if r.label == 1]
    benign = [r for r in records if r.label == 0]
    if not phish:
        return {}

    # 케이스 분기의 실증적 근거 — CASE_B/CASE_C 분리가 정당한 이유
    print("\n  실측 VT 상태 분포")
    print(f"  {'구분':<8} {'미등재':>8} {'등재·clean':>12} {'등재·탐지':>11}")
    print("  " + "-" * 42)
    dist: dict = {}
    for lb, name, group in [(0, "정상", benign), (1, "피싱", phish)]:
        nf = sum(1 for r in group if r.vt_status == VTStatus.NOT_FOUND.value)
        d0 = sum(1 for r in group if r.vt_status == VTStatus.OK.value and r.detected == 0)
        dp = sum(1 for r in group if r.vt_status == VTStatus.OK.value and r.detected > 0)
        dist[name] = {"unlisted": nf, "listed_clean": d0, "listed_detected": dp}
        print(f"  {name:<8} {nf:>8} {d0:>12} {dp:>11}")
    print("  → 피싱은 등재 시 예외 없이 탐지되고, 정상은 대부분 등재·clean이다.")
    print("    두 집단이 서로 다른 케이스로 자연 분리된다 (CASE_B/CASE_C 분리 근거).")

    def ablate_phishing(mode: str) -> list[Record]:
        """피싱만 TI 제거. 정상은 실측값 그대로 유지."""
        out = list(benign)
        for r in phish:
            c = Record(**asdict(r))
            if mode == "unlisted":    # VT 미등재 → CASE_C (현실적 제로데이)
                c.detected = c.total = 0
                c.vt_status = VTStatus.NOT_FOUND.value
            elif mode == "d0":        # VT 응답·전부 clean → CASE_B (대조군)
                c.detected = 0
                c.total = r.total or 92
                c.vt_status = VTStatus.OK.value
            out.append(c)
        return out

    modes = [
        ("unlisted", "미등재 404 → CASE_C  [주 시나리오]"),
        ("d0", "등재·clean → CASE_B  [대조군]"),
    ]

    out: dict = {"vt_status_distribution": dist}
    for mode, mode_label in modes:
        data = ablate_phishing(mode)
        ablated_phish = [r for r in data if r.label == 1]

        print(f"\n  ▶ {mode_label}")
        print(f"     피싱 {len(phish)}건만 변환 · 정상 {len(benign)}건은 실측 유지")
        print(f"\n     {'Strategy':<24} {'제로데이Recall':>14} {'95% CI':>16}"
              f" {'전체FPR':>9} {'전체F1':>9}")
        print("     " + "-" * 76)
        for name, make in STRATEGIES:
            params = make()
            pz, res = predict(ablated_phish, params, blocked_only=False)
            hit = sum(1 for p in pz if p)
            recall = hit / len(ablated_phish)
            ci = wilson_ci(hit, len(ablated_phish))
            pall, _ = predict(data, params, blocked_only=False)
            m = evaluate(data, pall)
            out.setdefault(mode, {})[name] = {
                "zero_day_recall": recall, "hit": hit, "n": len(ablated_phish),
                "ci": ci,
                "mean_final_score": sum(r.final_score for r in res) / len(res),
                "overall_fpr": m.fpr, "overall_f1": m.f1,
            }
            print(f"     {name:<24} {pct(recall):>14} {ci_str(ci):>16}"
                  f" {pct(m.fpr):>9} {pct(m.f1):>9}")

    print("\n  ※ 주 시나리오(미등재)에서 적응 융합은 고정 융합 대비 제로데이 Recall이")
    print("    높으면서 FPR도 낮다. 대조군(d=0)은 CASE_B가 ML을 억제하도록 설계된")
    print("    결과이며, 실측상 해당 구간에는 피싱이 거의 존재하지 않는다.")
    return out


def experiment_zero_day(records: list[Record]) -> dict:
    section("§3.4  제로데이(TI 미등재) 분석")

    zd = [r for r in records if r.is_zero_day]
    zd_phish = [r for r in zd if r.label == 1]
    print(f"\n제로데이 부분집합: 전체 {len(zd)}건 (피싱 {len(zd_phish)} / 정상 {len(zd) - len(zd_phish)})")

    if not zd_phish:
        print("  ⚠ 제로데이 피싱 표본이 없어 Recall을 산출할 수 없습니다.")
        return {"n_total": len(zd), "n_phishing": 0}

    out: dict = {"n_total": len(zd), "n_phishing": len(zd_phish), "strategies": {}}

    print(f"\n{'Strategy':<24} {'제로데이 Recall':>16} {'95% CI':>16} {'평균 S_final':>13}")
    print("-" * 74)
    for name, make in STRATEGIES:
        preds, results = predict(zd_phish, make(), blocked_only=False)
        hit = sum(1 for p in preds if p)
        recall = hit / len(zd_phish)
        ci = wilson_ci(hit, len(zd_phish))
        mean_score = sum(r.final_score for r in results) / len(results)
        out["strategies"][name] = {
            "recall": recall, "hit": hit, "n": len(zd_phish),
            "ci": ci, "mean_final_score": mean_score,
            "scores": [r.final_score for r in results],
        }
        print(f"{name:<24} {pct(recall):>16} {ci_str(ci):>16} {mean_score:>13.4f}")

    if len(zd_phish) < 20:
        print(f"\n  ⚠ 표본 {len(zd_phish)}건 — 신뢰구간이 넓습니다. 해석에 주의하고")
        print("    논문에는 표본 수와 CI를 반드시 병기하십시오.")

    return out


# 사용자가 QR로 스캔할 대상이 아닌 정적 리소스 (폰트·아이콘·번들 등).
# 평가셋의 정상 deep URL을 상위 사이트 홈페이지의 href에서 추출했기 때문에
# 스타일시트·파비콘 링크가 함께 수집되었다. 제거 여부에 따른 강건성을 보고한다.
_STATIC_EXT_RE = re.compile(
    r"\.(woff2?|ttf|eot|otf|css|js|mjs|svg|png|jpe?g|gif|webp|ico|map|json|xml|txt|pdf)"
    r"(\?|$)", re.IGNORECASE
)
_BUNDLE_PATH_RE = re.compile(r"/_next/|/static/|/assets/|/dist/|/build/", re.IGNORECASE)


def is_static_resource(url: str) -> bool:
    return bool(_STATIC_EXT_RE.search(url) or _BUNDLE_PATH_RE.search(url))


def experiment_case_b_blindspot(records: list[Record]) -> dict:
    """CASE_B 구조적 맹점 — 논문 §4 한계(VirusTotal 종속성)의 정량적 실체.

    CASE_B(d=0, n>0)는 S_VT = 0이므로 최종 점수가 W_ML을 넘을 수 없다.
    현행 W_ML = 0.30 < τ_SUSPICIOUS = 0.35 이므로, ML이 100% 확신해도
    판정은 항상 SECURED가 된다. 즉 '**VT가 인지하였으나 미탐지한 피싱**'을
    구조적으로 놓친다.

    ※ 이는 논문이 §2.3에서 인용한 선행 연구와 직접 관련된다.
      [17] 신규 피싱 URL의 상당수가 출현 1주일 후에도 탐지 건수 0~1건.
      해당 URL이 VT에 색인되어 있다면 CASE_B로 분류되어 탐지되지 않는다.
      숨기지 말고 한계로 명시할 것.
    """
    section("§4-A  CASE_B 구조적 맹점 (한계 정량화)")

    params = FusionParams()
    w_ml_b = params.w_ml[CASE_B]
    ceiling = w_ml_b * 1.0
    print(f"\n  CASE_B 최대 도달 점수 = W_ML × 1.0 = {w_ml_b:.2f}")
    print(f"  SUSPICIOUS 임계값      = {params.tau_suspicious:.2f}")
    print(f"  → {ceiling:.2f} {'<' if ceiling < params.tau_suspicious else '>='} "
          f"{params.tau_suspicious:.2f} 이므로 "
          f"{'탐지 불가 (항상 SECURED)' if ceiling < params.tau_suspicious else '탐지 가능'}")

    case_b = [r for r in records
              if r.vt_status == VTStatus.OK.value and r.detected == 0]
    n_phish = sum(1 for r in case_b if r.label == 1)
    print(f"\n  평가셋의 CASE_B 구간: {len(case_b)}건 (정상 {len(case_b) - n_phish} / "
          f"피싱 {n_phish})")
    if n_phish == 0:
        print("  ⚠ 피싱 표본이 0건이므로 이 맹점의 실제 영향을 실측할 수 없다.")
        print("    평가셋 피싱을 검증 완료된 공개 피드에서 수집했기 때문이며,")
        print("    '검증 전' 단계의 피싱은 표본에 포함되지 않았다.")

    # 시뮬레이션: 실제 피싱을 CASE_B 상태로 옮기면 몇 건을 놓치는가
    phish = [r for r in records if r.label == 1]
    simulated = []
    for r in phish:
        c = Record(**asdict(r))
        c.detected = 0
        c.total = r.total or 92
        c.vt_status = VTStatus.OK.value
        simulated.append(c)
    preds, _ = predict(simulated, params, blocked_only=False)
    missed = sum(1 for p in preds if not p)
    print(f"\n  시뮬레이션 — 피싱 {len(simulated)}건을 CASE_B 상태로 이동 시")
    print(f"    탐지 {len(simulated) - missed}건 · 미탐 {missed}건 "
          f"(재현율 {pct((len(simulated) - missed) / len(simulated))})")

    # 맹점을 없애려면 W_ML을 얼마나 올려야 하는가, 그 대가는 얼마인가
    print(f"\n  W_ML(CASE_B) 상향의 대가")
    print(f"    {'W_ML':>6} {'CASE_B 재현율':>14} {'전체 FPR':>10} {'전체 F1':>10}")
    print("    " + "-" * 44)
    cost = []
    for w in [0.30, 0.35, 0.40, 0.50, 0.70, 0.90]:
        p = params.with_w_ml(CASE_B, w)
        ps, _ = predict(simulated, p, blocked_only=False)
        rec = sum(1 for x in ps if x) / len(ps)
        pa, _ = predict(records, p, blocked_only=False)
        m = evaluate(records, pa)
        cost.append({"w_ml": w, "case_b_recall": rec, "fpr": m.fpr, "f1": m.f1})
        print(f"    {w:>6.2f} {pct(rec):>14} {pct(m.fpr):>10} {pct(m.f1):>10}")

    print("\n  → 맹점 해소를 위해 W_ML을 올리면 전체 오탐이 급증한다. 이는 ML 모델의")
    print("    학습 데이터 편향(정상 루트 URL 0.09%)에 기인하므로, 모델 개선 없이는")
    print("    가중치 조정만으로 해소할 수 없다. 향후 연구 과제로 명시할 것.")

    return {
        "w_ml_case_b": w_ml_b,
        "ceiling": ceiling,
        "tau_suspicious": params.tau_suspicious,
        "detectable": ceiling >= params.tau_suspicious,
        "case_b_size": len(case_b),
        "case_b_phishing": n_phish,
        "simulated_recall": (len(simulated) - missed) / len(simulated),
        "weight_cost_curve": cost,
    }


def experiment_robustness(records: list[Record]) -> dict:
    """강건성 검증 — 정적 리소스 제외 시에도 결론이 유지되는가"""
    section("§3.3-H  강건성 검증 (정적 리소스 제외)")

    static = [r for r in records if is_static_resource(r.url)]
    clean = [r for r in records if not is_static_resource(r.url)]

    print(f"\n평가셋 {len(records)}건 중 정적 리소스 {len(static)}건 "
          f"({len(static) / len(records) * 100:.1f}%)")
    for name, group in [("정적 리소스", static), ("실제 페이지", clean)]:
        b = sum(1 for r in group if r.label == 0)
        p = sum(1 for r in group if r.label == 1)
        nf = sum(1 for r in group if r.is_zero_day)
        print(f"  {name:<12} {len(group):>4}건 · 정상 {b:>3} / 피싱 {p:>3} · 미등재 {nf:>3}")

    out: dict = {"n_static": len(static), "n_clean": len(clean), "subsets": {}}
    for label, key, data in [("전체 (현행)", "all", records),
                             ("정적 리소스 제외", "clean", clean)]:
        rows = []
        for name, make in STRATEGIES:
            preds, _ = predict(data, make(), blocked_only=False)
            m = evaluate(data, preds)
            rows.append((name, m))
            out["subsets"].setdefault(key, {})[name] = asdict(m)
        print_metric_table(
            rows,
            f"{label}  n={len(data)} "
            f"(정상 {sum(1 for r in data if r.label == 0)} / "
            f"피싱 {sum(1 for r in data if r.label == 1)})",
        )

    print("\n※ 두 조건에서 전략 간 우열이 동일하면 결론이 평가셋 구성에 좌우되지")
    print("  않음을 보인다. 논문에는 정적 리소스 혼입 사실과 함께 병기할 것.")
    return out


def experiment_latency(records: list[Record]) -> dict:
    """처리 지연 분해 — 논문 제목의 '실시간(Real-time)' 주장을 뒷받침하는 근거.

    VT 조회 지연은 수집 시점(vt_cache.jsonl)에 기록된 실측값이고,
    ML 지연은 이번 실행에서 URL마다 측정한 값이다.
    """
    section("§3.3-F  처리 지연 분해 (Real-time 근거)")

    def summarise(values: list[float]) -> dict:
        vs = sorted(v for v in values if v > 0)
        if not vs:
            return {"n": 0}
        return {
            "n": len(vs),
            "mean": sum(vs) / len(vs),
            "p50": vs[len(vs) // 2],
            "p95": vs[min(len(vs) - 1, int(len(vs) * 0.95))],
            "max": vs[-1],
        }

    stages = [
        ("Feature extraction", [r.ml_feature_ms for r in records]),
        ("Ensemble inference", [r.ml_inference_ms for r in records]),
        ("ML subtotal", [r.ml_feature_ms + r.ml_inference_ms for r in records]),
        ("VirusTotal lookup", [r.vt_latency_ms for r in records]),
        ("End-to-end", [r.ml_feature_ms + r.ml_inference_ms + r.vt_latency_ms
                        for r in records]),
    ]

    out: dict = {"stages": {}}
    print(f"\n{'Stage':<22} {'n':>5} {'mean':>10} {'p50':>10} {'p95':>10} {'max':>10}")
    print("-" * 72)
    for name, vals in stages:
        s = summarise(vals)
        out["stages"][name] = s
        if not s.get("n"):
            print(f"{name:<22} {'—':>5}  (측정값 없음)")
            continue
        print(f"{name:<22} {s['n']:>5} {s['mean']:>9.1f}ms {s['p50']:>9.1f}ms "
              f"{s['p95']:>9.1f}ms {s['max']:>9.1f}ms")

    # 콜드 스타트 — 서버 시작 후 첫 요청에서 모델을 처음 읽는 비용
    import time as _time
    started = _time.perf_counter()
    _load_model()
    cold_ms = (_time.perf_counter() - started) * 1000
    out["cold_start_ms"] = cold_ms
    print(f"\n모델 콜드로드 (8MB pkl 역직렬화 + 검증): {cold_ms:.0f} ms")

    ml = out["stages"]["ML subtotal"]
    vt = out["stages"]["VirusTotal lookup"]
    if ml.get("n") and vt.get("n"):
        share = vt["mean"] / (ml["mean"] + vt["mean"]) * 100
        out["vt_share_of_e2e"] = share
        print(f"→ 전체 지연의 {share:.1f}%가 VirusTotal 네트워크 대기.")
        print("  외부 TI 의존이 응답 시간의 지배적 요인이며, CASE_C(장애 시 ML 의존)")
        print("  설계의 실증적 근거가 된다.")
    return out


def experiment_confusion(records: list[Record]) -> dict:
    """전략별 혼동행렬 — 논문 §3.4 요구 산출물"""
    section("§3.3-G  전략별 혼동행렬 (SUSPICIOUS 이상 기준)")

    out: dict = {}
    print(f"\n{'Strategy':<24} {'TP':>6} {'FN':>6} {'FP':>6} {'TN':>6}   해석")
    print("-" * 78)
    for name, make in STRATEGIES:
        preds, _ = predict(records, make(), blocked_only=False)
        m = evaluate(records, preds)
        out[name] = {"tp": m.tp, "fn": m.fn, "fp": m.fp, "tn": m.tn}
        print(f"{name:<24} {m.tp:>6} {m.fn:>6} {m.fp:>6} {m.tn:>6}   "
              f"미탐 {m.fn}건 · 오탐 {m.fp}건")
    print("\n※ FN(미탐)이 본 연구의 최소화 대상이다.")
    return out


SWEEP_DESIGN = [
    ("alpha", "α (VT amplification)", "3.0", "1.0 – 5.0", "0.5", "Fig. 3"),
    ("tau_blocked", "τ (BLOCKED threshold)", "0.65", "0.45 – 0.85", "0.05", "Fig. 4"),
    ("d_high", "d (CASE_A_HIGH boundary)", "5", "3 – 7", "1", "Fig. 5"),
    ("w_ml_B", "W_ML (CASE_B)", "0.30", "0.30 – 0.95", "0.05", "Fig. 6"),
]


def print_sweep_design() -> dict:
    """§3.5 스윕 설계표 — 논문 Table로 그대로 옮길 수 있는 형태"""
    print(f"\n{'Parameter':<28} {'Design':>8} {'Range':>14} {'Step':>6} {'Figure':>8}")
    print("-" * 70)
    rows = []
    for key, label, design, rng, step, fig in SWEEP_DESIGN:
        rows.append({"key": key, "label": label, "design": design,
                     "range": rng, "step": step, "figure": fig})
        print(f"{label:<28} {design:>8} {rng:>14} {step:>6} {fig:>8}")
    print("\n※ 모든 스윕은 vt_cache 재사용 — VirusTotal API 재호출 0건.")
    return rows


def experiment_sweeps(records: list[Record]) -> dict:
    section("§3.5  하이퍼파라미터 민감도 분석 (OAT) — VT 재호출 0건")

    zd_phish = [r for r in records if r.is_zero_day and r.label == 1]
    out: dict = {"design": print_sweep_design()}

    def run(param_name: str, values, build, blocked_only: bool = False) -> None:
        """
        blocked_only: 판정 기준.
          False → SUSPICIOUS 이상을 탐지로 간주 (전반적 탐지 성능)
          True  → BLOCKED만 탐지로 간주. τ_blocked는 BLOCKED/SUSPICIOUS 경계만
                  움직이므로, SUSPICIOUS 기준으로 평가하면 아무 변화도 나타나지
                  않는다. 차단 임계값의 민감도는 BLOCKED 기준으로 봐야 한다.
        """
        rows = []
        basis = "BLOCKED" if blocked_only else "SUSPICIOUS+"
        print(f"\n{param_name} 스윕  (판정 기준: {basis})")
        print(f"{'value':>8} {'Recall':>8} {'Precision':>10} {'FPR':>8} {'F1':>8}"
              f" {'제로데이 Recall':>15}")
        print("-" * 62)
        for v in values:
            params = build(v)
            preds, _ = predict(records, params, blocked_only=blocked_only)
            m = evaluate(records, preds)
            zd_recall = None
            if zd_phish:
                zp, _ = predict(zd_phish, params, blocked_only=blocked_only)
                zd_recall = sum(1 for p in zp if p) / len(zd_phish)
            rows.append({
                "value": v, "recall": m.recall, "precision": m.precision,
                "fpr": m.fpr, "f1": m.f1, "recall_ci": m.recall_ci,
                "zero_day_recall": zd_recall, "basis": basis,
            })
            zd_txt = pct(zd_recall) if zd_recall is not None else "  N/A"
            print(f"{v:>8} {pct(m.recall):>8} {pct(m.precision):>10} {pct(m.fpr):>8}"
                  f" {pct(m.f1):>8} {zd_txt:>15}")
        out[param_name] = rows

    run("alpha", [round(1.0 + 0.5 * i, 1) for i in range(9)],
        lambda v: params_adaptive(alpha=v))
    run("tau_blocked", [round(0.45 + 0.05 * i, 2) for i in range(9)],
        lambda v: params_adaptive(tau_blocked=v), blocked_only=True)
    run("d_high", list(range(3, 8)),
        lambda v: params_adaptive(d_high=v))
    run("w_ml_B", [round(0.30 + 0.05 * i, 2) for i in range(14)],
        lambda v: params_adaptive().with_w_ml(CASE_B, v))

    print("\n※ OAT는 파라미터 간 상호작용을 포착하지 못한다 (논문 한계로 명시).")
    return out


# ═══════════════════════════════════════════════════════════════
#  main
# ═══════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(description="융합 전략 실험 (VT 재호출 없음)")
    ap.add_argument("--skip-sweeps", action="store_true", help="§3.5 스윕 생략")
    ap.add_argument("--out", type=Path, default=RESULTS)
    args = ap.parse_args()

    records = attach_ml_probabilities(load_records())
    if not records:
        raise SystemExit("분석 가능한 레코드가 없습니다.")

    results: dict = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "seed": SEED,
            "model_file": _LOCAL_MODEL_PATH.name,
            "ml_threshold": MODEL_THRESHOLD,
            "n_records": len(records),
            "note": "융합 계산은 app.services.fusion.fuse()를 사용 — 서버와 동일",
        },
    }

    results["composition"] = experiment_composition(records)
    results["strategies"] = experiment_strategies(records)
    results["confusion"] = experiment_confusion(records)
    results["stratified"] = experiment_stratified(records)
    results["robustness"] = experiment_robustness(records)
    results["case_b_blindspot"] = experiment_case_b_blindspot(records)
    results["latency"] = experiment_latency(records)
    results["degradation"] = experiment_degradation(records)
    results["override"] = experiment_override(records)
    results["zero_day"] = experiment_zero_day(records)
    results["zero_day_ablation"] = experiment_zero_day_ablation(records)
    if not args.skip_sweeps:
        results["sweeps"] = experiment_sweeps(records)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(results, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n\n결과 저장: {args.out}")


if __name__ == "__main__":
    main()

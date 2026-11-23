"""테스트 집합 파이프라인 한 번에 — 수집 → VT 조회 → (완료 확인) → 고정 파라미터 평가 → 독립 재검산

    python experiments/run_test_pipeline.py                 # 전체 (중단되면 같은 명령으로 이어받음)
    python experiments/run_test_pipeline.py --stage collect  # 수집·VT 조회까지만
    python experiments/run_test_pipeline.py --stage evaluate # 평가만 (VT 조회가 끝나 있어야 함)

안전장치
  - 테스트 URL 중 VT 조회가 안 끝난 건이 하나라도 있으면 평가를 하지 않는다 (불완전한 테스트 집합으로 수치가 나가는 것을 막음).
  - 파라미터는 fixed_params.json 그대로 쓴다. 이 스크립트는 어떤 선정 로직도 돌리지 않는다.
  - 모든 출력은 experiments/data/revision/test_pipeline.log 에 누적 기록된다.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments"
DATA = EXP / "data"
EVALSET = DATA / "evalset.csv"
CACHE = DATA / "vt_cache.jsonl"
LOG = DATA / "revision" / "test_pipeline.log"
STATUS = DATA / "revision" / "test_pipeline_status.json"
TEST_TARGET = 500


def log(msg: str) -> None:
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {msg}"
    print(line, flush=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def run(args: list[str]) -> int:
    log("$ " + " ".join(args))
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    with LOG.open("a", encoding="utf-8") as fh:
        proc = subprocess.Popen([sys.executable, *args], cwd=str(ROOT), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            fh.write(line)
        proc.wait()
    log(f"→ 종료 코드 {proc.returncode}")
    return proc.returncode


def test_rows() -> list[dict]:
    if not EVALSET.exists():
        return []
    with EVALSET.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if rows and "split" in rows[0]:
        return [r for r in rows if r.get("split") == "test"]
    return []


def cache_status() -> dict:
    cached: dict[str, str] = {}
    if CACHE.exists():
        for line in CACHE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                cached[rec["url"]] = rec.get("vt_status", "")
            except json.JSONDecodeError:
                continue
    rows = test_rows()
    done = [r for r in rows if cached.get(r["url"]) in ("ok", "not_found")]
    missing = [r["url"] for r in rows if r["url"] not in cached]
    bad = [r["url"] for r in rows if r["url"] in cached and cached[r["url"]] not in ("ok", "not_found")]
    by = {"ok": 0, "not_found": 0}
    for r in done:
        by[cached[r["url"]]] += 1
    st = {"checked_at": datetime.now().isoformat(timespec="seconds"), "test_rows": len(rows), "vt_done": len(done),
          "vt_missing": len(missing), "vt_bad_status": len(bad), "by_status": by,
          "test_benign": sum(1 for r in rows if str(r["label"]) == "0"), "test_phishing": sum(1 for r in rows if str(r["label"]) == "1"),
          "complete": bool(rows) and not missing and not bad}
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    return st


def stage_collect() -> bool:
    rows = test_rows()
    if len(rows) < TEST_TARGET:
        log(f"테스트 집합 {len(rows)}건 < {TEST_TARGET} → prepare_testset.py 실행 (새 피드 수집·중복 제거·split 열)")
        if run(["experiments/prepare_testset.py", "--total", str(TEST_TARGET)]) != 0:
            log("prepare_testset.py 실패 — 네트워크(OpenPhish·Tranco·홈페이지 크롤)를 확인하고 같은 명령으로 다시 실행")
            return False
        rows = test_rows()
        log(f"테스트 집합 {len(rows)}건 준비됨")
    else:
        log(f"테스트 집합 {len(rows)}건 이미 준비됨 — 수집 생략")
    st = cache_status()
    if st["complete"]:
        log(f"VT 조회 이미 완료 ({st['vt_done']}/{st['test_rows']})")
        return True
    log(f"VT 조회 시작 — 남은 {st['vt_missing']}건 (무료 API 15.5초 간격, 약 {st['vt_missing'] * 15.5 / 60:.0f}분). POST 없음, GET 만.")
    rc = run(["experiments/collect_vt.py"])
    run(["experiments/collect_vt.py", "--stats"])
    st = cache_status()
    if not st["complete"]:
        log(f"VT 조회 미완료 — 남은 {st['vt_missing']}건 (상태 이상 {st['vt_bad_status']}건). 429(일일 한도)면 다음 날 같은 명령으로 이어받기. 평가는 하지 않음.")
        return False
    log(f"VT 조회 완료 — ok {st['by_status']['ok']} / not_found {st['by_status']['not_found']} (종료 코드 {rc})")
    return True


def stage_evaluate() -> bool:
    st = cache_status()
    if not st["complete"]:
        log(f"평가 중단 — 테스트 {st['test_rows']}건 중 VT 미조회 {st['vt_missing']}건, 상태 이상 {st['vt_bad_status']}건. 먼저 --stage collect.")
        return False
    fixed = DATA / "revision" / "fixed_params.json"
    if not fixed.exists():
        log("fixed_params.json 없음 — 패키지의 experiments/data/revision/ 이 들어왔는지 확인")
        return False
    p = json.loads(fixed.read_text(encoding="utf-8"))
    log(f"고정 파라미터 (검증 집합에서 {p.get('selected_at')} 확정): {p['params']}")
    if run(["experiments/revision_experiment.py", "--evaluate"]) != 0:
        return False
    run(["experiments/recheck_from_csv.py", "--split", "test"])
    out = DATA / "revision"
    log("산출물: " + ", ".join(str(out / f) for f in ("tables_test.md", "per_url_test.csv", "zero_day_test.csv", "revision_results_test.json")))
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["collect", "evaluate", "all"], default="all")
    args = ap.parse_args()
    log(f"==== run_test_pipeline --stage {args.stage} (python {sys.version.split()[0]}, cwd {ROOT})")
    ok = True
    if args.stage in ("collect", "all"):
        ok = stage_collect()
    if ok and args.stage in ("evaluate", "all"):
        ok = stage_evaluate()
    log("==== 완료" if ok else "==== 미완료 — 위 메시지 확인 후 같은 명령으로 재실행")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

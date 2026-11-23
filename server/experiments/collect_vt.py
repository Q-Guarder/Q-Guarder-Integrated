"""VirusTotal 평판 수집기 — 평가셋 500건의 (d, n, status) 캐시 구축

설계 원칙
  1. GET 전용. POST(스캔 제출)를 절대 하지 않는다.
     제출하면 해당 URL이 VT에 등재되어 '미등재(제로데이)' 상태가 소멸한다.
  2. 404(미등재) / 429(쿼터) / timeout(장애) / 200(정상)을 구분해 기록한다.
  3. 조회 실패는 '결과'가 아니라 '아직 못 받음'이다. 캐시에 쓰지 않고 재시도하며,
     쿼터 소진이면 그 지점에서 멈춘다. 다음 실행 시 이어받는다.
  4. ML 확률은 여기서 계산하지 않는다. VT 결과는 URL만의 함수라 모델이 바뀌어도
     영구 유효하지만, ML 확률은 모델에 종속되므로 실험 시점에 계산한다.

무료 Public API 기준 (4 req/min · 500 req/day)
  500건 × GET 1회 = 500 요청 ≈ 130분. 하루 한도에 딱 맞으므로 여유를 두고 실행할 것.

사용법
  python experiments/collect_vt.py              # 수집 시작 / 이어받기
  python experiments/collect_vt.py --stats      # 진행 상황만 확인
  python experiments/collect_vt.py --limit 100  # 이번 실행에서 100건만
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
# app.core.config는 CWD 기준으로 .env를 읽으므로 프로젝트 루트로 이동
os.chdir(PROJECT_ROOT)

from app.core.config import get_settings  # noqa: E402
from app.services.hybrid_engine import (  # noqa: E402
    VTStatus, scan_url_with_virustotal,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("collect_vt")

DATA_DIR = Path(__file__).resolve().parent / "data"
EVALSET = DATA_DIR / "evalset.csv"
CACHE = DATA_DIR / "vt_cache.jsonl"

# 무료 티어 4 req/min → 15초 간격 + 안전 마진
DEFAULT_INTERVAL = 15.5
DEFAULT_MAX_RETRIES = 3


# ═══════════════════════════════════════════════════════════════
#  캐시 입출력 (JSONL — 한 건씩 append하여 중단에 안전)
# ═══════════════════════════════════════════════════════════════

def load_cache() -> dict[str, dict]:
    if not CACHE.exists():
        return {}
    cached: dict[str, dict] = {}
    with CACHE.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("캐시 손상 라인 무시: %.80s", line)
                continue
            cached[rec["url"]] = rec
    return cached


def append_cache(record: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    with CACHE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_evalset() -> list[dict]:
    if not EVALSET.exists():
        raise SystemExit(
            f"평가셋이 없습니다: {EVALSET}\n"
            f"먼저 실행하세요 → python experiments/build_evalset.py"
        )
    with EVALSET.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ═══════════════════════════════════════════════════════════════
#  진행 상황 보고
# ═══════════════════════════════════════════════════════════════

def print_stats(rows: list[dict], cached: dict[str, dict]) -> None:
    done = [c for c in cached.values()]
    print(f"\n평가셋 {len(rows)}건 중 수집 완료 {len(done)}건 "
          f"({len(done) / len(rows) * 100:.1f}%)\n")

    if not done:
        print("아직 수집된 건이 없습니다.")
        return

    by_status: dict[str, int] = {}
    for rec in done:
        by_status[rec["vt_status"]] = by_status.get(rec["vt_status"], 0) + 1

    print(f"{'VT 응답 상태':<16} {'건수':>7}   의미")
    print("-" * 62)
    meaning = {
        "ok": "등재됨 · 분석 결과 존재",
        "not_found": "미등재 → 제로데이 후보",
        "unavailable": "조회 실패 (캐시에 기록되면 안 됨)",
    }
    for st, cnt in sorted(by_status.items()):
        print(f"{st:<16} {cnt:>7}   {meaning.get(st, '')}")

    # 라벨 × 상태 교차
    label_of = {r["url"]: int(r["label"]) for r in rows}
    ptype_of = {r["url"]: r["path_type"] for r in rows}

    print(f"\n{'구분':<12} {'ok':>6} {'not_found':>11} {'합계':>7}")
    print("-" * 40)
    for lb, name in [(0, "정상"), (1, "피싱")]:
        sub = [r for r in done if label_of.get(r["url"]) == lb]
        ok = sum(1 for r in sub if r["vt_status"] == "ok")
        nf = sum(1 for r in sub if r["vt_status"] == "not_found")
        print(f"{name:<12} {ok:>6} {nf:>11} {len(sub):>7}")

    nf_all = [r for r in done if r["vt_status"] == "not_found"]
    print(f"\n★ 제로데이 후보(미등재): {len(nf_all)}건")
    if nf_all:
        nf_phish = sum(1 for r in nf_all if label_of.get(r["url"]) == 1)
        nf_root = sum(1 for r in nf_all if ptype_of.get(r["url"]) == "root")
        print(f"   그중 피싱 라벨: {nf_phish}건 / 루트 URL: {nf_root}건")

    lat = [r["latency_ms"] for r in done if r.get("latency_ms")]
    if lat:
        lat.sort()
        print(f"\nVT 조회 지연 — 평균 {sum(lat)/len(lat):.0f}ms · "
              f"p50 {lat[len(lat)//2]:.0f}ms · p95 {lat[int(len(lat)*0.95)]:.0f}ms")

    detected = [r for r in done if r["vt_status"] == "ok" and r["detected_engines"] > 0]
    print(f"\nVT 탐지 있음(d>0): {len(detected)}건")


# ═══════════════════════════════════════════════════════════════
#  사전 점검 — 식별자 오류로 대량 오수집하는 사고 방지
# ═══════════════════════════════════════════════════════════════

# VT가 반드시 알고 있어야 하는 URL. 루트 URL을 포함하는 것이 핵심 —
# URL 식별자를 SHA-256(원문)으로 만들면 루트 URL만 404가 되어
# 전체의 절반이 '제로데이'로 오분류된 채 수집이 끝나버린다.
_PREFLIGHT_URL = "https://example.com"


async def preflight() -> None:
    logger.info("사전 점검: 루트 URL 조회가 정상 동작하는지 확인 (%s)", _PREFLIGHT_URL)
    vt = await scan_url_with_virustotal(_PREFLIGHT_URL)

    if vt.status is VTStatus.UNAVAILABLE:
        raise SystemExit(
            f"사전 점검 실패 — VT 조회 불가 (http={vt.http_status}). "
            f"API 키 또는 쿼터를 확인하세요."
        )
    if vt.status is VTStatus.NOT_FOUND:
        raise SystemExit(
            f"사전 점검 실패 — {_PREFLIGHT_URL} 가 '미등재'로 조회되었습니다.\n"
            f"VT가 모를 리 없는 URL이므로 URL 식별자 생성이 잘못되었을 가능성이 큽니다.\n"
            f"hybrid_engine.vt_url_id()를 확인하세요 (base64url이어야 하며 SHA-256은 오답)."
        )
    logger.info("사전 점검 통과 — d=%d n=%d", vt.detected_engines, vt.total_engines)


# ═══════════════════════════════════════════════════════════════
#  수집 루프
# ═══════════════════════════════════════════════════════════════

async def collect(
    rows: list[dict], cached: dict[str, dict],
    interval: float, limit: int | None, max_retries: int,
) -> None:
    pending = [r for r in rows if r["url"] not in cached]
    if not pending:
        logger.info("모든 URL이 이미 수집되었습니다.")
        return

    if limit is not None:
        pending = pending[:limit]

    total = len(pending)
    eta_min = total * interval / 60
    logger.info("수집 대상 %d건 · 요청 간격 %.1fs · 예상 소요 %.0f분", total, interval, eta_min)

    collected = 0
    last_request_at = 0.0

    for idx, row in enumerate(pending, 1):
        url = row["url"]

        # ── rate limit: 최소 간격 유지 ──
        wait = interval - (time.monotonic() - last_request_at)
        if wait > 0 and last_request_at > 0:
            await asyncio.sleep(wait)

        result = None
        for attempt in range(1, max_retries + 1):
            last_request_at = time.monotonic()
            # submit_unknown=False (기본) — POST 금지
            vt = await scan_url_with_virustotal(url)

            if vt.status is not VTStatus.UNAVAILABLE:
                result = vt
                break

            if vt.http_status == 429:
                backoff = interval * (2 ** attempt)
                logger.warning(
                    "[%d/%d] 429 쿼터 초과 — %.0fs 후 재시도 (%d/%d)",
                    idx, total, backoff, attempt, max_retries,
                )
                await asyncio.sleep(backoff)
            else:
                logger.warning(
                    "[%d/%d] 조회 실패(http=%s) — 재시도 %d/%d",
                    idx, total, vt.http_status, attempt, max_retries,
                )
                await asyncio.sleep(interval)

        if result is None:
            logger.error(
                "쿼터 소진 또는 지속적 조회 실패로 중단합니다. "
                "이번 실행 수집: %d건 · 남은 대상: %d건. "
                "한도가 회복되면 같은 명령으로 이어받으세요.",
                collected, total - idx + 1,
            )
            break

        record = {
            "url": url,
            "label": int(row["label"]),
            "source": row["source"],
            "path_type": row["path_type"],
            "vt_status": result.status.value,
            "http_status": result.http_status,
            "detected_engines": result.detected_engines,
            "total_engines": result.total_engines,
            "latency_ms": result.latency_ms,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
        append_cache(record)
        cached[url] = record
        collected += 1

        if idx % 10 == 0 or idx == total:
            remaining_min = (total - idx) * interval / 60
            logger.info(
                "진행 %d/%d (%.1f%%) · 남은 예상 %.0f분",
                idx, total, idx / total * 100, remaining_min,
            )

    logger.info("이번 실행 수집 완료: %d건 (누적 %d건)", collected, len(cached))


def main() -> None:
    ap = argparse.ArgumentParser(description="VirusTotal 평판 수집 (GET 전용)")
    ap.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                    help="요청 간 최소 간격(초). 무료 티어 4req/min 기준 기본 15.5")
    ap.add_argument("--limit", type=int, default=None,
                    help="이번 실행에서 수집할 최대 건수")
    ap.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    ap.add_argument("--stats", action="store_true", help="진행 상황만 출력하고 종료")
    args = ap.parse_args()

    rows = load_evalset()
    cached = load_cache()

    if args.stats:
        print_stats(rows, cached)
        return

    if not get_settings().VIRUSTOTAL_API_KEY:
        raise SystemExit(
            "VIRUSTOTAL_API_KEY가 설정되지 않았습니다. .env를 확인하세요."
        )

    async def run() -> None:
        await preflight()
        await asyncio.sleep(args.interval)
        await collect(rows, cached, args.interval, args.limit, args.max_retries)

    asyncio.run(run())
    print_stats(rows, load_cache())


if __name__ == "__main__":
    main()

"""독립 테스트 집합 준비 — 심사위원 2-2 / 3-2 (데이터 독립성) 대응

기존 500건(evalset.csv)은 파라미터 선정에 쓰였으므로 **검증 집합(validation)** 으로 선언하고,
최종 성능 보고용 **테스트 집합(test)** 을 새로 수집한다. build_evalset.py 의 수집 절차를 그대로
재사용하되 다음을 추가한다.

  1. 원본 피드를 새로 내려받는다 (data/raw_test/ — 8월 캐시 data/raw/ 를 쓰지 않음)
  2. 검증 집합과의 중복을 제거한다
       - 모든 URL: 정규화 URL 일치 제거
       - 정상: 등록가능 도메인(base domain) 수준에서도 제거 (Tranco 상위 도메인은 거의 같으므로 필수)
       - 피싱: 호스트명(hostname) 일치 제거 (공유 호스팅 base domain 은 제외하지 않음 — 과도 제거 방지)
  3. 오프라인 학습·테스트 URL 목록(data/raw/offline_urls.csv, 열 이름 url)이 있으면 정규화 URL 일치 제거
  4. 다른 seed 를 사용한다
  5. evalset.csv 를 `split` 열이 있는 통합 파일로 다시 쓴다
       - 기존 500건 → split=validation (백업: evalset_validation_only.csv)
       - 신규 → split=test
     collect_vt.py 는 evalset.csv 를 읽고 vt_cache.jsonl 에 없는 URL 만 조회하므로 신규 test 행만 VT 조회된다.

사용 순서 (프로젝트 루트에서)
  python experiments/prepare_testset.py --total 500          # 수집 + 중복 제거 + split 통합 (네트워크 필요)
  python experiments/collect_vt.py                            # VT 조회 — 무료 API 500건/일, 약 2시간 10분
  python experiments/collect_vt.py --stats                    # 진행 확인
  python experiments/revision_experiment.py --evaluate       # fixed_params.json 으로 test split 평가 (선정 없음)

중단 없이 재실행해도 안전하다: 이미 split 열이 있으면 기존 test 행을 보존하고 부족분만 보충한다.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import random
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_evalset as be  # noqa: E402
from app.services.url_features import preprocess_url  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent / "data"
EVALSET = DATA_DIR / "evalset.csv"
BACKUP = DATA_DIR / "evalset_validation_only.csv"
OFFLINE_URLS = DATA_DIR / "raw" / "offline_urls.csv"
RAW_TEST = DATA_DIR / "raw_test"
TEST_SEED = 20261018

logger = be.logger


def hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def load_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_offline_keys() -> set[str]:
    if not OFFLINE_URLS.exists():
        logger.warning("오프라인 URL 목록 없음 (%s) — 오프라인 데이터와의 중복 제거는 생략됨. "
                       "Drive Q-Guard/dataset/preprocessed_dataset.csv 를 이 경로에 두면 자동 적용", OFFLINE_URLS)
        return set()
    keys: set[str] = set()
    with OFFLINE_URLS.open(encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        col = "url" if "url" in (reader.fieldnames or []) else (reader.fieldnames or ["url"])[0]
        for row in reader:
            u = (row.get(col) or "").strip()
            if u:
                keys.add(preprocess_url(u) or u)
    logger.info("오프라인 URL %d건 로드 — 중복 제거에 사용", len(keys))
    return keys


def build_test(total: int, benign_ratio: float, root_ratio: float, existing: list[dict],
               offline_keys: set[str], seed: int) -> list[dict]:
    """build_evalset.build() 와 같은 절차 + 제외 규칙"""
    be.RAW_DIR = RAW_TEST                      # 캐시를 새 폴더로 → 피드 재다운로드
    RAW_TEST.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    excl_keys = {preprocess_url(r["url"]) or r["url"] for r in existing} | offline_keys
    excl_benign_domains = {be.base_domain(be.registrable_host(r["url"])) for r in existing if r["label"] == "0"}
    excl_phish_hosts = {hostname(r["url"]) for r in existing if r["label"] == "1"}

    n_benign = int(total * benign_ratio)
    n_phish = total - n_benign

    # ── 피싱 ──
    phish_pool = [(u, pt) for u, pt in be._dedupe_valid(be.fetch_openphish())
                  if u not in excl_keys and hostname(u) not in excl_phish_hosts]
    logger.info("피싱 풀 %d건 (검증 집합·오프라인 중복 제외 후)", len(phish_pool))
    phish = be._take_stratified(phish_pool, int(n_phish * root_ratio), n_phish - int(n_phish * root_ratio), rng)

    # ── 정상 ──
    phish_bases = {be.base_domain(be.registrable_host(u)) for u, _ in phish_pool}
    domains: list[str] = []
    for d in be.fetch_tranco(limit=6000):
        if be._SKIP_DOMAIN_PATTERN.search(d + "."):
            continue
        if d in be._SHARED_HOSTING or be.base_domain(d) in be._SHARED_HOSTING:
            continue
        if be.base_domain(d) in phish_bases or be.base_domain(d) in excl_benign_domains:
            continue
        domains.append(d)
    logger.info("정상 후보 도메인 %d개 (인프라·공유호스팅·라벨충돌·검증집합 도메인 제외 후)", len(domains))

    n_benign_root = int(n_benign * root_ratio)
    n_benign_deep = n_benign - n_benign_root
    live_roots = asyncio.run(be.filter_live_roots(domains, target=n_benign_root))
    benign_root = [(u, pt) for u, pt in be._dedupe_valid([f"https://{d}" for d in live_roots]) if u not in excl_keys][:n_benign_root]
    deep_raw = asyncio.run(be.collect_benign_deep(domains, target=n_benign_deep * 2))
    benign_deep = [(u, pt) for u, pt in be._dedupe_valid(deep_raw) if pt == "deep" and u not in excl_keys][:n_benign_deep]

    rows: list[dict] = []
    for url, ptype in benign_root:
        rows.append({"url": url, "label": 0, "source": "tranco", "path_type": ptype, "split": "test"})
    for url, ptype in benign_deep:
        rows.append({"url": url, "label": 0, "source": "tranco-crawl", "path_type": ptype, "split": "test"})
    for url, ptype in phish:
        rows.append({"url": url, "label": 1, "source": "openphish", "path_type": ptype, "split": "test"})
    rng.shuffle(rows)
    return rows


def report(rows: list[dict], title: str) -> None:
    print(f"\n{title}")
    print(f"{'구분':<10} {'root':>7} {'deep':>7} {'합계':>7}")
    for lb, name in [("0", "정상"), ("1", "피싱")]:
        r = sum(1 for x in rows if str(x["label"]) == lb and x["path_type"] == "root")
        d = sum(1 for x in rows if str(x["label"]) == lb and x["path_type"] == "deep")
        print(f"{name:<10} {r:>7} {d:>7} {r + d:>7}")
    print(f"{'합계':<10} {'':>7} {'':>7} {len(rows):>7}")


def main() -> None:
    ap = argparse.ArgumentParser(description="독립 테스트 집합 준비")
    ap.add_argument("--total", type=int, default=500)
    ap.add_argument("--benign-ratio", type=float, default=0.5)
    ap.add_argument("--root-ratio", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=TEST_SEED)
    args = ap.parse_args()

    rows = load_rows(EVALSET)
    has_split = "split" in rows[0]
    validation = [dict(r, split="validation") for r in rows if not has_split or r.get("split") in ("", "validation")]
    existing_test = [r for r in rows if has_split and r.get("split") == "test"]
    if not BACKUP.exists():
        shutil.copy(EVALSET, BACKUP)
        logger.info("검증 집합 백업: %s", BACKUP)

    offline_keys = load_offline_keys()
    need = args.total - len(existing_test)
    if need <= 0:
        logger.info("테스트 집합 %d건 이미 존재 — 수집 생략", len(existing_test))
        new_rows: list[dict] = []
    else:
        new_rows = build_test(need, args.benign_ratio, args.root_ratio, validation + existing_test, offline_keys, args.seed)

    test = existing_test + new_rows
    merged = validation + test
    with EVALSET.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["url", "label", "source", "path_type", "split"])
        w.writeheader()
        w.writerows(merged)

    report(validation, "검증 집합 (split=validation)")
    report(test, "테스트 집합 (split=test)")
    # 중복 검사 결과 (답변서 기재용)
    vkeys = {preprocess_url(r["url"]) or r["url"] for r in validation}
    tkeys = {preprocess_url(r["url"]) or r["url"] for r in test}
    vdom = {be.base_domain(be.registrable_host(r["url"])) for r in validation if str(r["label"]) == "0"}
    tdom = {be.base_domain(be.registrable_host(r["url"])) for r in test if str(r["label"]) == "0"}
    print(f"\n검증↔테스트 URL 중복: {len(vkeys & tkeys)}건 · 정상 등록가능 도메인 중복: {len(vdom & tdom)}건"
          f" · 오프라인 URL 중복: {len(tkeys & offline_keys) if offline_keys else '검사 안 함(목록 없음)'}")
    print(f"\n저장: {EVALSET} ({len(merged)}건). 다음: python experiments/collect_vt.py  (신규 {len(new_rows)}건만 VT 조회)")


if __name__ == "__main__":
    main()

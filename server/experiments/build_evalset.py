"""평가셋 500건 구성 — 융합 전략 평가용 (논문 §3.3/§3.4)

학습/테스트셋과 분리된 별도 평가셋을 구성한다. 학습 데이터는 URL 문자열이
보존되어 있지 않아 VirusTotal 조회가 불가능하므로, 공개 피드에서 새로 수집한다.

데이터 출처
  - 피싱 : OpenPhish 공개 피드 (최신 등록분) — 제로데이 후보 확보 목적
  - 정상 : Tranco Top-1M 도메인 목록 (루트 URL) + 해당 도메인 홈페이지에서
           추출한 동일 출처 내부 링크 (deep URL)

★ 층화(stratification) 설계 근거
  학습 데이터는 '정상 중 루트 URL' 비율이 0.09%(11,992건 중 11건)에 불과해,
  모델이 루트 URL을 사실상 피싱으로 학습한 편향이 확인되었다.
  QR 코드 실환경은 루트 URL 비중이 높으므로(OpenPhish 피드 기준 61.7%),
  평가셋은 루트/deep을 균형 배치하고 결과를 구간별로 분리 보고한다.

출력: experiments/data/evalset.csv  (url, label, source, path_type)
      label 규약은 학습셋과 동일 — 0 = 정상, 1 = 피싱
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import logging
import random
import re
import sys
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.url_features import preprocess_url  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_evalset")

DATA_DIR = Path(__file__).resolve().parent / "data"
RAW_DIR = DATA_DIR / "raw"

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_TOP1M = "https://tranco-list.eu/top-1m.csv.zip"

SEED = 42

# 홈페이지 크롤링 대상에서 제외 — 브라우징용이 아닌 인프라/API/CDN 도메인
_SKIP_DOMAIN_PATTERN = re.compile(
    r"(^|\.)(googleapis|gstatic|akamai|akamaized|cloudfront|fbcdn|ytimg|doubleclick|"
    r"googlesyndication|googletagmanager|google-analytics|cloudflare|jsdelivr|unpkg|"
    r"gvt1|gvt2|windowsupdate|azureedge|licdn|cdninstagram|twimg|googleusercontent|"
    r"appsflyersdk|registrar-servers|rootcanal|in-addr|amazonaws|azure-dns)\.",
    re.IGNORECASE,
)

# 공유 호스팅(서브도메인을 누구나 생성) — 루트는 정상이지만 하위는 피싱에 광범위하게
# 악용된다. 같은 등록가능 도메인이 양쪽 라벨에 걸치면 분석이 흐려지므로 정상 풀에서 제외.
_SHARED_HOSTING = frozenset([
    "workers.dev", "pages.dev", "vercel.app", "netlify.app", "blogspot.com",
    "github.io", "herokuapp.com", "firebaseapp.com", "web.app", "glitch.me",
    "repl.co", "replit.app", "onrender.com", "surge.sh", "weebly.com",
    "wixsite.com", "000webhostapp.com", "r2.dev", "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "amazonaws.com", "azurewebsites.net",
    "cloudfunctions.net", "appspot.com", "framer.app", "framer.website",
    "typedream.app", "webflow.io", "square.site", "godaddysites.com",
    "webcindario.com", "notion.site", "gitbook.io", "bubbleapps.io",
])

_HREF_RE = re.compile(rb"""href\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)

USER_AGENT = (
    "Mozilla/5.0 (compatible; Q-Guarder-Research/1.0; "
    "academic phishing-detection study)"
)


# ═══════════════════════════════════════════════════════════════
#  공통 유틸
# ═══════════════════════════════════════════════════════════════

def classify_path_type(url: str) -> str | None:
    """정규화 후 루트/deep 판정. 유효하지 않은 URL이면 None."""
    normalized = preprocess_url(url)
    if normalized is None:
        return None
    path = urlsplit(normalized).path
    return "root" if path in ("", "/") else "deep"


def normalized_key(url: str) -> str | None:
    """중복 제거용 정규화 키"""
    return preprocess_url(url)


def registrable_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def base_domain(host: str) -> str:
    """등록가능 도메인 근사 — 마지막 두 레이블"""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ═══════════════════════════════════════════════════════════════
#  1) 피싱 URL — OpenPhish
# ═══════════════════════════════════════════════════════════════

def fetch_openphish() -> list[str]:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache = RAW_DIR / "openphish_feed.txt"

    if cache.exists():
        logger.info("OpenPhish 캐시 사용: %s", cache)
        text = cache.read_text(encoding="utf-8", errors="replace")
    else:
        logger.info("OpenPhish 피드 다운로드 중...")
        # 피드는 GitHub raw로 302 리다이렉트된다
        resp = httpx.get(
            OPENPHISH_FEED, timeout=60.0, follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        text = resp.text
        cache.write_text(text, encoding="utf-8")
        logger.info("OpenPhish 원본 저장: %s", cache)

    urls = [ln.strip() for ln in text.splitlines() if ln.strip()]
    logger.info("OpenPhish 원본 %d건", len(urls))
    return urls


# ═══════════════════════════════════════════════════════════════
#  2) 정상 도메인 — Tranco Top-1M
# ═══════════════════════════════════════════════════════════════

def fetch_tranco(limit: int = 3000) -> list[str]:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    cache = RAW_DIR / "tranco_top.csv"

    if cache.exists():
        logger.info("Tranco 캐시 사용: %s", cache)
        rows = cache.read_text(encoding="utf-8").splitlines()
    else:
        logger.info("Tranco Top-1M 다운로드 중 (약 10MB)...")
        resp = httpx.get(
            TRANCO_TOP1M, timeout=180.0, follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            name = zf.namelist()[0]
            with zf.open(name) as fh:
                text = io.TextIOWrapper(fh, encoding="utf-8")
                rows = [next(text).strip() for _ in range(limit)]
        cache.write_text("\n".join(rows), encoding="utf-8")
        logger.info("Tranco 상위 %d개 저장: %s", len(rows), cache)

    domains = []
    for row in rows[:limit]:
        parts = row.split(",")
        if len(parts) >= 2 and parts[1]:
            domains.append(parts[1].strip().lower())
    logger.info("Tranco 도메인 %d개", len(domains))
    return domains


# ═══════════════════════════════════════════════════════════════
#  3) 정상 deep URL — 상위 도메인 홈페이지에서 내부 링크 추출
# ═══════════════════════════════════════════════════════════════

async def _extract_internal_links(
    client: httpx.AsyncClient, domain: str, max_links: int
) -> list[str]:
    """도메인 홈페이지를 1회 조회하여 동일 출처 deep 링크를 추출"""
    home = f"https://{domain}"
    try:
        resp = await client.get(home)
    except Exception:
        return []
    if resp.status_code != 200 or not resp.content:
        return []

    base = str(resp.url)
    base_host = registrable_host(base)
    found: list[str] = []
    seen: set[str] = set()

    for raw in _HREF_RE.findall(resp.content[:600_000]):
        try:
            href = raw.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue
        if not href or href.startswith(("mailto:", "javascript:", "tel:", "data:")):
            continue

        absolute = urljoin(base, href)
        if not absolute.startswith(("http://", "https://")):
            continue
        # 동일 출처만 (외부 링크는 정상 보장이 약함)
        if registrable_host(absolute) != base_host:
            continue
        if classify_path_type(absolute) != "deep":
            continue

        key = normalized_key(absolute)
        if key is None or key in seen:
            continue
        seen.add(key)
        found.append(key)
        if len(found) >= max_links:
            break

    return found


async def collect_benign_deep(
    domains: list[str], target: int, per_domain: int = 2, concurrency: int = 12
) -> list[str]:
    """목표 개수를 채울 때까지 상위 도메인들의 홈페이지를 순회"""
    results: list[str] = []
    seen: set[str] = set()
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        verify=True,
    ) as client:

        async def worker(domain: str) -> list[str]:
            async with sem:
                return await _extract_internal_links(client, domain, per_domain)

        batch_size = concurrency * 4
        for start in range(0, len(domains), batch_size):
            batch = domains[start:start + batch_size]
            gathered = await asyncio.gather(
                *(worker(d) for d in batch), return_exceptions=True
            )
            for item in gathered:
                if isinstance(item, Exception):
                    continue
                for url in item:
                    if url not in seen:
                        seen.add(url)
                        results.append(url)
            logger.info(
                "deep URL 수집 진행: %d/%d (도메인 %d개 처리)",
                len(results), target, min(start + batch_size, len(domains)),
            )
            if len(results) >= target:
                break

    return results[:target]


async def filter_live_roots(
    domains: list[str], target: int, concurrency: int = 12
) -> list[str]:
    """루트 URL이 실제로 열리는 도메인만 선별.

    Tranco 상위에는 브라우징 대상이 아닌 인프라 도메인(광고·SDK·DNS 등)이 섞여 있다.
    '실제로 200을 반환하는 사이트'만 남겨 정상 표본의 품질을 확보한다.
    """
    alive: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        timeout=12.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    ) as client:

        async def probe(domain: str) -> str | None:
            async with sem:
                try:
                    resp = await client.get(f"https://{domain}")
                except Exception:
                    return None
            return domain if resp.status_code == 200 else None

        batch_size = concurrency * 4
        for start in range(0, len(domains), batch_size):
            batch = domains[start:start + batch_size]
            got = await asyncio.gather(*(probe(d) for d in batch), return_exceptions=True)
            for item in got:
                if isinstance(item, str):
                    alive.append(item)
            logger.info(
                "정상 루트 생존 확인: %d/%d (도메인 %d개 검사)",
                len(alive), target, min(start + batch_size, len(domains)),
            )
            if len(alive) >= target:
                break

    return alive[:target]


# ═══════════════════════════════════════════════════════════════
#  4) 평가셋 조립
# ═══════════════════════════════════════════════════════════════

def _dedupe_valid(urls: list[str]) -> list[tuple[str, str]]:
    """정규화·검증 통과분만 (정규화URL, path_type)으로 반환"""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for u in urls:
        key = normalized_key(u)
        if key is None or key in seen:
            continue
        ptype = classify_path_type(key)
        if ptype is None:
            continue
        seen.add(key)
        out.append((key, ptype))
    return out


def _take_stratified(
    pool: list[tuple[str, str]], n_root: int, n_deep: int, rng: random.Random
) -> list[tuple[str, str]]:
    roots = [p for p in pool if p[1] == "root"]
    deeps = [p for p in pool if p[1] == "deep"]
    rng.shuffle(roots)
    rng.shuffle(deeps)

    picked = roots[:n_root] + deeps[:n_deep]
    # 한쪽이 부족하면 다른 쪽에서 보충하되, 실제 구성은 그대로 보고한다
    shortfall = (n_root + n_deep) - len(picked)
    if shortfall > 0:
        leftovers = roots[n_root:] + deeps[n_deep:]
        rng.shuffle(leftovers)
        picked += leftovers[:shortfall]
        logger.warning("층화 목표 미달 — %d건을 잔여 풀에서 보충", shortfall)
    return picked


def build(total: int, benign_ratio: float, root_ratio: float) -> list[dict]:
    rng = random.Random(SEED)

    n_benign = int(total * benign_ratio)
    n_phish = total - n_benign

    # ── 피싱 ──
    phish_pool = _dedupe_valid(fetch_openphish())
    logger.info(
        "피싱 풀 %d건 (root %d / deep %d)",
        len(phish_pool),
        sum(1 for p in phish_pool if p[1] == "root"),
        sum(1 for p in phish_pool if p[1] == "deep"),
    )
    phish = _take_stratified(
        phish_pool, int(n_phish * root_ratio), n_phish - int(n_phish * root_ratio), rng
    )

    # ── 정상 ──
    # 라벨 충돌 방지: 피싱 피드에 하위 URL이 존재하는 등록가능 도메인은 정상에서 제외.
    # (예: github.io·blogspot.com은 루트가 정상이나 하위에 피싱이 다수 존재)
    phish_bases = {base_domain(registrable_host(u)) for u, _ in phish_pool}

    domains: list[str] = []
    for d in fetch_tranco():
        if _SKIP_DOMAIN_PATTERN.search(d + "."):
            continue
        if d in _SHARED_HOSTING or base_domain(d) in _SHARED_HOSTING:
            continue
        if base_domain(d) in phish_bases:
            continue
        domains.append(d)
    logger.info("정상 후보 도메인 %d개 (인프라·공유호스팅·라벨충돌 제외 후)", len(domains))

    n_benign_root = int(n_benign * root_ratio)
    n_benign_deep = n_benign - n_benign_root

    logger.info("정상 루트 URL 생존 확인 시작 (목표 %d건)", n_benign_root)
    live_roots = asyncio.run(filter_live_roots(domains, target=n_benign_root))
    benign_root = _dedupe_valid([f"https://{d}" for d in live_roots])[:n_benign_root]

    logger.info("정상 deep URL 크롤링 시작 (목표 %d건)", n_benign_deep)
    deep_raw = asyncio.run(collect_benign_deep(domains, target=n_benign_deep * 2))
    benign_deep_pool = _dedupe_valid(deep_raw)
    benign_deep = [p for p in benign_deep_pool if p[1] == "deep"][:n_benign_deep]

    rows: list[dict] = []
    for url, ptype in benign_root:
        rows.append({"url": url, "label": 0, "source": "tranco", "path_type": ptype})
    for url, ptype in benign_deep:
        rows.append({"url": url, "label": 0, "source": "tranco-crawl", "path_type": ptype})
    for url, ptype in phish:
        rows.append({"url": url, "label": 1, "source": "openphish", "path_type": ptype})

    rng.shuffle(rows)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="평가셋 500건 구성")
    ap.add_argument("--total", type=int, default=500, help="총 URL 수")
    ap.add_argument("--benign-ratio", type=float, default=0.5, help="정상 비율")
    ap.add_argument("--root-ratio", type=float, default=0.5,
                    help="각 클래스 내 루트 URL 비율 (층화 통제)")
    ap.add_argument("--out", type=Path, default=DATA_DIR / "evalset.csv")
    args = ap.parse_args()

    rows = build(args.total, args.benign_ratio, args.root_ratio)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["url", "label", "source", "path_type"])
        writer.writeheader()
        writer.writerows(rows)

    # ── 구성 보고 (논문 '평가셋 구성표'에 그대로 사용) ──
    print(f"\n저장: {args.out}  ({len(rows)}건)\n")
    print(f"{'구분':<14} {'root':>7} {'deep':>7} {'합계':>7}")
    print("-" * 38)
    for label, name in [(0, "정상"), (1, "피싱")]:
        r = sum(1 for x in rows if x["label"] == label and x["path_type"] == "root")
        d = sum(1 for x in rows if x["label"] == label and x["path_type"] == "deep")
        print(f"{name:<14} {r:>7} {d:>7} {r + d:>7}")
    tr = sum(1 for x in rows if x["path_type"] == "root")
    td = sum(1 for x in rows if x["path_type"] == "deep")
    print("-" * 38)
    print(f"{'합계':<14} {tr:>7} {td:>7} {len(rows):>7}")
    print("\n※ 제로데이 부분집합은 사전 지정하지 않는다. VT 조회 결과 미등재(404)로")
    print("  판명된 건이 제로데이 표본이 된다 (collect_vt.py 실행 후 확정).")


if __name__ == "__main__":
    main()

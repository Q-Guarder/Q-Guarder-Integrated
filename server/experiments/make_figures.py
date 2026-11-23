"""논문 그림 생성 — §3.5 하이퍼파라미터 민감도 분석 (Fig. 3~6)

results.json을 읽어 파라미터 스윕 결과를 선그래프로 렌더링한다.
계산은 하지 않는다. fusion_experiment.py를 먼저 실행할 것.

■ 인쇄 규격 (학진등재 논문지)
  - 흑백 인쇄 대응: 계열 구분을 **색상에 의존하지 않는다.**
    선 종류(실선/파선/점선) + 마커 모양 + 명도 3단계를 함께 사용하므로
    그레이스케일로 출력해도 계열이 분리된다.
  - 벡터(PDF) + 300dpi PNG 동시 출력
  - 축·범례·라벨은 영문 (본문 그림 캡션이 영문)
  - 격자는 실선 hairline (파선 격자는 '임계값'으로 오독됨)
  - 값 라벨은 모든 점에 달지 않는다. 설계값 위치만 표시.

사용법
  python experiments/fusion_experiment.py     # results.json 생성
  python experiments/make_figures.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import PercentFormatter  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent / "data"
RESULTS = DATA_DIR / "results.json"
FIG_DIR = Path(__file__).resolve().parent / "figures"

# ── 흑백 인쇄용 계열 스타일 ──
# 명도가 뚜렷이 갈리는 3단계 + 서로 다른 선 종류/마커.
# 색상 채널을 쓰지 않으므로 CVD·그레이스케일 모두에서 안전하다.
SERIES_STYLE = {
    "recall":    {"color": "#000000", "linestyle": "-",   "marker": "o", "label": "Recall"},
    "precision": {"color": "#5A5A5A", "linestyle": "--",  "marker": "s", "label": "Precision"},
    "f1":        {"color": "#9A9A9A", "linestyle": "-.",  "marker": "^", "label": "F1-score"},
    "zero_day_recall": {
        "color": "#000000", "linestyle": ":", "marker": "D", "label": "Zero-day Recall",
    },
}

GRID_COLOR = "#D9D9D9"
AXIS_COLOR = "#4D4D4D"
TEXT_COLOR = "#1A1A1A"

# 파라미터별 그림 정의 — (results.json 키, 파일명, 캡션용 x축 라벨, 현행 설계값, 표시 계열)
FIGURES = [
    ("alpha", "fig3_alpha_sweep",
     r"VT amplification coefficient $\alpha$", 3.0,
     ["recall", "precision", "f1"]),
    ("tau_blocked", "fig4_tau_sweep",
     r"BLOCKED threshold $\tau$", 0.65,
     ["recall", "precision", "f1"]),
    ("d_high", "fig5_dhigh_sweep",
     r"CASE_A_HIGH boundary $d$", 5,
     ["recall", "precision", "f1"]),
    ("w_ml_B", "fig6_wmlb_sweep",
     r"CASE_B machine-learning weight $W_{ML}$", 0.30,
     ["recall", "f1", "zero_day_recall"]),
]


def apply_print_style() -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.labelsize": 10,
        "axes.titlesize": 10,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "axes.edgecolor": AXIS_COLOR,
        "axes.labelcolor": TEXT_COLOR,
        "text.color": TEXT_COLOR,
        "xtick.color": AXIS_COLOR,
        "ytick.color": AXIS_COLOR,
        "axes.linewidth": 0.8,
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "pdf.fonttype": 42,   # TrueType 임베딩 — 학회 제출 요건
        "ps.fonttype": 42,
    })


def draw_sweep(rows: list[dict], xlabel: str, design_value: float,
               series: list[str], outfile: Path) -> None:
    fig, ax = plt.subplots(figsize=(4.4, 3.2))

    xs = [r["value"] for r in rows]
    handles: list = []  # errorbar는 legend 등록 순서가 어긋나므로 직접 모아 정렬한다

    for key in series:
        style = SERIES_STYLE[key]
        ys, yerr_lo, yerr_hi = [], [], []
        has_ci = key == "recall"
        for r in rows:
            v = r.get(key)
            ys.append(float("nan") if v is None else v)
            if has_ci and r.get("recall_ci") and v is not None:
                lo, hi = r["recall_ci"]
                yerr_lo.append(max(0.0, v - lo))
                yerr_hi.append(max(0.0, hi - v))

        if has_ci and len(yerr_lo) == len(ys):
            # 95% Wilson CI — Recall에만 표기 (전 계열에 달면 판독이 어려움)
            container = ax.errorbar(
                xs, ys, yerr=[yerr_lo, yerr_hi],
                color=style["color"], linestyle=style["linestyle"],
                marker=style["marker"], markersize=5.5, linewidth=1.6,
                capsize=2.5, elinewidth=0.8, label=style["label"],
                markerfacecolor="white", markeredgewidth=1.2, zorder=3,
            )
            handles.append(container)
        else:
            line, = ax.plot(
                xs, ys,
                color=style["color"], linestyle=style["linestyle"],
                marker=style["marker"], markersize=5.5, linewidth=1.6,
                label=style["label"], markerfacecolor="white",
                markeredgewidth=1.2, zorder=3,
            )
            handles.append(line)

    # 현행 설계값 — 유일한 직접 주석 (모든 점에 값을 달지 않는다)
    # 라벨은 plot 영역 바깥 위쪽에 둔다. 안쪽에 세로로 세우면 데이터 선과 겹친다.
    ax.axvline(design_value, color=AXIS_COLOR, linewidth=0.8,
               linestyle=(0, (4, 3)), alpha=0.55, zorder=1)
    ax.annotate(
        f"design = {design_value:g}",
        xy=(design_value, 1.0), xycoords=("data", "axes fraction"),
        xytext=(0, 3), textcoords="offset points",
        fontsize=8, color=AXIS_COLOR, ha="center", va="bottom",
    )

    ax.set_xlabel(xlabel)
    # 판정 기준을 축 라벨에 명시 — τ 스윕만 BLOCKED 기준이라 혼동 소지가 있다
    basis = rows[0].get("basis")
    ax.set_ylabel("Score" if not basis else f"Score ({basis} basis)")
    ax.set_ylim(-0.03, 1.05)
    ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0, decimals=0))

    # 격자는 실선 hairline · 축 아래로
    ax.grid(True, which="major", axis="both", color=GRID_COLOR,
            linewidth=0.6, linestyle="-", zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)

    # loc="best" — 계열 형태가 그림마다 달라 고정 위치는 데이터와 겹친다.
    # 흰 배경을 깔아 선 위에 놓여도 판독을 방해하지 않게 한다.
    ax.legend(handles, [SERIES_STYLE[k]["label"] for k in series],
              loc="best", handlelength=2.6, borderaxespad=0.4,
              labelspacing=0.3, frameon=True, framealpha=0.9,
              edgecolor="none", facecolor="white")

    outfile.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(outfile.with_suffix(".pdf"))
    fig.savefig(outfile.with_suffix(".png"))
    plt.close(fig)
    print(f"  저장: {outfile.with_suffix('.pdf').name} / {outfile.with_suffix('.png').name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="논문 그림 생성 (§3.5)")
    ap.add_argument("--results", type=Path, default=RESULTS)
    ap.add_argument("--out", type=Path, default=FIG_DIR)
    args = ap.parse_args()

    if not args.results.exists():
        raise SystemExit(
            f"결과 파일 없음: {args.results}\n"
            f"먼저 실행하세요 → python experiments/fusion_experiment.py"
        )

    data = json.loads(args.results.read_text(encoding="utf-8"))
    sweeps = data.get("sweeps")
    if not sweeps:
        raise SystemExit(
            "results.json에 sweeps가 없습니다. "
            "--skip-sweeps 없이 fusion_experiment.py를 실행하세요."
        )

    apply_print_style()
    print(f"그림 생성 (n={data['meta']['n_records']}건 기준)")
    for key, stem, xlabel, design, series in FIGURES:
        rows = sweeps.get(key)
        if not rows:
            print(f"  건너뜀: {key} (데이터 없음)")
            continue
        draw_sweep(rows, xlabel, design, series, args.out / stem)

    print(f"\n출력 디렉터리: {args.out}")
    print("PDF는 벡터, PNG는 300dpi. 흑백 인쇄 시에도 선 종류·마커로 계열이 구분됩니다.")


if __name__ == "__main__":
    main()

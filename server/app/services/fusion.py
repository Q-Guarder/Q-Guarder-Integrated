"""상황 적응형 가중 융합 — 순수 함수 (논문 §2.3)

네트워크·모델·DB에 의존하지 않는다. 입력은 숫자와 상태값뿐이다.

■ 왜 분리하는가
  서버(analyze_url)와 실험 스크립트(fusion_experiment.py)가 **같은 함수**를 호출한다.
  실험 쪽에서 융합 로직을 따로 구현하면 논문이 보고하는 수치와 서버의 실제 동작이
  달라질 수 있으므로, 단일 구현으로 고정해 "논문 수치 = 서버 동작"을 코드로 보장한다.

■ 파라미터화가 필요한 이유
  §3.3 전략 비교(ML 단독 / 고정 융합 / 4-Case / 4-Case+Override)와
  §3.5 민감도 분석(α·τ·d·W_ML 스윕)은 동일 입력에 대해 파라미터만 바꿔가며
  수백 번 재계산해야 한다. 모듈 상수로는 불가능하다.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

# ═══════════════════════════════════════════════════════════════
#  VT 응답 상태
# ═══════════════════════════════════════════════════════════════

class VTStatus(str, Enum):
    """VirusTotal 응답 상태.

    ⚠️ NOT_FOUND(미등재)와 UNAVAILABLE(장애)을 절대 같은 값으로 뭉개지 말 것.
       - NOT_FOUND  : VT가 이 URL을 모른다 → '제로데이 후보'라는 유의미한 정보
       - UNAVAILABLE: 조회 자체가 실패했다 → 아무 정보도 얻지 못함
       둘 다 (0, 0)으로 처리하면 제로데이 판별이 불가능해진다.
    """
    OK = "ok"                    # 200 — VT가 아는 URL, 분석 결과 존재
    NOT_FOUND = "not_found"      # 404 — VT 미등재 (제로데이 후보)
    UNAVAILABLE = "unavailable"  # 401/429/timeout/network — 판단 불가


# ═══════════════════════════════════════════════════════════════
#  케이스 식별자
# ═══════════════════════════════════════════════════════════════

CASE_A_HIGH = "CASE_A_HIGH"  # VT 다수 탐지 → VT 강하게 신뢰
CASE_A_LOW = "CASE_A_LOW"    # VT 소수 탐지 → 균등
CASE_B = "CASE_B"            # VT clean → VT 신뢰, ML false positive 억제
CASE_C = "CASE_C"            # TI 무정보 (미등재 / API 장애) → ML 의존
CASE_OVERRIDE = "OVERRIDE"   # 하드 오버라이드 발동
CASE_FIXED = "CASE_FIXED"    # 고정 융합 baseline (케이스 전환 없음)

ALL_CASES = (CASE_A_HIGH, CASE_A_LOW, CASE_B, CASE_C)

RISK_BLOCKED = "BLOCKED"
RISK_SUSPICIOUS = "SUSPICIOUS"
RISK_SECURED = "SECURED"


# ═══════════════════════════════════════════════════════════════
#  융합 파라미터
# ═══════════════════════════════════════════════════════════════

def _default_w_ml() -> dict[str, float]:
    """1차 심사본의 W_ML (상황 B 루트/경로 구분 없음). W_VT는 1 − W_ML로 정해진다.

    최종 논문 식 (3)의 값은 REVISED_PARAMS 참조 (상황 B 경로 포함 URL은 0.50).
    """
    return {
        CASE_A_HIGH: 0.25,  # VT 0.75
        CASE_A_LOW: 0.50,   # VT 0.50
        CASE_B: 0.30,       # VT 0.70
        CASE_C: 0.80,       # VT 0.20
    }


@dataclass(frozen=True)
class OverrideRules:
    """하드 오버라이드 안전 계층.

    두 계열의 규칙을 모두 표현할 수 있다.
      - 비율 규칙(2차 논문 식 2): d/n ≥ θ → BLOCKED
      - 절대 개수 규칙(1차 구성안 R1~R3)

    ※ 비율 규칙 θ=0.30은 92개 엔진 기준 d≥28을 요구한다. 실제 피싱 URL의 VT
      탐지 수는 보통 5~15개이므로 사실상 발동하지 않는다. 절대 개수 규칙과
      어느 쪽을 쓸지는 실측으로 결정한다.
    """
    ratio_threshold: float | None = 0.30   # d/n ≥ θ → BLOCKED
    r1_min_detections: int | None = None   # R1: d ≥ k → BLOCKED
    r2_ml_min: float | None = None         # R2: p_ml ≥ x ∧ d ≥ m → BLOCKED
    r2_min_detections: int = 1
    r3_ml_max: float | None = None         # R3: d = 0 ∧ p_ml < y → SECURED


RATIO_OVERRIDE = OverrideRules()
"""2차 논문 식 (2) — 비율 단일 규칙"""

RULE_OVERRIDE = OverrideRules(
    ratio_threshold=None,
    r1_min_detections=5,
    r2_ml_min=0.85,
    r2_min_detections=1,
    r3_ml_max=0.08,
)
"""1차 구성안 R1/R2/R3 — 절대 개수 기반 3규칙"""


@dataclass(frozen=True)
class FusionParams:
    """융합 하이퍼파라미터. 모든 값이 §3.5 민감도 분석의 스윕 대상이다.

    ⚠️ 필드 기본값은 **1차 심사본 값**(α 3.0, τL 0.35, θ 0.30)이다. 1차 실험 재현
       스크립트와 전략 프리셋(params_adaptive/params_fixed/params_ml_only)이 이 값을
       전제로 하므로 바꾸지 않는다. 최종 논문·서버 값은 SERVER_PARAMS(= REVISED_PARAMS)
       이며, fuse()/classify_risk()/select_case()의 기본 인자도 SERVER_PARAMS다.
    """

    alpha: float = 3.0              # VT 증폭 계수 α (식 4)
    d_high: int = 5                 # CASE_A_HIGH 진입 최소 탐지 수
    tau_blocked: float = 0.65       # BLOCKED 임계값
    tau_suspicious: float = 0.35    # SUSPICIOUS 임계값

    # 케이스별 ML 가중치 (W_VT = 1 − W_ML)
    w_ml: dict[str, float] = field(default_factory=_default_w_ml)
    # CASE_B 경로 포함(deep) URL 전용 W_ML — 재심 수정안 C (식 (3)).
    # None이면 CASE_B 전체에 w_ml[CASE_B]를 쓴다 (1차 심사본 동작).
    w_ml_b_deep: float | None = None

    # 전략 스위치
    use_case_selection: bool = True   # False면 fixed_w_ml을 항상 사용 (고정 융합)
    fixed_w_ml: float = 0.50          # use_case_selection=False일 때의 W_ML
    override: OverrideRules | None = field(default_factory=OverrideRules)

    @property
    def theta_override(self) -> float | None:
        """식 (2)의 θ — 하위 호환용 읽기 전용 접근자"""
        return self.override.ratio_threshold if self.override else None

    def with_w_ml(self, case: str, value: float) -> "FusionParams":
        """특정 케이스의 W_ML만 바꾼 새 파라미터 (스윕용)"""
        updated = dict(self.w_ml)
        updated[case] = value
        return replace(self, w_ml=updated)


# ── 전략 프리셋 (논문 §3.3 Table 4의 4조건) ──

def params_adaptive(
    *,
    use_override: bool = True,
    override: OverrideRules | None = None,
    **overrides,
) -> FusionParams:
    """(3)/(4) 상황 적응형 4-Case 융합

    use_override=False면 오버라이드 계층 없음. override로 규칙 계열을 지정한다
    (기본은 2차 논문의 비율 규칙).
    """
    rules = override if override is not None else (RATIO_OVERRIDE if use_override else None)
    if not use_override:
        rules = None
    return replace(FusionParams(), override=rules, **overrides)


def params_fixed(w_ml: float = 0.50, **overrides) -> FusionParams:
    """(2) 고정 비율 융합 baseline — 케이스 전환도 오버라이드도 없음"""
    return replace(
        FusionParams(),
        use_case_selection=False,
        override=None,
        fixed_w_ml=w_ml,
        **overrides,
    )


def params_ml_only(threshold: float = 0.41) -> FusionParams:
    """(1) ML 단독 baseline.

    W_ML = 1.0으로 두어 S_final = P_ML이 되게 하고, 두 임계값을 학습 시 확정된
    threshold(0.41)로 일치시켜 SUSPICIOUS 구간 없는 이진 판정을 만든다.
    """
    return replace(
        FusionParams(),
        use_case_selection=False,
        override=None,
        fixed_w_ml=1.0,
        tau_blocked=threshold,
        tau_suspicious=threshold,
    )


PAPER_V1_PARAMS = FusionParams()
"""1차 심사본 파라미터 (α 3.0, τL 0.35, θ 0.30). 1차 실험 재현(fusion_experiment.py,
confusion_report.py) 전용. 서버 동작이나 최종 논문 수치와는 다르다."""

DEFAULT_PARAMS = PAPER_V1_PARAMS
"""하위 호환 별칭 — 이름과 달리 함수 기본값이 아니다. 새 코드에서는 PAPER_V1_PARAMS
또는 SERVER_PARAMS를 명시적으로 쓸 것."""

REVISED_PARAMS = FusionParams(
    alpha=18.4,                 # n̄/d_high = 92/5 (검증 집합 VT 엔진 수 중앙값)
    d_high=5,
    tau_blocked=0.65,
    tau_suspicious=0.45,
    w_ml={CASE_A_HIGH: 0.25, CASE_A_LOW: 0.50, CASE_B: 0.30, CASE_C: 0.80},
    w_ml_b_deep=0.50,           # CASE_B 경로 포함 URL (루트 URL은 0.30 유지)
    override=OverrideRules(ratio_threshold=0.05),   # θ = d_high/n̄
)
"""재심 수정본 확정 파라미터 — experiments/data/revision/fixed_params.json(2026-10-18)과 동일.
서버(analyze_url)의 기본값. "논문 수치 = 서버 동작"을 이 상수로 보장한다."""

SERVER_PARAMS = REVISED_PARAMS


# ═══════════════════════════════════════════════════════════════
#  융합 결과
# ═══════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class FusionResult:
    risk_level: str      # SECURED | SUSPICIOUS | BLOCKED
    final_score: float   # 0.0 ~ 1.0
    case: str
    ml_weighted: float
    vt_weighted: float
    vt_ratio: float      # 원본 탐지 비율 d/n
    vt_score: float      # 증폭 후 VT 위험 점수 S_VT (식 4)
    override_rule: str | None = None  # 발동한 오버라이드 규칙명 (RATIO/R1/R2/R3)

    @property
    def detected(self) -> bool:
        """이진 탐지 판정 — SUSPICIOUS 이상을 '탐지'로 본다 (Recall/FPR 계산용)"""
        return self.risk_level in (RISK_BLOCKED, RISK_SUSPICIOUS)

    @property
    def blocked(self) -> bool:
        """BLOCKED 기준 판정 — 자동 KISA 신고 등 강한 조치의 근거"""
        return self.risk_level == RISK_BLOCKED


# ═══════════════════════════════════════════════════════════════
#  핵심 로직
# ═══════════════════════════════════════════════════════════════

def amplify_vt_ratio(vt_ratio: float, alpha: float = SERVER_PARAMS.alpha) -> float:
    """VT 위험 점수 (식 4) — S_VT = min(1.0, α × d/n).

    실제 탐지율은 자연적으로 낮아 선형 결합 시 희석되므로 이를 보정한다.
    예) α=18.4에서 5/92 → 0.054 → 1.0 포화 (d ≥ d_high 이면 S_VT = 1)
        α=3.0(1차 심사본)에서 10/70 → 0.143 → 0.429
    """
    return min(1.0, vt_ratio * alpha)


def classify_risk(score: float, params: FusionParams = SERVER_PARAMS) -> str:
    """최종 점수 → 위험도 등급 (식 7)"""
    if score >= params.tau_blocked:
        return RISK_BLOCKED
    if score >= params.tau_suspicious:
        return RISK_SUSPICIOUS
    return RISK_SECURED


def select_case(
    detected: int, total: int, status: VTStatus,
    params: FusionParams = SERVER_PARAMS,
) -> str:
    """VT 응답 상태와 탐지 수 기준 케이스 선택 (식 2).

    ※ 미등재(NOT_FOUND)와 API 장애(UNAVAILABLE)는 모두 CASE_C다. 논문도 상황 C를
      "VT 정보를 활용할 수 없는 경우"로 정의해 둘을 구분하지 않는다.
    """
    if not params.use_case_selection:
        return CASE_FIXED
    if status is VTStatus.UNAVAILABLE:
        return CASE_C           # API 장애 → TI 신호 소실
    if status is VTStatus.NOT_FOUND:
        return CASE_C           # VT 미등재 → TI 무정보 (제로데이 후보)
    if detected == 0:
        return CASE_B           # VT가 스캔 완료, 전부 clean
    if detected >= params.d_high:
        return CASE_A_HIGH      # VT 다수 탐지
    return CASE_A_LOW           # VT 소수 탐지


def fuse(
    p_ml: float,
    detected: int,
    total: int,
    status: VTStatus | str,
    params: FusionParams = SERVER_PARAMS,
    path_type: str | None = None,
) -> FusionResult:
    """ML 확률과 VT 평판을 상황 적응형으로 융합한다 (식 2~7).

    params를 생략하면 SERVER_PARAMS(최종 논문 확정값)를 쓴다.

    Args:
        p_ml:     ML 앙상블의 악성 확률 (0~1)
        detected: VT 탐지 엔진 수 d
        total:    VT 전체 엔진 수 n
        status:   VT 응답 상태
        params:   융합 하이퍼파라미터
        path_type: "root" | "deep" — CASE_B에서 params.w_ml_b_deep 적용 여부 결정
                   (None이면 루트로 간주해 w_ml[CASE_B] 사용)

    Returns:
        FusionResult
    """
    if isinstance(status, str):
        status = VTStatus(status)

    vt_ratio = detected / total if total > 0 else 0.0
    vt_score = amplify_vt_ratio(vt_ratio, params.alpha)
    rules = params.override

    # ── 상향 오버라이드 — 케이스 가중 융합보다 먼저 평가 ──
    escalation: str | None = None
    if rules is not None:
        if rules.ratio_threshold is not None and vt_ratio >= rules.ratio_threshold:
            escalation = "RATIO"
        elif rules.r1_min_detections is not None and detected >= rules.r1_min_detections:
            escalation = "R1"
        elif (
            rules.r2_ml_min is not None
            and p_ml >= rules.r2_ml_min
            and detected >= rules.r2_min_detections
        ):
            escalation = "R2"

    if escalation is not None:
        return FusionResult(
            risk_level=RISK_BLOCKED,
            final_score=1.0,
            case=CASE_OVERRIDE,
            ml_weighted=0.0,
            vt_weighted=1.0,
            vt_ratio=vt_ratio,
            vt_score=vt_score,
            override_rule=escalation,
        )

    case = select_case(detected, total, status, params)
    if case == CASE_FIXED:
        w_ml = params.fixed_w_ml
    elif case == CASE_B and params.w_ml_b_deep is not None and path_type == "deep":
        w_ml = params.w_ml_b_deep
    else:
        w_ml = params.w_ml[case]
    w_vt = 1.0 - w_ml

    ml_weighted = p_ml * w_ml          # 식 (5)의 ML 항
    vt_weighted = vt_score * w_vt      # 식 (5)의 VT 항
    final_score = round(ml_weighted + vt_weighted, 4)  # 식 (5)
    risk = classify_risk(final_score, params)

    # ── 하향 오버라이드 R3 — VT가 아무것도 못 잡고 ML도 매우 낮으면 안전 확정 ──
    demotion: str | None = None
    if (
        rules is not None
        and rules.r3_ml_max is not None
        and detected == 0
        and p_ml < rules.r3_ml_max
    ):
        risk = RISK_SECURED
        demotion = "R3"

    return FusionResult(
        risk_level=risk,
        final_score=final_score,
        case=case,
        ml_weighted=round(ml_weighted, 4),
        vt_weighted=round(vt_weighted, 4),
        vt_ratio=vt_ratio,
        vt_score=vt_score,
        override_rule=demotion,
    )

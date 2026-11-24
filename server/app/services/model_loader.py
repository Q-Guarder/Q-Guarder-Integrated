"""모델 로더 — local_models/의 model.pkl을 로드하여 메모리에 적재 (추론 전용)"""

import logging
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)

# 모듈 레벨 캐싱 (Redis 사용 금지 — Python 변수로 대체)
_model_cache: object | None = None

# With Feature Selection · XGB+LGBM Top-17 Soft Voting · threshold 0.41
_LOCAL_MODEL_PATH = Path(__file__).resolve().parents[2] / "local_models" / "final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl"


class ModelLoadError(Exception):
    """모델 로드 실패 시 발생하는 예외"""


class _EnsembleUnpickler(pickle.Unpickler):
    """__main__.SoftVotingEnsemble → app.services.ensemble_model로 리매핑"""

    def find_class(self, module: str, name: str):
        if module == "__main__" and name == "SoftVotingEnsemble":
            from app.services.ensemble_model import SoftVotingEnsemble
            return SoftVotingEnsemble
        return super().find_class(module, name)


def _validate_model(model: object) -> None:
    """
    로드된 앙상블이 서버의 피처 추출기와 호환되는지 검증합니다.

    학습 측에서 선택한 피처(model.features)가 url_features.FEATURE_COLUMNS의
    부분집합이 아니면 추론 시점에 KeyError가 나므로 로드 단계에서 차단합니다.
    """
    from app.services.url_features import FEATURE_COLUMNS

    if not hasattr(model, "models") or not hasattr(model, "features"):
        raise ModelLoadError(
            "앙상블 모델 형식이 아닙니다: models/features 속성이 없습니다."
        )

    available = set(FEATURE_COLUMNS)
    for idx, feats in enumerate(model.features):
        missing = [f for f in feats if f not in available]
        if missing:
            raise ModelLoadError(
                f"서브모델 #{idx}가 요구하는 피처를 추출기가 제공하지 않습니다: {missing}"
            )

    sizes = ", ".join(str(len(f)) for f in model.features)
    logger.info(
        "모델 검증 통과 — 서브모델 %d개 (피처 수: %s / 추출기 %d개)",
        len(model.models), sizes, len(FEATURE_COLUMNS),
    )


def _load_model() -> object:
    """local_models/에서 모델 로드 (로드 직후 호환성 검증)"""
    if not _LOCAL_MODEL_PATH.exists():
        raise ModelLoadError(f"모델 파일 없음: {_LOCAL_MODEL_PATH}")
    try:
        with open(_LOCAL_MODEL_PATH, "rb") as f:
            model = _EnsembleUnpickler(f).load()
    except (pickle.UnpicklingError, EOFError, AttributeError) as e:
        logger.error("모델 역직렬화 실패: %s", e)
        raise ModelLoadError(f"모델 파일이 손상되었습니다: {e}") from e
    logger.info("ML 모델 로드 완료: %s", _LOCAL_MODEL_PATH)
    _validate_model(model)
    return model


def get_model() -> object:
    """캐싱된 모델 반환. 없으면 로드 후 캐싱."""
    global _model_cache
    if _model_cache is None:
        _model_cache = _load_model()
    return _model_cache


def reload_model() -> object:
    """강제 리로드 (모델 파일 교체 후 호출). 재학습이 아닌 최신 모델 재적재."""
    global _model_cache
    _model_cache = _load_model()
    return _model_cache

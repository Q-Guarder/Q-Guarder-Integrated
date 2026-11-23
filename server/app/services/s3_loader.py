"""S3 모델 로더 — S3 또는 로컬에서 model.pkl을 로드하여 메모리에 적재 (추론 전용)"""

import io
import logging
import pickle
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# 모듈 레벨 캐싱 (Redis 사용 금지 — Python 변수로 대체)
_model_cache: object | None = None

# 로컬 모델 경로 (S3 미설정 시 fallback)
# With Feature Selection · XGB+LGBM Top-17 Soft Voting · threshold 0.41 (논문 §3.1)
_LOCAL_MODEL_PATH = Path(__file__).resolve().parents[2] / "local_models" / "final_with_fs_top17_e1_top17_xgb_lgbm_threshold041.pkl"


class S3LoadError(Exception):
    """S3 모델 로드 실패 시 발생하는 예외"""


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
        raise S3LoadError(
            "앙상블 모델 형식이 아닙니다: models/features 속성이 없습니다."
        )

    available = set(FEATURE_COLUMNS)
    for idx, feats in enumerate(model.features):
        missing = [f for f in feats if f not in available]
        if missing:
            raise S3LoadError(
                f"서브모델 #{idx}가 요구하는 피처를 추출기가 제공하지 않습니다: {missing}"
            )

    sizes = ", ".join(str(len(f)) for f in model.features)
    logger.info(
        "모델 검증 통과 — 서브모델 %d개 (피처 수: %s / 추출기 %d개)",
        len(model.models), sizes, len(FEATURE_COLUMNS),
    )


def _load_from_local() -> object:
    """로컬 파일에서 모델 로드 (개발/Docker 환경용)"""
    if not _LOCAL_MODEL_PATH.exists():
        raise S3LoadError(f"로컬 모델 파일 없음: {_LOCAL_MODEL_PATH}")
    try:
        with open(_LOCAL_MODEL_PATH, "rb") as f:
            model = _EnsembleUnpickler(f).load()
        logger.info("ML 모델 로컬 로드 완료: %s", _LOCAL_MODEL_PATH)
        return model
    except (pickle.UnpicklingError, EOFError, AttributeError) as e:
        logger.error("로컬 모델 역직렬화 실패: %s", e)
        raise S3LoadError(f"모델 파일이 손상되었습니다: {e}") from e


def _download_from_s3() -> object:
    """S3에서 model.pkl 바이너리를 다운로드하고 역직렬화"""
    try:
        s3 = boto3.client("s3", region_name=settings.AWS_REGION)
        buffer = io.BytesIO()
        s3.download_fileobj(
            Bucket=settings.S3_MODEL_BUCKET,
            Key=settings.S3_MODEL_KEY,
            Fileobj=buffer,
        )
        buffer.seek(0)
        model = _EnsembleUnpickler(buffer).load()
        logger.info("ML 모델 로드 완료: s3://%s/%s", settings.S3_MODEL_BUCKET, settings.S3_MODEL_KEY)
        return model
    except (ClientError, BotoCoreError) as e:
        logger.error("S3 모델 다운로드 실패: %s", e)
        raise S3LoadError(f"S3에서 모델을 로드할 수 없습니다: {e}") from e
    except (pickle.UnpicklingError, EOFError, AttributeError) as e:
        logger.error("모델 역직렬화 실패: %s", e)
        raise S3LoadError(f"모델 파일이 손상되었습니다: {e}") from e


def _load_model() -> object:
    """S3 설정이 있으면 S3에서, 없으면 로컬에서 모델 로드 (로드 직후 호환성 검증)"""
    model = _download_from_s3() if settings.S3_MODEL_BUCKET else _load_from_local()
    _validate_model(model)
    return model


def get_model() -> object:
    """캐싱된 모델 반환. 없으면 S3/로컬에서 로드 후 캐싱."""
    global _model_cache
    if _model_cache is None:
        _model_cache = _load_model()
    return _model_cache


def reload_model() -> object:
    """강제 리로드 (배포 이력 갱신 시 호출). 재학습이 아닌 최신 모델 재적재."""
    global _model_cache
    _model_cache = _load_model()
    return _model_cache

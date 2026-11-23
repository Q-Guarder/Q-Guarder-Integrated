"""SoftVotingEnsemble 클래스 정의 — pkl 역직렬화 시 필요

⚠️ 이 클래스는 학습 파이프라인(Colab `__main__`)에서 pickle된 객체를 복원하기 위한
   정의입니다. 속성명(models/features/model_names)과 predict_proba 로직은 학습 측과
   반드시 일치해야 하며, 변경하면 역직렬화된 객체가 오동작합니다.

   복원되는 인스턴스 속성: models, features, model_names
   (학습 측에 threshold 속성이 없으므로 predict()는 인자로 받습니다.)

   학습 측과의 유일한 차이: predict()의 기본 threshold를 0.5 → MODEL_THRESHOLD(0.41)로
   변경. 서버에서 인자 없이 호출해도 운영 임계값이 적용되도록 하기 위함이며,
   역직렬화에는 영향을 주지 않습니다.
"""

import numpy as np

# 학습 시 확정된 운영 임계값 — With FS · XGB+LGBM Top-17 (논문 §3.1 Table 3)
MODEL_THRESHOLD = 0.41


class SoftVotingEnsemble:
    """XGBoost + LightGBM Soft Voting 앙상블 모델 (Top-17 Feature Selection)"""

    def __init__(self, model_outputs, model_names=None):
        self.models = [m["best_model"] for m in model_outputs]
        self.features = [m["selected_features"] for m in model_outputs]
        self.model_names = model_names

    def predict_proba(self, X):
        probs = []

        for model, feats in zip(self.models, self.features):
            X_input = X[feats].copy()
            prob = model.predict_proba(X_input)[:, 1]
            probs.append(prob)

        avg_prob = np.mean(probs, axis=0)
        return np.vstack([1 - avg_prob, avg_prob]).T

    def predict(self, X, threshold=MODEL_THRESHOLD):
        avg_prob = self.predict_proba(X)[:, 1]
        return (avg_prob >= threshold).astype(int)

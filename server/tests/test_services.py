"""하이브리드 엔진 및 서비스 레이어 테스트

회귀 방어 대상 (실제로 발생했던 버그)
  1. VT URL 식별자를 SHA-256(원문)으로 만들어 루트 URL이 전부 404 → '제로데이' 오분류
  2. 미등재(404)와 API 장애(429/timeout)를 같은 (0,0)으로 뭉개 제로데이 판별 불가
  3. VT 조회 실패를 'clean 판정'으로 오기록하여 FeedbackQueue가 잘못 처리 완료됨
  4. URL 파싱 실패가 ML 장애로 둔갑해 중립값 0.5로 처리됨
  5. send_kisa_report 호출 시 필수 인자 report_id 누락 → KISA 신고 100% 실패
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.fusion import (
    CASE_A_HIGH,
    CASE_A_LOW,
    CASE_B,
    CASE_C,
    CASE_OVERRIDE,
    PAPER_V1_PARAMS as V1,
    SERVER_PARAMS,
    FusionParams,
    VTStatus,
    amplify_vt_ratio,
    classify_risk,
    fuse,
    params_adaptive,
    params_fixed,
    params_ml_only,
    select_case,
)
from app.services.hybrid_engine import (
    InvalidUrlError,
    MLPredictionResult,
    VTResult,
    predict_url_with_ml,
    scan_url_with_virustotal,
    vt_url_id,
)
from app.services.model_loader import ModelLoadError


# ═══════════════════════════════════════════════════════════════
#  위험도 분류
#  ※ 이 파일 앞부분의 V1 = PAPER_V1_PARAMS (1차 심사본 값) 기준 테스트.
#    함수 기본값(SERVER_PARAMS, 최종 논문 값)은 TestDefaultsAreServerParams에서 검증.
# ═══════════════════════════════════════════════════════════════

class TestClassifyRisk:
    def test_blocked(self):
        assert classify_risk(0.7, V1) == "BLOCKED"
        assert classify_risk(0.99, V1) == "BLOCKED"

    def test_suspicious(self):
        assert classify_risk(0.4, V1) == "SUSPICIOUS"
        assert classify_risk(0.64, V1) == "SUSPICIOUS"

    def test_secured(self):
        assert classify_risk(0.0, V1) == "SECURED"
        assert classify_risk(0.349, V1) == "SECURED"

    def test_boundary_values(self):
        assert classify_risk(0.65, V1) == "BLOCKED"
        assert classify_risk(0.35, V1) == "SUSPICIOUS"
        assert classify_risk(0.3499, V1) == "SECURED"

    def test_thresholds_are_parameterised(self):
        strict = FusionParams(tau_blocked=0.45)
        assert classify_risk(0.5, strict) == "BLOCKED"
        assert classify_risk(0.5, V1) == "SUSPICIOUS"


# ═══════════════════════════════════════════════════════════════
#  VT 위험 점수 증폭 (식 4)
# ═══════════════════════════════════════════════════════════════

class TestAmplifyVtRatio:
    def test_linear_region(self):
        assert amplify_vt_ratio(10 / 70, alpha=V1.alpha) == pytest.approx(0.4286, abs=1e-4)

    def test_saturates_at_one(self):
        assert amplify_vt_ratio(24 / 70, alpha=V1.alpha) == 1.0
        assert amplify_vt_ratio(1.0, alpha=V1.alpha) == 1.0

    def test_zero_stays_zero(self):
        assert amplify_vt_ratio(0.0, alpha=V1.alpha) == 0.0

    def test_alpha_is_parameterised(self):
        assert amplify_vt_ratio(0.1, alpha=5.0) == pytest.approx(0.5)


# ═══════════════════════════════════════════════════════════════
#  케이스 선택 — 미등재 vs API 장애 구분 (회귀 #2)
# ═══════════════════════════════════════════════════════════════

class TestSelectCase:
    def test_vt_many_detections(self):
        assert select_case(5, 70, VTStatus.OK, V1) == CASE_A_HIGH
        assert select_case(30, 70, VTStatus.OK, V1) == CASE_A_HIGH

    def test_vt_few_detections(self):
        assert select_case(1, 70, VTStatus.OK, V1) == CASE_A_LOW
        assert select_case(4, 70, VTStatus.OK, V1) == CASE_A_LOW

    def test_vt_clean(self):
        assert select_case(0, 94, VTStatus.OK, V1) == CASE_B

    def test_not_found_and_unavailable_are_distinct_inputs(self):
        """현행 스펙은 같은 CASE_C를 쓰지만, 상태값 자체는 보존되어야 한다.

        두 상태를 (0, 0)으로 뭉개면 제로데이 분석이 불가능해진다.
        """
        assert VTStatus.NOT_FOUND is not VTStatus.UNAVAILABLE
        assert select_case(0, 0, VTStatus.NOT_FOUND, V1) == CASE_C
        assert select_case(0, 0, VTStatus.UNAVAILABLE, V1) == CASE_C

    def test_d_high_boundary_is_parameterised(self):
        params = FusionParams(d_high=3)
        assert select_case(3, 70, VTStatus.OK, params) == CASE_A_HIGH
        assert select_case(3, 70, VTStatus.OK, V1) == CASE_A_LOW


# ═══════════════════════════════════════════════════════════════
#  융합 — 논문 §2.3 식 (2)~(7)
# ═══════════════════════════════════════════════════════════════

class TestFuse:
    def test_case_b_vt_clean(self):
        """VT clean → ML 30% / VT 70%"""
        r = fuse(0.8, 0, 94, VTStatus.OK, V1)
        assert r.case == CASE_B
        assert r.final_score == pytest.approx(0.24)
        assert r.risk_level == "SECURED"

    def test_case_c_vt_unavailable(self):
        """VT 장애 → ML 80% / VT 20%"""
        r = fuse(0.8, 0, 0, VTStatus.UNAVAILABLE, V1)
        assert r.case == CASE_C
        assert r.final_score == pytest.approx(0.64)
        assert r.risk_level == "SUSPICIOUS"

    def test_case_a_low(self):
        r = fuse(0.8, 3, 70, VTStatus.OK, V1)
        assert r.case == CASE_A_LOW
        assert r.final_score == pytest.approx(0.4643, abs=1e-4)

    def test_case_a_high(self):
        r = fuse(0.8, 10, 70, VTStatus.OK, V1)
        assert r.case == CASE_A_HIGH
        assert r.final_score == pytest.approx(0.5214, abs=1e-4)

    def test_hard_override(self):
        """VT 탐지 비율 30% 이상 → ML과 무관하게 즉시 BLOCKED"""
        r = fuse(0.0, 30, 60, VTStatus.OK, V1)
        assert r.case == CASE_OVERRIDE
        assert r.final_score == 1.0
        assert r.risk_level == "BLOCKED"

    def test_override_can_be_disabled(self):
        r = fuse(0.0, 30, 60, VTStatus.OK, params_adaptive(use_override=False))
        assert r.case != CASE_OVERRIDE

    def test_weights_sum_to_one(self):
        """W_VT = 1 − W_ML 불변식"""
        params = FusionParams()
        for case, w_ml in params.w_ml.items():
            assert 0.0 <= w_ml <= 1.0, case

    def test_status_accepts_string(self):
        assert fuse(0.8, 0, 94, "ok", V1).case == CASE_B

    def test_detected_property(self):
        assert fuse(0.8, 0, 0, VTStatus.UNAVAILABLE, V1).detected is True
        assert fuse(0.8, 0, 94, VTStatus.OK, V1).detected is False


# ═══════════════════════════════════════════════════════════════
#  함수 기본값 = 서버 = 최종 논문 확정값
# ═══════════════════════════════════════════════════════════════

class TestDefaultsAreServerParams:
    """params를 생략하면 1차 심사본 값이 아니라 SERVER_PARAMS가 적용되어야 한다."""

    def test_classify_risk_default(self):
        # τL = 0.45 (1차 값 0.35였다면 0.40은 SUSPICIOUS)
        assert classify_risk(0.40) == "SECURED"
        assert classify_risk(0.45) == "SUSPICIOUS"
        assert classify_risk(0.65) == "BLOCKED"

    def test_amplify_default_alpha(self):
        # α = 18.4 → d ≥ 5 (n=92) 에서 포화
        assert amplify_vt_ratio(5 / 92) == pytest.approx(1.0)
        assert amplify_vt_ratio(6 / 92) == 1.0
        assert amplify_vt_ratio(1 / 92) == pytest.approx(0.2, abs=1e-4)

    def test_fuse_default_matches_server_params(self):
        for args in [(0.8, 0, 94, VTStatus.OK), (0.8, 3, 92, VTStatus.OK),
                     (0.1, 5, 92, VTStatus.OK), (0.6, 0, 0, VTStatus.NOT_FOUND)]:
            assert fuse(*args) == fuse(*args, SERVER_PARAMS)

    def test_fuse_default_override_theta(self):
        # θ = 0.05 → 5/92 에서 우선 판정 (1차 값 0.30이었다면 미발동)
        assert fuse(0.0, 5, 92, VTStatus.OK).case == CASE_OVERRIDE


# ═══════════════════════════════════════════════════════════════
#  전략 프리셋 — 논문 §3.3 Table 4의 4조건
# ═══════════════════════════════════════════════════════════════

class TestStrategyPresets:
    def test_ml_only_is_binary_at_threshold(self):
        p = params_ml_only(0.41)
        assert fuse(0.42, 0, 94, VTStatus.OK, p).risk_level == "BLOCKED"
        assert fuse(0.40, 0, 94, VTStatus.OK, p).risk_level == "SECURED"

    def test_ml_only_ignores_vt(self):
        p = params_ml_only(0.41)
        with_vt = fuse(0.9, 20, 70, VTStatus.OK, p).final_score
        without_vt = fuse(0.9, 0, 94, VTStatus.OK, p).final_score
        assert with_vt == without_vt == pytest.approx(0.9)

    def test_fixed_fusion_does_not_switch_cases(self):
        p = params_fixed(0.5)
        clean = fuse(0.9, 0, 94, VTStatus.OK, p)
        unavailable = fuse(0.9, 0, 0, VTStatus.UNAVAILABLE, p)
        assert clean.case == unavailable.case
        assert clean.final_score == unavailable.final_score

    def test_adaptive_beats_fixed_on_zero_day(self):
        """미등재 제로데이에서 적응 융합이 고정 융합보다 높은 점수를 준다"""
        ml = 0.95
        fixed = fuse(ml, 0, 0, VTStatus.NOT_FOUND, params_fixed(0.5))
        adaptive = fuse(ml, 0, 0, VTStatus.NOT_FOUND, params_adaptive())
        assert adaptive.final_score > fixed.final_score

    def test_adaptive_suppresses_ml_on_clean_url(self):
        """VT가 clean이면 ML 고확률이어도 억제된다 (false positive 방지)"""
        adaptive = fuse(0.9, 0, 94, VTStatus.OK, params_adaptive())
        assert adaptive.risk_level == "SECURED"


# ═══════════════════════════════════════════════════════════════
#  VT URL 식별자 — 회귀 #1 (가장 중요)
# ═══════════════════════════════════════════════════════════════

class TestVtUrlId:
    def test_uses_base64url_not_sha256(self):
        url = "https://example.com"
        expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        assert vt_url_id(url) == expected

    def test_no_base64_padding(self):
        """VT는 패딩 없는 base64url을 요구한다"""
        for url in ["https://a.com", "https://ab.com", "https://abc.com"]:
            assert "=" not in vt_url_id(url)

    def test_root_url_identifier_is_not_sha256(self):
        """루트 URL을 SHA-256(원문)으로 만들면 VT가 404를 반환한다.

        VT의 SHA-256 식별자는 정규화된 URL(끝에 /) 기준이라 원문 해시와 어긋난다.
        이 때문에 평가셋의 루트 URL 전부가 '미등재'로 오분류된 적이 있다.
        """
        import hashlib

        url = "https://gmail.com"
        assert vt_url_id(url) != hashlib.sha256(url.encode()).hexdigest()

    def test_identifier_is_reversible(self):
        url = "https://example.com/path?q=1"
        ident = vt_url_id(url)
        padded = ident + "=" * (-len(ident) % 4)
        assert base64.urlsafe_b64decode(padded).decode() == url


# ═══════════════════════════════════════════════════════════════
#  VirusTotal 조회 — GET 전용 + 상태 구분
# ═══════════════════════════════════════════════════════════════

def _mock_client(mock_cls):
    client = AsyncMock()
    mock_cls.return_value.__aenter__ = AsyncMock(return_value=client)
    mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return client


def _analysis_response(stats: dict):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": {"attributes": {"last_analysis_stats": stats}}}
    return resp


@pytest.mark.asyncio
class TestScanUrlWithVirusTotal:
    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_successful_scan(self, mock_cls, mock_settings):
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.return_value = _analysis_response(
            {"malicious": 3, "suspicious": 1, "undetected": 85, "harmless": 5}
        )

        result = await scan_url_with_virustotal("https://malicious.com")
        assert result.status is VTStatus.OK
        assert result.detected_engines == 4
        assert result.total_engines == 94

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_does_not_post_by_default(self, mock_cls, mock_settings):
        """POST는 URL을 VT에 등재시켜 '미등재' 상태를 파괴하므로 기본 경로에서 금지"""
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.return_value = _analysis_response({"malicious": 0, "harmless": 92})

        await scan_url_with_virustotal("https://example.com")
        client.post.assert_not_called()
        client.get.assert_called_once()

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_404_is_not_found_not_unavailable(self, mock_cls, mock_settings):
        """미등재는 '정보 없음'이 아니라 '제로데이 후보'라는 정보다"""
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        resp = MagicMock()
        resp.status_code = 404
        client.get.return_value = resp

        result = await scan_url_with_virustotal("https://brand-new-phish.tk")
        assert result.status is VTStatus.NOT_FOUND
        assert result.http_status == 404
        client.post.assert_not_called()

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_429_is_unavailable(self, mock_cls, mock_settings):
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        resp = MagicMock()
        resp.status_code = 429
        client.get.return_value = resp

        result = await scan_url_with_virustotal("https://example.com")
        assert result.status is VTStatus.UNAVAILABLE
        assert result.http_status == 429

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_timeout_is_unavailable(self, mock_cls, mock_settings):
        import httpx

        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.side_effect = httpx.TimeoutException("timeout")

        result = await scan_url_with_virustotal("https://slow-site.com")
        assert result.status is VTStatus.UNAVAILABLE
        assert result.detected_engines == 0

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_network_error_is_unavailable(self, mock_cls, mock_settings):
        import httpx

        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.side_effect = httpx.ConnectError("connection failed")

        result = await scan_url_with_virustotal("https://unreachable.com")
        assert result.status is VTStatus.UNAVAILABLE

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_empty_analysis_is_not_found(self, mock_cls, mock_settings):
        """등재됐지만 분석 이력이 없으면 TI 정보가 없다는 점에서 미등재와 같다"""
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.return_value = _analysis_response({})

        result = await scan_url_with_virustotal("https://never-analysed.com")
        assert result.status is VTStatus.NOT_FOUND

    @patch("app.services.hybrid_engine.settings")
    async def test_missing_api_key_is_unavailable(self, mock_settings):
        mock_settings.VIRUSTOTAL_API_KEY = ""
        result = await scan_url_with_virustotal("https://example.com")
        assert result.status is VTStatus.UNAVAILABLE

    @patch("app.services.hybrid_engine.settings")
    @patch("app.services.hybrid_engine.httpx.AsyncClient")
    async def test_latency_is_recorded(self, mock_cls, mock_settings):
        mock_settings.VIRUSTOTAL_API_KEY = "test-key"
        client = _mock_client(mock_cls)
        client.get.return_value = _analysis_response({"malicious": 0, "harmless": 92})

        result = await scan_url_with_virustotal("https://example.com")
        assert result.latency_ms >= 0.0


# ═══════════════════════════════════════════════════════════════
#  ML 추론 — 입력 오류와 모델 장애 분리 (회귀 #4)
# ═══════════════════════════════════════════════════════════════

class TestPredictUrlWithMl:
    @pytest.mark.parametrize("bad_url", [
        "https://", "http:// spaces .com", "not-a-url", "https://nodot", "",
    ])
    def test_invalid_url_raises_instead_of_falling_back(self, bad_url):
        """무효 URL이 중립값 0.5로 둔갑하면 실험 데이터가 오염된다"""
        with pytest.raises(InvalidUrlError):
            predict_url_with_ml(bad_url)

    def test_invalid_url_error_is_value_error(self):
        assert issubclass(InvalidUrlError, ValueError)

    def test_result_carries_latency_fields(self):
        result = MLPredictionResult(ml_probability=0.5, xai_features={})
        assert result.feature_ms == 0.0
        assert result.inference_ms == 0.0


# ═══════════════════════════════════════════════════════════════
#  VTResult 구조
# ═══════════════════════════════════════════════════════════════

class TestVTResult:
    def test_status_is_required(self):
        """status 없이 생성되면 미등재/장애 구분이 사라진다"""
        with pytest.raises(TypeError):
            VTResult(detected_engines=0, total_engines=94)

    def test_construction(self):
        r = VTResult(0, 94, VTStatus.OK, 200, 123.4)
        assert r.status is VTStatus.OK
        assert r.http_status == 200
        assert r.latency_ms == 123.4


# ═══════════════════════════════════════════════════════════════
#  모델 로더
# ═══════════════════════════════════════════════════════════════

class TestModelLoadError:
    def test_model_load_error_is_exception(self):
        err = ModelLoadError("model file not found")
        assert isinstance(err, Exception)
        assert "model file not found" in str(err)


# ═══════════════════════════════════════════════════════════════
#  KISA Reporter (SMTP) — 회귀 #5 (report_id 누락) 포함
# ═══════════════════════════════════════════════════════════════

def _sent_message(mock_smtp_cls):
    """mock SMTP로 보낸 EmailMessage를 꺼낸다."""
    smtp = mock_smtp_cls.return_value.__enter__.return_value
    smtp.send_message.assert_called_once()
    return smtp.send_message.call_args[0][0]


@pytest.mark.asyncio
class TestKisaReporter:
    @pytest.fixture(autouse=True)
    def _enable_sending(self):
        """발송 스위치와 받는 주소·SMTP 계정을 모두 설정한 상태를 가정한다 (SMTP 접속은 각 테스트가 mock)."""
        with patch("app.services.kisa_reporter.settings") as mock_settings:
            mock_settings.KISA_REPORT_ENABLED = True
            mock_settings.KISA_REPORT_RECIPIENT = "tester@example.com"
            mock_settings.SMTP_HOST = "smtp.gmail.com"
            mock_settings.SMTP_PORT = 587
            mock_settings.SMTP_USERNAME = "sender@example.com"
            mock_settings.SMTP_PASSWORD = "app-password"
            mock_settings.SMTP_USE_TLS = True
            mock_settings.MAIL_FROM = ""
            self.settings = mock_settings
            yield

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_disabled_by_default_sends_nothing(self, mock_smtp_cls):
        """KISA_REPORT_ENABLED=False 면 메일 서버에 접속하지도 않는다 — 실제 메일 오발송 방지"""
        from app.core.config import Settings
        from app.services.kisa_reporter import send_kisa_report

        assert Settings.model_fields["KISA_REPORT_ENABLED"].default is False

        self.settings.KISA_REPORT_ENABLED = False
        result = await send_kisa_report(
            reported_url="https://malicious-test.com",
            threat_score=0.87,
            vt_detected_count=3,
            report_id="1234abcd-5678-90ef-1234-567890abcdef",
        )
        assert result is False
        mock_smtp_cls.assert_not_called()

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_missing_recipient_sends_nothing(self, mock_smtp_cls):
        """받는 주소가 없으면 보내지 않는다 — 기본값으로 KISA에 가짜 신고가 나가는 일 방지"""
        from app.core.config import Settings
        from app.services.kisa_reporter import send_kisa_report

        assert Settings.model_fields["KISA_REPORT_RECIPIENT"].default == ""

        self.settings.KISA_REPORT_RECIPIENT = ""
        result = await send_kisa_report(
            reported_url="https://malicious-test.com",
            threat_score=0.87,
            vt_detected_count=3,
            report_id="1234abcd-5678-90ef-1234-567890abcdef",
        )
        assert result is False
        mock_smtp_cls.assert_not_called()

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_missing_smtp_account_sends_nothing(self, mock_smtp_cls):
        from app.services.kisa_reporter import send_kisa_report

        self.settings.SMTP_PASSWORD = ""
        result = await send_kisa_report(
            reported_url="https://malicious-test.com",
            threat_score=0.87,
            vt_detected_count=3,
            report_id="1234abcd-5678-90ef-1234-567890abcdef",
        )
        assert result is False
        mock_smtp_cls.assert_not_called()

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_send_success(self, mock_smtp_cls):
        from app.services.kisa_reporter import send_kisa_report

        result = await send_kisa_report(
            reported_url="https://malicious-test.com",
            threat_score=0.87,
            vt_detected_count=3,
            report_id="1234abcd-5678-90ef-1234-567890abcdef",
            ml_probability=0.91,
            vt_total_engines=70,
            weighting_case="CASE_A_LOW",
        )
        assert result is True

        mock_smtp_cls.assert_called_once_with("smtp.gmail.com", 587, timeout=20)
        smtp = mock_smtp_cls.return_value.__enter__.return_value
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("sender@example.com", "app-password")

        msg = _sent_message(mock_smtp_cls)
        assert msg["To"] == "tester@example.com"      # 설정한 주소로만 보낸다
        assert msg["From"] == "sender@example.com"     # MAIL_FROM이 비면 SMTP_USERNAME
        body = msg.get_content()
        assert "87.0" in body           # threat_score × 100
        assert "3 / 70" in body         # VT 탐지 비율
        assert "QG-" in body            # incident reference
        assert "QG-" in msg["Subject"]

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_url_is_defanged(self, mock_smtp_cls):
        """메일 본문의 악성 URL은 클릭되지 않도록 무력화되어야 한다"""
        from app.services.kisa_reporter import send_kisa_report

        await send_kisa_report(
            reported_url="https://evil.example.com/login",
            threat_score=0.9,
            vt_detected_count=5,
            report_id="abcd1234-0000-0000-0000-000000000000",
        )
        body = _sent_message(mock_smtp_cls).get_content()
        assert "https://evil.example.com" not in body
        assert "hxxps[://]evil[.]example[.]com" in body

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_smtp_failure_returns_false(self, mock_smtp_cls):
        """로그인 실패(앱 비밀번호 오류 등)는 예외 없이 False로 끝나야 한다"""
        import smtplib

        from app.services.kisa_reporter import send_kisa_report

        smtp = mock_smtp_cls.return_value.__enter__.return_value
        smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Username and Password not accepted")

        result = await send_kisa_report(
            reported_url="https://test.com",
            threat_score=0.5,
            vt_detected_count=1,
            report_id="0000-1111",
        )
        assert result is False

    @patch("app.services.kisa_reporter.smtplib.SMTP")
    async def test_network_failure_returns_false(self, mock_smtp_cls):
        from app.services.kisa_reporter import send_kisa_report

        mock_smtp_cls.side_effect = OSError("Network is unreachable")

        result = await send_kisa_report(
            reported_url="https://test.com",
            threat_score=0.5,
            vt_detected_count=1,
            report_id="0000-1111",
        )
        assert result is False

    async def test_report_id_is_required(self):
        """report_id 없이 호출하면 TypeError — 실제로 이 누락으로 신고가 전부 실패했다"""
        from app.services.kisa_reporter import send_kisa_report

        with pytest.raises(TypeError):
            await send_kisa_report(
                reported_url="https://test.com",
                threat_score=0.5,
                vt_detected_count=1,
            )


# ═══════════════════════════════════════════════════════════════
#  재심 수정본 파라미터 (REVISED_PARAMS = SERVER_PARAMS)
# ═══════════════════════════════════════════════════════════════

class TestRevisedParams:
    def test_server_uses_revised_params(self):
        from app.services.fusion import REVISED_PARAMS, SERVER_PARAMS
        assert SERVER_PARAMS is REVISED_PARAMS
        p = REVISED_PARAMS
        assert (p.alpha, p.d_high, p.tau_suspicious, p.tau_blocked) == (18.4, 5, 0.45, 0.65)
        assert p.w_ml_b_deep == 0.50 and p.theta_override == 0.05

    def test_default_params_unchanged_for_paper_v1_reproduction(self):
        from app.services.fusion import DEFAULT_PARAMS
        assert (DEFAULT_PARAMS.alpha, DEFAULT_PARAMS.tau_suspicious, DEFAULT_PARAMS.theta_override) == (3.0, 0.35, 0.30)
        assert DEFAULT_PARAMS.w_ml_b_deep is None

    def test_case_b_deep_url_uses_higher_ml_weight(self):
        from app.services.fusion import REVISED_PARAMS
        deep = fuse(0.95, 0, 94, VTStatus.OK, REVISED_PARAMS, path_type="deep")
        root = fuse(0.95, 0, 94, VTStatus.OK, REVISED_PARAMS, path_type="root")
        assert deep.case == root.case == CASE_B
        assert deep.final_score == pytest.approx(0.475) and deep.risk_level == "SUSPICIOUS"
        assert root.final_score == pytest.approx(0.285) and root.risk_level == "SECURED"

    def test_case_b_deep_never_blocks_without_vt(self):
        from app.services.fusion import REVISED_PARAMS
        assert fuse(1.0, 0, 94, VTStatus.OK, REVISED_PARAMS, path_type="deep").risk_level == "SUSPICIOUS"

    def test_revised_override_at_d_high(self):
        from app.services.fusion import REVISED_PARAMS
        r = fuse(0.0, 5, 92, VTStatus.OK, REVISED_PARAMS)
        assert r.risk_level == "BLOCKED" and r.override_rule == "RATIO"

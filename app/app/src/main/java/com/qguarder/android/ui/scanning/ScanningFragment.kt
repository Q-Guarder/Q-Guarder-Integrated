package com.qguarder.android.ui.scanning

import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.OvershootInterpolator
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.qguarder.android.databinding.FragmentScanningBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class ScanningFragment : Fragment() {

    private var _binding: FragmentScanningBinding? = null
    private val binding get() = _binding!!
    private val viewModel: ScanningViewModel by viewModels()
    private val args: ScanningFragmentArgs by navArgs()

    private val handler = Handler(Looper.getMainLooper())
    private var navigated = false

    // ── 페이즈 정의 ────────────────────────────────────────────────
    // 타이머 기반: 실제 서버 진행 상황과 무관하게 자동 진행.
    // 결과가 먼저 오면 즉시 화면 전환, 느리면 마지막 페이즈에서 대기.
    private data class Phase(
        val title:    String,
        val subtitle: String,
        val delayMs:  Long,
    )

    private val phases = listOf(
        Phase("연결 중...",             "서버에 연결하고 있어요",              0L),
        Phase("VirusTotal 검사 중...",  "다수의 보안 엔진 탐지 결과를 조회합니다",       1_000L),
        Phase("AI 모델 분석 중...",     "머신러닝으로 위험도를 분석합니다",    2_000L),
        Phase("결과 처리 중...",        "잠시만 기다려주세요",                 3_000L),
    )

    // ── Pulse 애니메이션 ───────────────────────────────────────────
    private val pulseRunnable = object : Runnable {
        override fun run() {
            if (_binding == null || navigated) return
            binding.iconContainer
                .animate()
                .scaleX(1.10f).scaleY(1.10f)
                .setDuration(650)
                .withEndAction {
                    if (_binding == null || navigated) return@withEndAction
                    binding.iconContainer
                        .animate()
                        .scaleX(1.00f).scaleY(1.00f)
                        .setDuration(650)
                        .withEndAction { handler.postDelayed(this, 150) }
                        .start()
                }
                .start()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentScanningBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // 초기 페이즈 + 애니메이션 시작
        setPhase(0)
        handler.post(pulseRunnable)
        schedulePhases()

        // 서버 분석 시작
        viewModel.analyze(args.url)
        observeState()
    }

    // ── 페이즈 타이머 스케줄 ──────────────────────────────────────
    private fun schedulePhases() {
        phases.forEachIndexed { index, phase ->
            if (index == 0) return@forEachIndexed   // 0번은 즉시 표시
            handler.postDelayed({
                if (_binding != null && !navigated) setPhase(index)
            }, phase.delayMs)
        }
    }

    private fun setPhase(index: Int) {
        val phase = phases[index]
        if (index == 0) {
            // 첫 페이즈는 즉시 표시
            binding.tvPhaseTitle.text    = phase.title
            binding.tvPhaseSubtitle.text = phase.subtitle
        } else {
            // 텍스트 크로스페이드: fade out → 교체 → fade in
            binding.tvPhaseTitle.animate().alpha(0f).setDuration(150).withEndAction {
                if (_binding == null || navigated) return@withEndAction
                binding.tvPhaseTitle.text = phase.title
                binding.tvPhaseTitle.animate().alpha(1f).setDuration(200).start()
            }.start()
            binding.tvPhaseSubtitle.animate().alpha(0f).setDuration(150).withEndAction {
                if (_binding == null || navigated) return@withEndAction
                binding.tvPhaseSubtitle.text = phase.subtitle
                binding.tvPhaseSubtitle.animate().alpha(1f).setDuration(200).start()
            }.start()
        }
        updateDots(index)
    }

    private var previousDotIndex = -1

    private fun updateDots(activeIndex: Int) {
        val activeTint   = ColorStateList.valueOf(0xFF3D5AFE.toInt())
        val inactiveTint = ColorStateList.valueOf(0xFF1E3050.toInt())
        val overshoot    = OvershootInterpolator(2f)

        listOf(binding.dot1, binding.dot2, binding.dot3, binding.dot4)
            .forEachIndexed { i, dot ->
                val wasActive = i <= previousDotIndex
                val isActive  = i <= activeIndex
                dot.backgroundTintList = if (isActive) activeTint else inactiveTint
                // 새로 활성화된 닷에 팝 애니메이션
                if (isActive && !wasActive) {
                    dot.scaleX = 1f; dot.scaleY = 1f
                    dot.animate()
                        .scaleX(1.5f).scaleY(1.5f)
                        .setDuration(150).setInterpolator(overshoot)
                        .withEndAction {
                            dot.animate().scaleX(1f).scaleY(1f).setDuration(200).start()
                        }.start()
                }
            }
        previousDotIndex = activeIndex
    }

    // ── 결과 관찰 → 즉시 화면 전환 ───────────────────────────────
    private fun observeState() {
        viewLifecycleOwner.lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    when (state) {
                        is ScanningUiState.Loading -> Unit
                        is ScanningUiState.Secured -> navigate {
                            findNavController().navigate(
                                ScanningFragmentDirections
                                    .actionScanningToResultSecured(
                                        scanId = state.scanId,
                                        url    = args.url)
                            )
                        }
                        is ScanningUiState.Warning -> navigate {
                            findNavController().navigate(
                                ScanningFragmentDirections
                                    .actionScanningToResultSuspicious(
                                        scanId = state.scanId,
                                        url    = args.url)
                            )
                        }
                        is ScanningUiState.Blocked -> navigate {
                            findNavController().navigate(
                                ScanningFragmentDirections
                                    .actionScanningToResultBlocked(
                                        scanId = state.scanId,
                                        url    = args.url)
                            )
                        }
                        is ScanningUiState.Error -> {
                            showErrorState(state.message)
                        }
                    }
                }
            }
        }
    }

    /** 에러 발생 시: 펄스 중단, 에러 메시지 표시, 재시도/돌아가기 버튼 */
    private fun showErrorState(message: String) {
        handler.removeCallbacksAndMessages(null)
        binding.iconContainer.animate().cancel()
        binding.iconContainer.scaleX = 1f
        binding.iconContainer.scaleY = 1f

        // 텍스트를 에러 메시지로 교체
        binding.tvPhaseTitle.animate().alpha(0f).setDuration(150).withEndAction {
            if (_binding == null) return@withEndAction
            binding.tvPhaseTitle.text = "분석 실패"
            binding.tvPhaseTitle.setTextColor(0xFFE53935.toInt())
            binding.tvPhaseTitle.animate().alpha(1f).setDuration(200).start()
        }.start()

        binding.tvPhaseSubtitle.animate().alpha(0f).setDuration(150).withEndAction {
            if (_binding == null) return@withEndAction
            binding.tvPhaseSubtitle.text = message
            binding.tvPhaseSubtitle.animate().alpha(1f).setDuration(200).start()
        }.start()

        // 재시도 / 돌아가기 버튼 표시
        binding.layoutErrorActions.visibility = View.VISIBLE
        binding.layoutErrorActions.alpha = 0f
        binding.layoutErrorActions.animate().alpha(1f).setDuration(250).setStartDelay(300).start()

        binding.btnRetry.setOnClickListener {
            resetToScanningState()
            viewModel.retry(args.url)
        }
        binding.btnGoBack.setOnClickListener {
            findNavController().popBackStack()
        }
    }

    /** 에러 상태에서 재시도 시: 스캐닝 UI로 복원 */
    private fun resetToScanningState() {
        binding.layoutErrorActions.animate().alpha(0f).setDuration(150).withEndAction {
            if (_binding == null) return@withEndAction
            binding.layoutErrorActions.visibility = View.GONE
        }.start()

        binding.tvPhaseTitle.setTextColor(
            binding.tvPhaseSubtitle.currentTextColor // 기본 색상으로 복원
        )
        navigated = false
        previousDotIndex = -1
        setPhase(0)
        handler.post(pulseRunnable)
        schedulePhases()
    }

    /** 중복 navigate 방지 + 핸들러/애니메이션 정리 */
    private fun navigate(block: () -> Unit) {
        if (navigated) return
        navigated = true
        handler.removeCallbacksAndMessages(null)
        binding.iconContainer.animate().cancel()
        block()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        handler.removeCallbacksAndMessages(null)
        binding.iconContainer.animate().cancel()
        _binding = null
    }
}
package com.qguarder.android.ui.result

import android.animation.ObjectAnimator
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.widget.NestedScrollView
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.qguarder.android.R
import com.qguarder.android.data.ScanResultStore
import com.qguarder.android.data.local.CustomTabsHelper
import com.qguarder.android.databinding.FragmentResultBlockedBinding
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.domain.model.XaiItem
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class ResultBlockedFragment : Fragment() {

    private var _binding: FragmentResultBlockedBinding? = null
    private val binding get() = _binding!!

    private val args: ResultBlockedFragmentArgs by navArgs()
    private val viewModel: ResultViewModel by viewModels()

    @Inject lateinit var scanResultStore: ScanResultStore

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResultBlockedBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // URL 표시
        val url = args.url.ifEmpty { scanResultStore.latestBlocked?.url ?: "" }
        binding.tvUrl.text = url

        // 분석 결과 바인딩
        scanResultStore.latestBlocked?.let { result ->
            bindAnalysisResult(result.finalScore, result.vtTotalEngines, result.vtDetectedEngines)
            if (result.xaiFeatures.isNotEmpty()) {
                bindDetectionReasons(result.xaiFeatures)
                bindXaiFeatures(result.xaiFeatures)
            }
        }

        // 툴바 이전버튼 -> 스캔 화면
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigate(R.id.action_result_blocked_to_scan)
        }

        // 북마크 기능
        if (url.isNotEmpty()) viewModel.checkFavorite(url)

        binding.btnFavorite.setOnClickListener {
            viewModel.toggleFavorite(url = url, title = null, riskLevel = "BLOCKED")
        }

        viewLifecycleOwner.lifecycleScope.launch {
            var isFirstEmit = true
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.isFavorite.collect { isFavorite ->
                    binding.btnFavorite.setImageResource(
                        if (isFavorite) R.drawable.ic_favorites
                        else R.drawable.ic_star_outline
                    )
                    if (!isFirstEmit) {
                        binding.btnFavorite.animate()
                            .scaleX(1.3f).scaleY(1.3f).setDuration(150)
                            .setInterpolator(OvershootInterpolator(2f))
                            .withEndAction {
                                binding.btnFavorite.animate()
                                    .scaleX(1f).scaleY(1f).setDuration(200).start()
                            }.start()
                    }
                    isFirstEmit = false
                }
            }
        }

        // 돌아가기
        binding.btnBack.setOnClickListener {
            findNavController().navigate(R.id.action_result_blocked_to_scan)
        }

        // 순차 콘텐츠 공개 애니메이션 + 아이콘 카드 shake
        playStaggerAnimation()

        // 위험 등급 단계적 경고 — 화면 진입 5초 후 고지 팝업 자동 표시 (접속 유도 없음)
        viewLifecycleOwner.lifecycleScope.launch {
            delay(5000)
            if (_binding != null) showBlockedNoticeDialog()
        }
    }

    /** 위험 URL 자동 고지 팝업 — 접속 유도 없이 경고만, 5초 후에만 닫기 가능 */
    private fun showBlockedNoticeDialog() {
        if (_binding == null) return
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_blocked_notice, null)

        scanResultStore.latestBlocked?.riskDescription?.let {
            dialogView.findViewById<TextView>(R.id.tv_notice_message).text = it
        }

        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setView(dialogView)
            .setCancelable(false)   // 5초 강제 읽기 — 바깥 터치·뒤로가기로 못 닫음
            .create()

        val btnClose = dialogView.findViewById<MaterialButton>(R.id.btn_notice_close)
        val btnX     = dialogView.findViewById<TextView>(R.id.btn_notice_x)

        // 5초 카운트다운 동안 닫기/X 비활성, 종료 후 활성화 + 텍스트 "닫기"
        var canClose = false
        val countdownJob = viewLifecycleOwner.lifecycleScope.launch {
            for (i in 5 downTo 1) {
                btnClose.text = "${i}초 후 닫기"
                delay(1000)
            }
            canClose = true
            btnClose.isEnabled = true
            btnClose.text = "닫기"
            btnX.alpha = 0.65f
        }

        btnClose.setOnClickListener { if (canClose) dialog.dismiss() }
        btnX.setOnClickListener { if (canClose) dialog.dismiss() }

        dialog.setOnDismissListener { countdownJob.cancel() }
        dialog.show()
    }

    private fun playStaggerAnimation() {
        val scrollView = binding.root.getChildAt(1) as? NestedScrollView ?: return
        val container = scrollView.getChildAt(0) as? LinearLayout ?: return
        val decelerate = DecelerateInterpolator(1.5f)
        val offsetPx = 28f * resources.displayMetrics.density
        var visibleCount = 0

        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            if (child.visibility == View.GONE) continue
            child.alpha = 0f
            child.translationY = offsetPx
            child.animate()
                .alpha(1f).translationY(0f)
                .setDuration(320).setStartDelay((visibleCount * 60).toLong())
                .setInterpolator(decelerate).start()
            visibleCount++
        }

        // Blocked 전용: 아이콘 카드(첫 번째 자식) shake 효과
        val iconCard = container.getChildAt(0)
        if (iconCard != null) {
            val shakeDelay = (visibleCount * 60 + 320).toLong()
            iconCard.postDelayed({
                ObjectAnimator.ofFloat(iconCard, "translationX", 0f, -8f, 8f, -6f, 6f, -3f, 3f, 0f)
                    .apply { duration = 400; start() }
            }, shakeDelay)
        }
    }

    private fun bindAnalysisResult(finalScore: Int, vtTotal: Int, vtDetected: Int) {
        // finalScore: 0~100 정수
        binding.tvScore.text = when {
            finalScore >= 85 -> "매우 높음 ($finalScore%)"
            else             -> "높음 ($finalScore%)"
        }

        if (vtTotal > 0) {
            binding.tvVt.text = "$vtDetected / $vtTotal 엔진 악성 탐지"
        } else {
            // 미등재·API 장애 등으로 VT 정보 없이 ML 중심으로 판정된 경우
            binding.tvVt.text = "VT 정보 없음"
        }
    }

    private fun bindDetectionReasons(features: List<XaiItem>) {
        val container = binding.llDetectionReasons
        container.removeAllViews()

        // 서버 제공 한글 title/description을 그대로 표시
        features.take(3).forEach { item ->
            val tv = TextView(requireContext()).apply {
                text = "• ${item.title}"
                textSize = 12f
                setTextColor(0xFFE53935.toInt())
                setPadding(0, 0, 0, 12)
            }
            container.addView(tv)
        }

        // XAI 결과가 없으면 기본 문구 유지
        if (container.childCount == 0) {
            val tv = TextView(requireContext()).apply {
                text = "• ML 엔진 및 VirusTotal 복합 탐지"
                textSize = 12f
                setTextColor(0xFFE53935.toInt())
            }
            container.addView(tv)
        }
    }

    private fun bindXaiFeatures(features: List<XaiItem>) {
        binding.cardXai.visibility = View.VISIBLE

        val container = binding.llXaiFeatures
        container.removeAllViews()
        var xaiAnimIndex = 0

        features.take(5).forEach { item ->
            val row = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_xai_row, container, false)

            // 서버 제공 한글 피처명 그대로 표시
            row.findViewById<android.widget.TextView>(R.id.tv_label).text = item.title

            // 기여도(0~100 정수) 프로그레스 표시 + 채움 애니메이션
            val bar = row.findViewById<android.widget.ProgressBar>(R.id.progress_xai)
            val target = item.contribution.coerceIn(0, 100)
            bar.progress = 0
            ObjectAnimator.ofInt(bar, "progress", 0, target).apply {
                duration = 600
                startDelay = (xaiAnimIndex * 100).toLong()
                interpolator = DecelerateInterpolator(2f)
                start()
            }
            xaiAnimIndex++
            // severity에 따른 색상
            val barColor = when (item.severity) {
                "high"   -> 0xFFE53935.toInt()   // 빨강
                "medium" -> 0xFFFF8F00.toInt()   // 주황
                else     -> 0xFF1D9E75.toInt()   // 녹색
            }
            bar.progressTintList = android.content.res.ColorStateList.valueOf(barColor)

            val scoreView = row.findViewById<android.widget.TextView>(R.id.tv_score)
            scoreView.text = "${item.contribution}%"
            scoreView.setTextColor(barColor)

            container.addView(row)
        }
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }
}
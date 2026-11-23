package com.qguarder.android.ui.result

import android.animation.ObjectAnimator
import android.os.Bundle
import android.view.animation.OvershootInterpolator
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
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
import com.qguarder.android.R
import com.qguarder.android.data.ScanResultStore
import com.qguarder.android.data.local.CustomTabsHelper
import com.qguarder.android.databinding.FragmentResultSecuredBinding
import com.qguarder.android.domain.model.RiskLevel
import com.qguarder.android.domain.model.XaiItem
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class ResultSecuredFragment : Fragment() {

    private var _binding: FragmentResultSecuredBinding? = null
    private val binding get() = _binding!!

    private val viewModel: ResultViewModel by viewModels()
    private val args: ResultSecuredFragmentArgs by navArgs()

    @Inject lateinit var scanResultStore: ScanResultStore

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentResultSecuredBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val url = args.url.ifEmpty { scanResultStore.latestSecured?.url ?: "" }

        // URL 표시
        binding.tvUrl.text = url

        // ML 분석 결과 표시
        scanResultStore.latestSecured?.let { result ->
            bindAnalysisResult(result.finalScore, result.vtTotalEngines, result.vtDetectedEngines)
            // SECURED 시 xai_features는 항상 빈 배열 — 섹션 숨김 처리
            if (result.xaiFeatures.isNotEmpty()) {
                bindXaiFeatures(result.xaiFeatures)
            } else {
                binding.cardXai.visibility     = View.GONE
                binding.spacerNoXai.visibility = View.VISIBLE
            }
        }

        // 툴바 뒤로가기
        binding.toolbar.setNavigationOnClickListener {
            findNavController().navigate(R.id.action_result_secured_to_scan)
        }

        // 즐겨찾기
        if (url.isNotEmpty()) viewModel.checkFavorite(url)

        binding.btnFavorite.setOnClickListener {
            viewModel.toggleFavorite(url = url, title = null, riskLevel = "SECURED")
        }

        viewLifecycleOwner.lifecycleScope.launch {
            var isFirstEmit = true
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.isFavorite.collect { isFavorite ->
                    binding.btnFavorite.setImageResource(
                        if (isFavorite) R.drawable.ic_favorites else R.drawable.ic_star_outline
                    )
                    // 첫 emit 제외, 토글 시 바운스 애니메이션
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

        // 웹사이트 이동
        binding.btnConnect.setOnClickListener {
            viewModel.recordVisit(url, RiskLevel.SECURED)
            CustomTabsHelper.open(requireContext(), url)
        }

        // 순차 콘텐츠 공개 애니메이션
        playStaggerAnimation()
    }

    private fun playStaggerAnimation() {
        val scrollView = binding.root.findViewById<NestedScrollView>(
            binding.root.getChildAt(1).id  // NestedScrollView는 CoordinatorLayout의 두 번째 자식
        ) ?: return
        val container = scrollView.getChildAt(0) as? LinearLayout ?: return
        val decelerate = DecelerateInterpolator(1.5f)
        val offsetPx = 28f * resources.displayMetrics.density

        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            if (child.visibility == View.GONE) continue
            child.alpha = 0f
            child.translationY = offsetPx
            child.animate()
                .alpha(1f).translationY(0f)
                .setDuration(320).setStartDelay((i * 60).toLong())
                .setInterpolator(decelerate).start()
        }
    }

    // ── ML 점수 + VT 결과 바인딩 ──────────────────────────────────
    private fun bindAnalysisResult(finalScore: Int, vtTotal: Int, vtDetected: Int) {
        // 위험도 점수 (0~100 정수, 낮을수록 안전)
        binding.tvScore.text = when {
            finalScore < 15  -> "매우 낮음 ($finalScore%)"
            finalScore < 45  -> "낮음 ($finalScore%)"
            else             -> "$finalScore%"
        }

        // VirusTotal — 악성 탐지 0건은 안전 보장이 아니라 '탐지 근거 없음'이므로 중립색 표시
        if (vtTotal > 0) {
            binding.tvVt.text = "$vtDetected / $vtTotal 엔진 악성 탐지"
            binding.tvVt.setTextColor(
                if (vtDetected == 0) 0xFF757575.toInt() else 0xFFFF6F00.toInt()
            )
        } else {
            // 미등재·API 장애 등으로 VT 정보를 얻지 못한 경우
            binding.tvVt.text = "VT 정보 없음"
            binding.tvVt.setTextColor(0xFF757575.toInt())
        }
    }

    // ── XAI 피처 동적 생성 ────────────────────────────────────────
    private fun bindXaiFeatures(features: List<XaiItem>) {
        binding.cardXai.visibility     = View.VISIBLE
        binding.spacerNoXai.visibility = View.GONE

        val container = binding.llXaiFeatures
        container.removeAllViews()
        var xaiAnimIndex = 0

        features.take(5).forEach { item ->
            val row = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_xai_row, container, false)

            // 서버 제공 한글 피처명 그대로 표시
            row.findViewById<TextView>(R.id.tv_label).text = item.title

            // 기여도(0~100 정수)를 프로그레스로 표시
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
            // severity에 따른 색상: high → 주황, 그 외 → 파랑
            val barColor = if (item.severity == "high") 0xFFFF6F00.toInt() else 0xFF3D5AFE.toInt()
            bar.progressTintList = android.content.res.ColorStateList.valueOf(barColor)

            val scoreView = row.findViewById<TextView>(R.id.tv_score)
            scoreView.text = "${item.contribution}%"
            scoreView.setTextColor(barColor)

            container.addView(row)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}